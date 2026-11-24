#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <thread>
#include <mutex>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <random>
#include <chrono>
#include <sys/file.h>

#include "files.h"
using namespace std;

struct User{
    string password;
    bool loggedin;
    string session;
    string creator;   // request id of the CREATE_USER line that won
};
struct Group{
    string owner;
    vector<string> members;
    vector<string> requests;
    string creator;   // request id of the CREATE_GROUP line that won
};

map<string,User> users;
map<string,Group> groups;
map<string,map<string,FileMeta>> group_files;
mutex state_mutex;
map<string,string> active_sessions;

const string SYNC_LOG="sync_log.txt";
off_t last_offset=0;
mutex file_mutex;

bool is_logged_in(const string &uid, const string &sess){
    lock_guard<mutex> lock(state_mutex);
    return users.count(uid) && users[uid].loggedin && users[uid].session == sess;
}

bool set_session(const string &uid, const string &sess, string &current_user, string &current_session) {
    lock_guard<mutex> lock(state_mutex);
    if(!users.count(uid) || users[uid].session != sess) return false;
    current_user = uid;
    current_session = sess;
    return true;
}
vector<string> split(const string &s,char delim){
    vector<string> out; string cur;
    for(char c:s){
        if(c==delim){
            out.push_back(cur);
            cur.clear();
        }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}
//apply any command to log file
void apply_op_line(const string &line){
    if(line.empty()) return;
    vector<string> parts=split(line,'|');
    if(parts.size()==0) return;
    lock_guard<mutex>lock(state_mutex);
    // Creates carry a request id. The first line for a name in the log wins,
    // and the creator field records whose request that was, so the tracker
    // that wrote a losing line can tell its client the name was taken.
    if(parts[0]=="CREATE_USER" && (parts.size()==3 || parts.size()==4)){
        string uid=parts[1];
        string pw=parts[2];
        string rid=parts.size()==4 ? parts[3] : "";
        if(!users.count(uid)) users[uid]={pw,false,"",rid};
        return;
    }
    if(parts[0]=="CREATE_GROUP" && (parts.size()==3 || parts.size()==4)){
        string gid=parts[1], own=parts[2];
        string rid=parts.size()==4 ? parts[3] : "";
        if(!groups.count(gid)) {
            groups[gid]={own,{own},{},rid};
        }
        return;
    }
    if(parts[0]=="JOIN_REQ"&&parts.size()==3){
        string gid=parts[1],uid=parts[2];
        if(groups.count(gid)){
            auto &reqs=groups[gid].requests;
            auto &m=groups[gid].members;
            if(find(m.begin(),m.end(),uid)==m.end() &&
               find(reqs.begin(),reqs.end(),uid)==reqs.end()){
                reqs.push_back(uid);
            }
        }
        return;
    }
    if(parts[0] == "ACCEPT_REQ" && parts.size() == 3) {
        string gid = parts[1], uid = parts[2];
        if(groups.count(gid)) {
            auto &r = groups[gid].requests;
            // Only a pending request can be accepted.
            if(find(r.begin(), r.end(), uid) == r.end()) return;
            r.erase(remove(r.begin(), r.end(), uid), r.end());
            auto &m = groups[gid].members;
            if(find(m.begin(), m.end(), uid) == m.end()) {
                m.push_back(uid);
            }
        }
        return;
    }
    if(parts[0]=="LOGIN" && parts.size()==3){
        string uid=parts[1], sid=parts[2];
        if(users.count(uid)) {
            users[uid].loggedin=true;
            users[uid].session=sid;
        }
        return;
    }
    if(parts[0]=="LOGOUT" && parts.size()==2){
        string uid=parts[1];
        if(users.count(uid)){ 
            users[uid].loggedin=false; 
            users[uid].session=""; 
        }
        return;
    }
    if(parts[0]=="LEAVE_GROUP" && parts.size()==3){
        string gid=parts[1], uid=parts[2];
        if(groups.count(gid)){
            auto &m=groups[gid].members;
            m.erase(remove(m.begin(), m.end(), uid), m.end());
        }
        return;
    }
    if(parts[0]=="UPLOAD_FILE" && parts.size()>=7){
        string gid=parts[1], filename=parts[2];
        uint64_t filesize=0;
        try { filesize=stoull(parts[3]); } catch(...) { return; }
        string peer=parts[4], filehash=parts[5];
        vector<string> ph=split(parts[6],',');
        if(!group_files.count(gid)) group_files[gid]={};
        FileMeta fm={filename,filesize,filehash,ph,{peer}};
        if(group_files[gid].count(filename)) {
            FileMeta &old=group_files[gid][filename];
            if(find(old.seeders.begin(),old.seeders.end(),peer)==old.seeders.end()) old.seeders.push_back(peer);
        } 
        else group_files[gid][filename]=fm;
        return;
    }
    if(parts[0]=="STOP_SHARE" && parts.size()==5){
        string gid=parts[1], filename=parts[2], peer=parts[3]+":"+parts[4];
        if(group_files.count(gid) && group_files[gid].count(filename)){
            FileMeta &fm=group_files[gid][filename];
            fm.seeders.erase(remove(fm.seeders.begin(),fm.seeders.end(),peer),fm.seeders.end());
            if(fm.seeders.empty()) group_files[gid].erase(filename);
        }
    }
}
//add command to log file. Returns the offset just past the new line, or -1.
off_t append_to_log(const string &line){
    lock_guard<mutex> lock(file_mutex);
    int fd=open(SYNC_LOG.c_str(),O_WRONLY|O_APPEND|O_CREAT,0644);
    if(fd<0){
        cerr<<"open("<<SYNC_LOG<<") failed: "<<strerror(errno)<<"\n";
        return -1;
    }
    // Lock the file so the other tracker's line can never be interleaved with
    // ours, even on filesystems where O_APPEND alone is not atomic.
    if(flock(fd,LOCK_EX)<0){
        close(fd);
        return -1;
    }
    string out=line+"\n";
    size_t done=0;
    while(done<out.size()){
        ssize_t w=write(fd,out.c_str()+done,out.size()-done);
        if(w<0 && errno==EINTR) continue;
        if(w<=0) break;
        done+=(size_t)w;
    }
    off_t end=(done==out.size()) ? lseek(fd,0,SEEK_CUR) : -1;
    flock(fd,LOCK_UN);
    close(fd);
    return end;
}
//reads any new operation added to log file and applies it.
//Only complete lines are consumed: if the other tracker is in the middle of
//writing a line, the partial line is left for the next read instead of being
//skipped. Returns how far the log has been applied.
off_t read_new_ops_from_log(){
    lock_guard<mutex> lock(file_mutex);
    int fd=open(SYNC_LOG.c_str(),O_RDONLY);
    if(fd<0) return last_offset;
    if(lseek(fd,last_offset,SEEK_SET)==(off_t)-1){
        close(fd);
        return last_offset;
    }
    string acc;
    const int BUF=4096;
    char buf[BUF];
    ssize_t r;
    while((r=read(fd,buf,BUF))>0){
        acc.append(buf,(size_t)r);
        size_t pos=0;
        while(true){
            size_t nl=acc.find('\n',pos);
            if(nl==string::npos) break;
            apply_op_line(acc.substr(pos,nl-pos));
            pos=nl+1;
        }
        last_offset+=(off_t)pos;   // advance past complete lines only
        acc.erase(0,pos);
    }
    close(fd);
    return last_offset;
}
//replay log file on startup
void replay_log_full(){
    int fdw=open(SYNC_LOG.c_str(),O_WRONLY|O_CREAT,0644);
    if(fdw>=0) close(fdw);
    {
        lock_guard<mutex> lock(file_mutex);
        last_offset=0;
    }
    // Sessions rebuilt from the log are kept, so a client failing over to a
    // restarted tracker keeps working with its existing token.
    read_new_ops_from_log();
}
//Write an operation to the shared log, then apply the log up to and including
//it. Every tracker applies operations only in log order, so all trackers end
//up in the same state, and the caller can check the result to see whether its
//operation took effect (for example, whether it won a race for a name).
bool commit_op(const string &op){
    off_t end=append_to_log(op);
    if(end<0) return false;
    for(int i=0;i<200;i++){
        if(read_new_ops_from_log()>=end) return true;
        // An earlier line is still being written; wait for it to finish.
        this_thread::sleep_for(chrono::milliseconds(5));
    }
    return false;
}
//frequently reads new operation
void watcher_thread(){
    while(true){ 
        read_new_ops_from_log(); 
        this_thread::sleep_for(chrono::milliseconds(800));
    }
}
//send reply to client
bool send_reply_with_marker(int fd,const string &reply){
    string out=reply; 
    if(out.empty()||out.back()!='\n') out+="\n";
    out+="END_OF_REPLY\n";
    size_t sent=0;
    while(sent<out.size()){
        ssize_t s=send(fd,out.c_str()+sent,out.size()-sent,0);
        if(s<=0) return false;
        sent+=(size_t)s;
    }
    return true;
}
//random token from the OS random source (/dev/urandom), not rand(): tokens
//must be unpredictable and must differ between trackers started together.
mutex rng_mutex;
string random_token(size_t n){
    static const string chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static random_device rd;
    lock_guard<mutex> lock(rng_mutex);
    string tok;
    while(tok.size()<n){
        unsigned int x=rd();
        // reject values that would bias the result toward some characters
        if(x >= (0xFFFFFFFFu/chars.size())*chars.size()) continue;
        tok+=chars[x%chars.size()];
    }
    return tok;
}
//generate session token to identify session
string generate_session(){
    return random_token(16);
}
//parse a non-negative decimal number; false on anything else
bool parse_u64(const string &s, uint64_t &out){
    if(s.empty() || s.size()>19) return false;
    uint64_t v=0;
    for(char c:s){
        if(c<'0'||c>'9') return false;
        v=v*10+(uint64_t)(c-'0');
    }
    out=v;
    return true;
}
bool is_sha1_hex(const string &s){
    if(s.size()!=40) return false;
    for(char c:s){
        if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) return false;
    }
    return true;
}
void handle_client(int client_fd){
    string current_user, 
    current_session;
    sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getpeername(client_fd, (sockaddr*)&addr, &len);
    string peer_ip = inet_ntoa(addr.sin_addr);
    int peer_port = ntohs(addr.sin_port);
    string peer = peer_ip + ":" + to_string(peer_port);
    const int BUF=4096; 
    char buf[BUF]; 
    string acc;

    while(true){
        ssize_t r=recv(client_fd,buf,BUF,0);
        if(r<=0) break;
        acc.append(buf,(size_t)r);
        while(true){
            size_t nl=acc.find('\n');
            if(nl==string::npos) break;
            string line=acc.substr(0,nl); 
            acc.erase(0,nl+1);
            if(!line.empty() && line.back()=='\r') line.pop_back();
            if(line.empty()) continue;

            vector<string> words; 
            stringstream ss(line); 
            string w;
            while(ss>>w) words.push_back(w);
            string reply;

            if(words.size()==0){ 
                send_reply_with_marker(client_fd,"Empty command"); 
                continue; 
            }
            // Apply anything the other tracker has written before answering, so
            // a client that just failed over sees its own recent changes (and a
            // token from a login on the other tracker is already known).
            read_new_ops_from_log();
            bool bad_char=false;
            for(auto &x:words) if(x.find('|')!=string::npos) bad_char=true;
            if(bad_char){
                send_reply_with_marker(client_fd,"Invalid character '|' in command");
                continue;
            }
            // handle session reuse for failover
            if(words[0]=="session"){
                if(words.size()<4){ 
                    reply="Invalid arguments for session"; 
                    send_reply_with_marker(client_fd,reply); 
                    continue;
                }
                string uid=words[1], token=words[2];
                if(!set_session(uid, token, current_user, current_session)){
                    // The token was replaced by a newer login or ended by logout:
                    // forget this connection's login so it cannot keep acting as uid.
                    current_user.clear();
                    current_session.clear();
                    reply="invalid_session";
                    send_reply_with_marker(client_fd,reply); 
                    continue;
                }
                words.erase(words.begin(), words.begin()+3);
            }
            //handle command
            if(words[0]=="create_user"){
                if(!current_user.empty()){ 
                    reply="cannot_create_user_while_logged_in"; 
                    send_reply_with_marker(client_fd,reply); 
                    continue;
                }
                if(words.size()!=3){ 
                    reply="Invalid arguments for create_user"; 
                    send_reply_with_marker(client_fd,reply); 
                    continue;
                }
                string uid=words[1],pw=words[2];
                { 
                    lock_guard<mutex> lock(state_mutex); 
                    if(users.count(uid)){ 
                        reply="User already exists"; 
                        send_reply_with_marker(client_fd,reply); 
                        continue;
                    } 
                }
                // Two trackers may both pass the check above for the same name.
                // Both lines go into the log; the first one wins on every
                // tracker, and only the client whose request id won gets OK.
                string rid=random_token(16);
                string op="CREATE_USER|"+uid+"|"+pw+"|"+rid;
                if(commit_op(op)){
                    lock_guard<mutex> lock(state_mutex);
                    reply = (users.count(uid) && users[uid].creator==rid) ? "OK user_created" : "User already exists";
                }
                else reply="log_append error for create_user";
                send_reply_with_marker(client_fd,reply); 
                continue;
            }
            if(words[0]=="login"){
                if(!current_user.empty()){ 
                    reply="already_logged_in_on_this_client"; 
                    send_reply_with_marker(client_fd, reply); 
                    continue;
                }
                if(words.size()!=3){ 
                    reply="Invalid arguments for login"; 
                    send_reply_with_marker(client_fd,reply); 
                    continue;
                }
                string uid=words[1], pw=words[2];
                { 
                    lock_guard<mutex> lock(state_mutex); 
                    if(!users.count(uid) || users[uid].password!=pw){ 
                        reply="invalid_credentials";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    // A correct login always succeeds and replaces any existing
                    // session, so a client that crashed without logging out can
                    // never lock its user out. The old token stops working on
                    // every tracker once this LOGIN is in the shared log.
                }
                string session_id = generate_session();
                string op="LOGIN|"+uid+"|"+session_id;
                if(commit_op(op)){
                    reply="OK login_success "+session_id; 
                    current_user=uid; 
                    current_session=session_id; 
                } 
                else reply="log_append error for login";
                send_reply_with_marker(client_fd,reply); 
                continue;
            }
            if(words[0]=="logout"){
                if(current_user.empty()){ 
                    reply="not_logged_in"; 
                    send_reply_with_marker(client_fd,reply); 
                    continue;
                }
                string op="LOGOUT|"+current_user;
                if(commit_op(op)){
                    reply="OK logout_success"; 
                    current_user=""; 
                    current_session="";
                } 
                else reply="log_append error for logout";
                send_reply_with_marker(client_fd,reply); 
                continue;
            }
            if(words[0]=="create_group"){
                if(words.size()!=2){
                    reply="Invalid arguments for create_group";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                if(current_user.empty()){
                    reply="You must login first";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid=words[1];
                {
                    lock_guard<mutex> lock(state_mutex);
                    if(groups.count(gid)){
                        reply="group_exists";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                // Same rule as create_user: the first line in the log wins.
                string rid=random_token(16);
                string op="CREATE_GROUP|"+gid+"|"+current_user+"|"+rid;
                if(commit_op(op)){
                    lock_guard<mutex> lock(state_mutex);
                    reply = (groups.count(gid) && groups[gid].creator==rid) ? "Group created" : "group_exists";
                }
                else {
                    reply="log_append error for create_group";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }
            if(words[0]=="join_group"){
                if(words.size()!=2){
                    reply="Invalid arguments for join_group";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                if(current_user.empty()){
                    reply="You must login first";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid=words[1];
                {
                    lock_guard<mutex> lock(state_mutex);
                    if(!groups.count(gid)){
                        reply="no_such_group";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    if(find(groups[gid].members.begin(), groups[gid].members.end(),current_user)!=groups[gid].members.end()){
                        reply="already_member";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string op="JOIN_REQ|"+gid+"|"+current_user;
                if(commit_op(op)){
                    // Report what actually happened once the log is applied
                    // (e.g. the owner may have accepted us in the meantime).
                    lock_guard<mutex> lock(state_mutex);
                    auto &m=groups[gid].members;
                    if(find(m.begin(),m.end(),current_user)!=m.end()) reply="already_member";
                    else reply="OK request_sent";
                }
                else {
                    reply="log_append error in join requests";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }
            if(words[0]=="leave_group"){
                if(words.size()!=2){
                    reply="Invalid arguments for leave_group";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                if(current_user.empty()){
                    reply="You must login first";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid=words[1];
                {
                    lock_guard<mutex> lock(state_mutex);
                    if(!groups.count(gid)){
                        reply="no_such_group";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string op="LEAVE_GROUP|"+gid+"|"+current_user;
                if(commit_op(op)){
                    reply="OK left_group";
                }
                else {
                    reply="log_append error in leave_group";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }
            if(words[0]=="list_groups"){
                string out;
                lock_guard<mutex> lock(state_mutex);
                for(auto &p:groups){
                    out+=p.first+" "+p.second.owner+"\n";
                }
                if(out.empty()){
                    out="No groups\n";
                }
                send_reply_with_marker(client_fd,out);
                continue;
            }
            if(words[0]=="list_requests"){
                if(words.size()!=2){
                    reply="Invalid command for list requests";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid=words[1];
                lock_guard<mutex> lock(state_mutex);
                if(!groups.count(gid)){
                    reply="No group exists";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                if(current_user!=groups[gid].owner){
                    reply="not_owner";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string out;
                for(auto &r:groups[gid].requests){
                    out+=r+"\n";
                }
                if(out.empty()){
                    out="No requests\n";
                }
                send_reply_with_marker(client_fd,out);
                continue;
            }
            if(words[0]=="accept_request"){
                if(words.size()!=3){
                    reply="Invalid arguments for accept_request";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                if(current_user.empty()){
                    reply="You must login first";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid=words[1];
                string uid=words[2];
                {
                    lock_guard<mutex> lock(state_mutex);
                    if(!groups.count(gid)){
                        reply="no_such_group";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    if(groups[gid].owner!=current_user){
                        reply="not_owner";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    auto &m=groups[gid].members;
                    if(find(m.begin(),m.end(),uid)!=m.end()){
                        reply="already_member";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    auto &r=groups[gid].requests;
                    if(find(r.begin(),r.end(),uid)==r.end()){
                        reply="no_such_request";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string op="ACCEPT_REQ|"+gid+"|"+uid;
                if(commit_op(op)){
                    lock_guard<mutex> lock(state_mutex);
                    auto &m=groups[gid].members;
                    reply = (find(m.begin(),m.end(),uid)!=m.end()) ? "OK request_accepted" : "no_such_request";
                }
                else {
                    reply="log_append error in accept request";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }
            if(words[0] == "upload_file") {
                if(words.size() < 8) {
                    reply = "Invalid arguments for upload file";
                    send_reply_with_marker(client_fd, reply);
                    continue;
                }
                if(current_user.empty()) {
                    reply = "you_must_login_first to upload file";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid = words[1];
                string filename = words[2];
                // Validate every field instead of letting stoull/stoi throw:
                // an uncaught exception here would kill the whole tracker.
                uint64_t filesize = 0, port_num = 0, num_pieces = 0;
                string peer_ip = words[4];
                string full_hash = words[6];
                in_addr ip_check;
                if(!parse_u64(words[3], filesize) || !parse_u64(words[5], port_num) ||
                   port_num < 1 || port_num > 65535 || !parse_u64(words[7], num_pieces) ||
                   inet_pton(AF_INET, peer_ip.c_str(), &ip_check) != 1 || !is_sha1_hex(full_hash)) {
                    reply = "invalid_upload_arguments";
                    send_reply_with_marker(client_fd, reply);
                    continue;
                }
                int peer_port = (int)port_num;
                if(num_pieces != (filesize + PIECE_SIZE - 1) / PIECE_SIZE ||
                   words.size() != 8 + num_pieces) {
                    reply = "mismatch_num_pieces";
                    send_reply_with_marker(client_fd, reply);
                    continue;
                }
                vector<string> piece_hashes;
                bool bad_hash = false;
                for(uint64_t i = 0; i < num_pieces; i++){
                    if(!is_sha1_hex(words[8+i])) bad_hash = true;
                    piece_hashes.push_back(words[8+i]);
                }
                if(bad_hash) {
                    reply = "invalid_upload_arguments";
                    send_reply_with_marker(client_fd, reply);
                    continue;
                }
                // Validate group membership
                {
                    lock_guard<mutex> lock(state_mutex);
                    if(!groups.count(gid)) {
                        reply = "no_such_group";
                        send_reply_with_marker(client_fd, reply);
                        continue;
                    }
                    auto &members = groups[gid].members;
                    if(find(members.begin(), members.end(), current_user) == members.end()) {
                        reply = "not_member";
                        send_reply_with_marker(client_fd, reply);
                        continue;
                    }
                }
                string peer = peer_ip + ":" + to_string(peer_port);
                string op = "UPLOAD_FILE|" + gid + "|" +filename + "|" +to_string(filesize)+"|" +peer + "|" 
                            + full_hash + "|" +join_piece_hashes(piece_hashes);

                if(commit_op(op)) {
                    reply = "OK file_uploaded";
                } else {
                    reply = "log append error in upload file";
                }
                send_reply_with_marker(client_fd, reply);
                continue;
            }
            if(words[0]=="list_files"){
                if(words.size()!=2){
                    reply="Invalid arguments for list_files";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid=words[1];
                lock_guard<mutex> lock(state_mutex);
                if(!group_files.count(gid)){
                    reply="No files\n";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string out;
                for(auto &p:group_files[gid]){
                    FileMeta &fm=p.second;
                    out+=fm.filename+" "+to_string(fm.filesize)+" "+fm.filehash+"\n";
                }
                if(out.empty()) out="No files\n";
                send_reply_with_marker(client_fd,out);
                continue;
            }
            if(words[0] == "download_file") {
                if(words.size() != 3) {
                    reply = "invalid command for download";
                    send_reply_with_marker(client_fd, reply);
                    continue;
                }
                string gid=words[1];
                string filename=words[2];
                lock_guard<mutex>lock(state_mutex);
                if(!group_files.count(gid) || !group_files[gid].count(filename)) {
                    reply = "no_such_file in the group";
                    send_reply_with_marker(client_fd, reply);
                    continue;
                }
                FileMeta &fm =group_files[gid][filename];
                std::ostringstream oss;
                oss << "OK " 
                    <<fm.filesize << " "
                    <<fm.filehash << " "
                    <<fm.piece_hashes.size();
                for(const auto &ph:fm.piece_hashes)oss<<" "<<ph;
                vector<string> filtered_seeders;
                for (const auto &s : fm.seeders) {
                    if (s == peer) continue;
                    // Check if this seeder still exists in tracker records for this file
                    bool still_sharing = false;
                    if (group_files.count(gid) && group_files[gid].count(filename)) {
                        FileMeta &fcheck = group_files[gid][filename];
                        if (find(fcheck.seeders.begin(), fcheck.seeders.end(), s) != fcheck.seeders.end()) {
                            still_sharing = true;
                        }
                    }
                    if (still_sharing) filtered_seeders.push_back(s);
                }
                oss << " " << filtered_seeders.size();
                for(const auto &s :filtered_seeders) oss<<" "<<s;
                reply=oss.str();
                send_reply_with_marker(client_fd,reply);
                continue;
            }
            if(words[0]=="stop_share"){
                if(words.size()!=5){
                    reply="Invaid arguments for stop_share";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid=words[1], filename=words[2],seeder_ip=words[3],seeder_port=words[4];
                if(current_user.empty()){
                    reply="you_must_login_first";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                {
                    lock_guard<mutex> lock(state_mutex);
                    if(!groups.count(gid)){
                        reply="no_such_group";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    auto &members = groups[gid].members;
                    if(find(members.begin(), members.end(), current_user) == members.end()){
                        reply="not_member";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string op = "STOP_SHARE|" + gid + "|" + filename + "|" + seeder_ip+"|"+seeder_port;
                if(commit_op(op)){
                    reply="OK stopped";
                } else {
                    reply="Log append error for stop_share";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }
        }
    }
    close(client_fd);
}
int main(int argc,char** argv){
    if(argc<3){
        cout<<"Invalid arguments to start"<<endl;
        return 1;
    }
    string infofile=argv[1];
    int tracker_no=atoi(argv[2]);
    vector<pair<string,int>> trackers;
    ifstream fin(infofile);
    if(!fin.is_open()){
        cerr<<"Cannot open "<<infofile<<endl;
        return 1;
    }
    string tip;
    int tport;
    while(fin>>tip>>tport) {
        trackers.push_back({tip,tport});
    }
    fin.close();
    if(tracker_no<1||tracker_no>(int)trackers.size()){
        cout<<"Invalid tracker_no"<<endl;
        return 1;
    }
    string myip=trackers[tracker_no-1].first;
    int myport=trackers[tracker_no-1].second;

    replay_log_full();
    thread watcher(watcher_thread);
    watcher.detach();

    int listen_fd=socket(AF_INET,SOCK_STREAM,0);
    if(listen_fd<0){
        perror("socket");
        return 1;
    }
    int opt=1;setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in addr;memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=htons((uint16_t)myport);
    addr.sin_addr.s_addr=INADDR_ANY;
    if(::bind(listen_fd,(sockaddr*)&addr,sizeof(addr))<0){
        perror("bind");
        close(listen_fd);
        return 1;
    }
    if(listen(listen_fd,20)<0){
        perror("listen");
        close(listen_fd);
        return 1;
    }
    cout<<"Tracker "<<tracker_no<<" listening on "<<myip<<":"<<myport<<endl;
    while(true){
        sockaddr_in client_addr;
        socklen_t cl=sizeof(client_addr);
        int client_fd=accept(listen_fd,(sockaddr*)&client_addr,&cl);
        if(client_fd<0) continue;
        thread t(handle_client,client_fd);
        t.detach();
    }
    close(listen_fd);
    return 0;
}
