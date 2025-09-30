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

#include "files.h"

using namespace std;

struct User{
    string password;
    bool loggedin;
    string session;
};
struct Group{
    string owner;
    vector<string> members;
    vector<string> requests;
};

map<string,User> users;
map<string,Group> groups;
map<string,map<string,FileMeta>> group_files;
mutex state_mutex;
map<string,string> active_sessions; // session->user

const string SYNC_LOG="sync_log.txt";
off_t last_offset=0;
mutex file_mutex;

bool is_logged_in(const string &uid, const string &sess) {
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
    vector<string> out;string cur;
    for(char c:s){
        if(c==delim){
            out.push_back(cur);
            cur.clear();
        }
        else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

void apply_op_line(const string &line){
    if(line.empty()) {
        return;
    }
    vector<string> parts=split(line,'|');
    if(parts.size()==0){
        return;
    }
    lock_guard<mutex>lock(state_mutex);

    if(parts[0]=="CREATE_USER"){
        if(parts.size()!=3){
            return;
        }
        string uid=parts[1];
        string pw=parts[2];
        if(!users.count(uid)){
            users[uid].password=pw;
            users[uid].loggedin=false;
            users[uid].session="";
        }
        return;
    }

    if(parts[0]=="CREATE_GROUP"){
        if(parts.size()!=3) return;
        string gid=parts[1];
        string own=parts[2];

        if(!groups.count(gid)){
            Group g;
            g.owner = own;
            g.members.push_back(own);
            // requests is empty by default
            groups[gid] = g; 
        }
        return;
    }

    if(parts[0]=="JOIN_REQ"){
        if(parts.size()!=3) return;
        string gid=parts[1];
        string uid=parts[2];
        if(groups.count(gid)){
            groups[gid].requests.push_back(uid);
        }
        return;
    }

    if(parts[0]=="ACCEPT_REQ"){
        if(parts.size()!=3) return;
        string gid=parts[1];
        string uid=parts[2];
        if(groups.count(gid)){
            auto &r = groups[gid].requests;
            r.erase(remove(r.begin(), r.end(), uid), r.end());
            groups[gid].members.push_back(uid);
        }
        return;
    }
    if(parts[0]=="LOGIN"){
        if(parts.size()!=3) return;
        string uid=parts[1];
        string sid=parts[2];
        if(users.count(uid)){
            users[uid].loggedin=true;
            users[uid].session=sid;
        }
        return;
    }

    if(parts[0]=="LOGOUT"){
        if(parts.size()!=2) return;
        string uid=parts[1];
        if(users.count(uid)){
            users[uid].loggedin=false;
            users[uid].session="";
        }
        return;
    }


    if(parts[0]=="LEAVE_GROUP"){
        if(parts.size()!=3) return;
        string gid=parts[1];
        string uid=parts[2];
        if(groups.count(gid)){
            auto &m = groups[gid].members;
            m.erase(remove(m.begin(), m.end(), uid), m.end());
        }
        return;
    }

    if(parts[0]=="UPLOAD_FILE"){
        // format: UPLOAD_FILE|<gid>|<filename>|<filesize>|<peerip:peerport>|<filehash>|<piecehash1>,<piecehash2>,...
        if(parts.size()<7) return;
        string gid=parts[1];
        string filename=parts[2];
        uint64_t filesize=0;
        try{ filesize=(uint64_t)stoull(parts[3]); } catch(...) { filesize=0; }
        string peer=parts[4];
        string filehash=parts[5];
        string piecehashes_str=parts[6];
        vector<string> ph=split(piecehashes_str,',');
        if(!group_files.count(gid)) group_files[gid]=map<string,FileMeta>();
        FileMeta fm;
        fm.filename=filename;fm.filesize=filesize;fm.filehash=filehash;fm.piece_hashes=ph;
        if(group_files[gid].count(filename)){
            FileMeta &old=group_files[gid][filename];
            if(find(old.seeders.begin(),old.seeders.end(),peer)==old.seeders.end()){
                old.seeders.push_back(peer);
            }
        } else {
            fm.seeders.clear();fm.seeders.push_back(peer);
            group_files[gid][filename]=fm;
        }
        return;
    }

    if(parts[0]=="STOP_SHARE"){
        // format: STOP_SHARE|<gid>|<filename>|<peerip:peerport>
        if(parts.size()!=4) return;
        string gid=parts[1];
        string filename=parts[2];
        string peer=parts[3];
        if(group_files.count(gid) && group_files[gid].count(filename)){
            FileMeta &fm=group_files[gid][filename];
            fm.seeders.erase(remove(fm.seeders.begin(),fm.seeders.end(),peer),fm.seeders.end());
            if(fm.seeders.empty()){
                group_files[gid].erase(filename);
            }
        }
        return;
    }
}

bool append_op_to_log(const string &line){
    lock_guard<mutex> lock(file_mutex);
    int fd=open(SYNC_LOG.c_str(),O_WRONLY|O_APPEND|O_CREAT,0644);
    if(fd<0){
        cerr<<"open("<<SYNC_LOG<<") failed: "<<strerror(errno)<<"\n";
        return false;
    }
    string out=line+"\n";
    ssize_t w=write(fd,out.c_str(),out.size());
    close(fd);
    return w==(ssize_t)out.size();
}

void replay_log_full(){
    int fd0=open(SYNC_LOG.c_str(),O_RDONLY);
    if(fd0<0){
        if(errno==ENOENT){
            int fdw=open(SYNC_LOG.c_str(),O_WRONLY|O_CREAT,0644);
            if(fdw>=0){
                close(fdw);
            }
        }
    }
    else{
        close(fd0);
    }
    lock_guard<mutex> lock(file_mutex);
    int fd=open(SYNC_LOG.c_str(),O_RDONLY);
    if(fd<0){
        last_offset=0;
        return;
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
            if(nl==string::npos)
                break;
                string line=acc.substr(pos,nl-pos);
                apply_op_line(line);pos=nl+1;
            }
            if(pos>0){
                acc.erase(0,pos);
            }
        }
    off_t off=lseek(fd,0,SEEK_END);
    if(off<0){
        off=0;
    }
    last_offset=off;
    close(fd);
}

void read_new_ops_from_log(){
    lock_guard<mutex> lock(file_mutex);
    int fd=open(SYNC_LOG.c_str(),O_RDONLY);
    if(fd<0){
        return;
    }
    if(lseek(fd,last_offset,SEEK_SET)==(off_t)-1){
        off_t off=lseek(fd,0,SEEK_END);
        last_offset=(off<0)?0:off;
        close(fd);
        return;
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
            string line=acc.substr(pos,nl-pos);
            apply_op_line(line);
            pos=nl+1;
        }
        if(pos>0) acc.erase(0,pos);
    }
    off_t off=lseek(fd,0,SEEK_END);
    if(off>=0) last_offset=off;
    close(fd);
}

void watcher_thread(){
    while(true){
        read_new_ops_from_log();
        this_thread::sleep_for(chrono::milliseconds(800));
    }
}

bool send_reply_with_marker(int fd,const string &reply){
    string out=reply;
    if(out.size()==0||out.back()!='\n') out+="\n";
    out+="END_OF_REPLY\n";
    size_t sent=0;
    while(sent<out.size()){
        ssize_t s=send(fd,out.c_str()+sent,out.size()-sent,0);
        if(s<=0) {
            return false;
        }
        sent+=(size_t)s;
    }
    return true;
}

string generate_session(){
    string chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    string tok;
    for(int i=0;i<16;i++){
        tok+=chars[rand()%chars.size()];
    }
    return tok;
}

void handle_client(int client_fd){
    string current_user;
    string current_session;
    const int BUF=4096;
    char buf[BUF];
    string acc;
    while(true){
        ssize_t r=recv(client_fd,buf,BUF,0);
        if(r<=0){
            break;
        }
        acc.append(buf,(size_t)r);
        while(true){
            size_t nl=acc.find('\n');
            if(nl==string::npos) {
                break;
            }
            string line=acc.substr(0,nl);
            acc.erase(0,nl+1);
            if(!line.empty()&&line.back()=='\r') {
                line.pop_back();
            }
            if(line.empty()) {
                continue;
            }
            vector<string> words;
            stringstream ss(line);
            string w;
            while(ss>>w){
                words.push_back(w);
            }
            string reply;
            if(words.size()==0){
                reply="Empty command";
                send_reply_with_marker(client_fd,reply);
                continue;
            }

            // bool used_session=false;
            if(words[0] == "session") {
                if(words.size() < 4) {
                    reply = "ERR usage: session <uid> <token> <command>";
                    send_reply_with_marker(client_fd, reply);
                    continue;
                }
                string uid = words[1];
                string token = words[2];
                if(!set_session(uid, token, current_user, current_session)) {
                    reply = "ERR invalid_session";
                    send_reply_with_marker(client_fd, reply);
                    continue;
                }
                words.erase(words.begin(), words.begin() + 3); // remaining command
            }

            if(words[0]=="create_user"){
                if(!current_user.empty()){
                reply="ERR cannot_create_user_while_logged_in";
                send_reply_with_marker(client_fd, reply);
                continue;
            }
                if(words.size()!=3){
                    reply="ERR usage: create_user <uid> <pw>";
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
                string op="CREATE_USER|"+uid+"|"+pw;
                if(append_op_to_log(op)){
                    // Do NOT call apply_op_line(op) here
                    apply_op_line(op);
                    reply="OK user_created";
                }
                else {
                    reply="ERR log_append";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }

            if(words[0]=="login"){
                if(!current_user.empty()){
                    reply="ERR already_logged_in_on_this_client";
                    send_reply_with_marker(client_fd, reply);
                    continue;
                }
                if(words.size()!=3){
                    reply="ERR usage: login <uid> <pw>";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string uid=words[1], pw=words[2];
                {
                    lock_guard<mutex> lock(state_mutex);
                    if(!users.count(uid) || users[uid].password!=pw){
                        reply="ERR invalid_credentials";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    if(users[uid].loggedin){
                        reply="ERR already_logged_in";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string session_id = generate_session();  // you’ll need a helper for random session
                string op="LOGIN|"+uid+"|"+session_id;
                if(append_op_to_log(op)){
                    apply_op_line(op);
                    reply="OK login_success"+session_id;
                    current_user=uid;
                    current_session=session_id;
                }
                else {
                    reply="ERR log_append";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }


            if(words[0]=="logout"){
                if(current_user.empty()){
                    reply="ERR not_logged_in";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string op="LOGOUT|"+current_user;
                if(append_op_to_log(op)){
                    apply_op_line(op);
                    reply="OK logout_success";
                    current_user="";
                    current_session="";
                }
                else {
                    reply="ERR log_append";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }


            if(words[0]=="create_group"){
                if(words.size()!=2){
                    reply="Invalid command: group can't be created";
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
                        reply="ERR group_exists";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string op="CREATE_GROUP|"+gid+"|"+current_user;
                if(append_op_to_log(op)){
                    // Do NOT call apply_op_line(op) here
                    apply_op_line(op);
                    reply="Group created";
                }
                else {
                    reply="ERR log_append";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }


            if(words[0]=="join_group"){
                if(words.size()!=2){
                    reply="ERR usage: join_group <gid>";
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
                        reply="ERR no_such_group";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    if(find(groups[gid].members.begin(), groups[gid].members.end(), current_user)!=groups[gid].members.end()){
                        reply="ERR already_member";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string op="JOIN_REQ|"+gid+"|"+current_user;
                if(append_op_to_log(op)){
                    apply_op_line(op);
                    reply="OK request_sent";
                }
                else {
                    reply="ERR log_append";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }


            if(words[0]=="leave_group"){
                if(words.size()!=2){
                    reply="ERR usage: leave_group <gid>";
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
                        reply="ERR no_such_group";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string op="LEAVE_GROUP|"+gid+"|"+current_user;
                if(append_op_to_log(op)){
                    apply_op_line(op);
                    reply="OK left_group";
                }
                else {
                    reply="ERR log_append";
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
                    reply="ERR not_owner";
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
                    reply="ERR usage: accept_request <gid> <uid>";
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
                        reply="ERR no_such_group";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    if(groups[gid].owner!=current_user){
                        reply="ERR not_owner";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string op="ACCEPT_REQ|"+gid+"|"+uid;
                if(append_op_to_log(op)){
                    apply_op_line(op);
                    reply="OK request_accepted";
                }
                else {
                    reply="ERR log_append";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }

            // Now handle upload_file/list_files/download_file/stop_share concretely
            if(words[0]=="upload_file"){
                if(words.size()!=3){
                    reply="ERR usage: upload_file <gid> <filename>";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                if(current_user.empty()){
                    reply="You must login first";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid=words[1], fname=words[2];
                {
                    lock_guard<mutex> lock(state_mutex);
                    if(!groups.count(gid)){
                        reply="ERR no_such_group";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                    if(find(groups[gid].members.begin(), groups[gid].members.end(), current_user)==groups[gid].members.end()){
                        reply="ERR not_member";
                        send_reply_with_marker(client_fd,reply);
                        continue;
                    }
                }
                string op="UPLOAD_FILE|"+gid+"|"+fname+"|"+current_user;
                if(append_op_to_log(op)){
                    apply_op_line(op);
                    reply="OK file_uploaded";
                }
                else {
                    reply="ERR log_append";
                }
                send_reply_with_marker(client_fd,reply);
                continue;
            }


            if(words[0]=="list_files"){
                if(words.size()!=2){
                    reply="ERR usage: list_files <gid>";
                    send_reply_with_marker(client_fd,reply);continue;
                }
                string gid=words[1];
                lock_guard<mutex> lock(state_mutex);
                if(!group_files.count(gid)){
                    reply="No files\n";
                    send_reply_with_marker(client_fd,reply);continue;
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

            if(words[0]=="download_file"){
                if(words.size()!=3){
                    reply="Invalid argument";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                string gid=words[1],filename=words[2];
                lock_guard<mutex> lock(state_mutex);
                if(!group_files.count(gid) || !group_files[gid].count(filename)){
                    reply="No such file";
                    send_reply_with_marker(client_fd,reply);
                    continue;
                }
                FileMeta &fm=group_files[gid][filename];
                std::ostringstream oss;
                oss<<"OK "<<fm.filesize<<" "<<fm.filehash<<" "<<fm.piece_hashes.size();
                for(auto &ph:fm.piece_hashes) oss<<" "<<ph;
                oss<<" "<<fm.seeders.size();
                for(auto &s:fm.seeders) oss<<" "<<s;
                reply=oss.str();
                send_reply_with_marker(client_fd,reply);
                continue;
            }

            if(words[0]=="stop_share"){
                // expect: stop_share <gid> <filename> <peerip> <peerport>
                if(words.size()!=5){
                    reply="ERR usage: stop_share <gid> <filename> <peerip> <peerport>";
                    send_reply_with_marker(client_fd,reply);continue;
                }
                string gid=words[1],filename=words[2],peerip=words[3],peerport=words[4];
                string peer=peerip+":"+peerport;
                string op="STOP_SHARE|"+gid+"|"+filename+"|"+peer;
                if(append_op_to_log(op)){
                    apply_op_line(op);
                    reply="OK stopped";
                } else reply="ERR log_append";
                send_reply_with_marker(client_fd,reply);
                continue;
            }

            reply="ERR unknown_command";
            send_reply_with_marker(client_fd,reply);
        }
    }
    close(client_fd);
}

int main(int argc,char** argv){
    if(argc<3){
        cout<<"Usage: "<<argv[0]<<" tracker_info.txt tracker_no\n";
        return 1;
    }
    string infofile=argv[1];
    int tracker_no=atoi(argv[2]);
    vector<pair<string,int>> trackers;
    ifstream fin(infofile);
    if(!fin.is_open()){
        cerr<<"Cannot open "<<infofile<<"\n";
        return 1;
    }
    string tip;
    int tport;
    while(fin>>tip>>tport) {
        trackers.push_back({tip,tport});
    }
    fin.close();
    if(tracker_no<1||tracker_no>(int)trackers.size()){
        cout<<"Invalid tracker_no\n";
        return 1;
    }
    string myip=trackers[tracker_no-1].first;
    int myport=trackers[tracker_no-1].second;

    srand(time(0));
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
    cout<<"Tracker "<<tracker_no<<" listening on "<<myip<<":"<<myport<<"\n";
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
