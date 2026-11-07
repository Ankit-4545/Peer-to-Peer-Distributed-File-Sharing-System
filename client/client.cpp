#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <mutex>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <map>
#include <set>
#include <condition_variable>
#include <sys/stat.h>
#include <fstream>

const std::string UPLOADS_REGISTRY = ".uploads_registry";
std::string cached_password="";
std::string localip;
#include "files.h"
#include "peer.h"
using namespace std;

struct Tracker {
    string ip;
    int port;
};

struct Peer {
    string ip;
    int port;
};

vector<Tracker> trackers;
int current_tracker=-1;
int sock=-1;
mutex sock_lock;
string cached_uid="";           
string cached_session="";       
int peer_listen_port=0;
// Serializes use of the tracker connection between the command loop and the
// background download threads (re-announces and peer-list refreshes).
recursive_mutex tracker_mtx;

void save_upload_record(const string &uid, const string &gid, const string &filename, const string &filepath) {
    ofstream out(UPLOADS_REGISTRY, ios::app);
    if(out.is_open()) {
        out << uid << " " << gid << " " << filename << " " << filepath << "\n";
    }
}

vector<tuple<string,string,string,string>> load_upload_records() {
    vector<tuple<string,string,string,string>> records;
    ifstream in(UPLOADS_REGISTRY);
    string uid, gid, filename, filepath;
    while(in >> uid >> gid >> filename >> filepath) {
        records.emplace_back(uid, gid, filename, filepath);
    }
    return records;
}

void read_tracker_file(string filename) {
    int fd=open(filename.c_str(),O_RDONLY);
    if(fd<0) {
        cout<<"cannot open tracker_info.txt"<<endl;
        exit(0);
    }
    char buf[1024];
    int n=read(fd,buf,sizeof(buf)-1);
    close(fd);
    if(n<=0) {
        cout<<"Invalid tracker file"<<endl;
        exit(0);
    }
    buf[n]='\0';
    string content(buf);
    stringstream ss(content);
    string line;
    while(getline(ss,line)) {
        if(line.size()==0) continue;
        stringstream ls(line);
        string ip;
        int port;
        if(!(ls>>ip>>port)) continue;
        Tracker t;
        t.ip=ip;
        t.port=port;
        trackers.push_back(t);
    }
    if(trackers.size()==0) {
        cout<<"No valid trackers found"<<endl;
        exit(0);
    }
}

int connect_to_tracker(int index) {
    if(index<0 || index>=trackers.size()) return -1;
    int s=socket(AF_INET,SOCK_STREAM,0);
    if(s<0) return -1;
    sockaddr_in serv;
    serv.sin_family=AF_INET;
    serv.sin_port=htons(trackers[index].port);
    serv.sin_addr.s_addr=inet_addr(trackers[index].ip.c_str());
    if(connect(s,(sockaddr*)&serv,sizeof(serv))<0) {
        close(s);
        return -1;
    }
    current_tracker=index;
    return s;
}

bool try_connect() {
    for(int i=0;i<trackers.size();i++) {
        int s = connect_to_tracker(i);
        if(s>=0) {
            if(sock>0 && sock!=s) {
                close(sock);
            }
            sock = s;
            cout<<"Connected to tracker "<<trackers[i].ip<<":"<<trackers[i].port<<"\n";
            return true;
        }
    }
    return false;
}

//get first token of a command
string first_word(const string &cmd) {
    stringstream ss(cmd);
    string w;
    ss >> w;
    return w;
}

//send command wraps the session if cached reads until end of reply
bool send_command(string cmd,string &response) {
    lock_guard<mutex>lg(sock_lock);
    if(sock<0) {
        return false;
    }
    string to_send=cmd;
    string fw=first_word(cmd);
    if(!cached_uid.empty()&&!cached_session.empty()) {
        // don't wrap login/create_user or session commands
        if(fw!="login"&&fw!="create_user"&&fw!="session") {
            to_send=string("session ")+cached_uid+" " + cached_session+" " +cmd;
        }
    }
    to_send+="\n";
    ssize_t n=send(sock, to_send.c_str(), (int)to_send.size(), 0);
    if (n<=0){
        close(sock);
        sock = -1;
        return false;
    }
    // read until end of reply
    string acc;
    const int BUF = 8192;
    char buffer[BUF];
    while(true){
        ssize_t r=recv(sock,buffer,BUF-1,0);
        if(r<=0){
            close(sock);
            sock=-1;
            return false;
        }
        buffer[r]='\0';
        acc.append(buffer,(size_t)r);
        if (acc.find("END_OF_REPLY\n")!=string::npos)break;
    }
    size_t pos=acc.find("END_OF_REPLY\n");
    if(pos != string::npos) {
        response = acc.substr(0, pos);
        if(!response.empty()&&response.back()=='\n')response.pop_back();
    } 
    else{
        response=acc;
    }
    return true;
}

// send without waiting for response with wrap session handle
bool send_command_noresp(string cmd) {
    lock_guard<mutex> lg(sock_lock);
    if(sock<0) {
        return false;
    }
    string to_send = cmd;
    string fw = first_word(cmd);
    if(!cached_uid.empty() && !cached_session.empty()) {
        if(fw != "login" && fw != "create_user" && fw != "session") {
            to_send = string("session ") + cached_uid + " " + cached_session + " " + cmd;
        }
    }
    to_send += "\n";
    int n = send(sock, to_send.c_str(), (int)to_send.size(), 0);
    if(n<=0){ 
        close(sock); 
        sock = -1;
        return false; 
    }
    return true;
}

//send command with failover handling
bool send_with_failover(const string &cmd, string &out_reply, bool is_login = false) {
    lock_guard<recursive_mutex> tracker_guard(tracker_mtx);
    out_reply.clear();
    int attempts = 0;
    int start = (current_tracker >= 0) ? current_tracker : 0;
    while(attempts < trackers.size()) {
        if(sock < 0) {
            int s = connect_to_tracker(start);
            if(s >= 0) {
                sock = s;
                cout << "Connected to tracker " << trackers[start].ip << ":" << trackers[start].port << "\n";
            } else {
                start = (start + 1) % trackers.size();
                attempts++;
                continue;
            }
        }
        string reply_local;
        if(send_command(cmd, reply_local)) {
            if(!is_login &&
               (reply_local.find("you should login first") != string::npos ||
                reply_local.find("already_logged_in_on_this_client") != string::npos)){
                cout << "Failover Session lost on tracker "
                     << trackers[start].ip << ":" << trackers[start].port << "\n";
                cached_session.clear();
                // Attempt auto-login only if we have credentials
                if(!cached_password.empty()&&!cached_uid.empty()) {
                    string login_cmd="login "+cached_uid + " " + cached_password;
                    string login_reply;
                    // try login on the same tracker first
                    if(send_command(login_cmd, login_reply)) {
                        // check if login succeeded
                        if(login_reply.find("OK login_success") == 0) {
                            // parse first line for token
                            size_t posn = login_reply.find('\n');
                            string firstline = (posn==string::npos) ? login_reply : login_reply.substr(0,posn);
                            stringstream ls(firstline);
                            string ok, tag, token;
                            ls >> ok >> tag >> token;
                            if(!token.empty()) {
                                cached_session = token;
                                cout << "Failover Auto-login succeeded on tracker "
                                     << trackers[start].ip << ":" << trackers[start].port << "\n";
                                // retry original command on same tracker
                                if(send_command(cmd, reply_local)) {
                                    out_reply = reply_local;
                                    return true;
                                }
                            } 
                            else{
                                cout<<"Failover Auto-login response missing token\n";
                            }
                        } 
                        else{
                            cout<<"Failover Auto-login failed: "<<login_reply << "\n";
                        }
                    } 
                    else{
                        cout<<"Failover Auto-login attempt failed to contact tracker\n";
                    }
                } 
                else{
                    cout << "Failover No cached credentials for auto-login\n";
                }
            } 
            else{
                out_reply = reply_local;
                return true;
            }
        } 
        if(sock >= 0){
            close(sock); 
            sock = -1; 
        }
        start=(start+1)%trackers.size();
        attempts++;
    }
    cout << "All trackers down"<<endl;
    return false;
}
//get ip from input socket
string get_local_ip_from_socket(int s){
    sockaddr_in name;
    socklen_t namelen=sizeof(name);
    if(s<=0) return string("127.0.0.1");
    if(getsockname(s,(sockaddr*)&name,&namelen)<0) return string("127.0.0.1");
    char buf[64];
    const char *p=inet_ntop(AF_INET,&name.sin_addr,buf,sizeof(buf));
    if(p) return string(buf);
    return string("127.0.0.1");
}

// The peer engine (peer.cpp) listens for other peers and runs uploads/downloads.
bool start_peer_server(){
    bool ok=p2p::start_engine();
    peer_listen_port=p2p::listen_port();
    return ok;
}

int main(int argc,char *argv[]) {
    if(argc!=3) {
        cout<<"Invalid arguments for main"<<endl;
        return 0;
    }
    string ip_port=argv[1];
    string file=argv[2];
    read_tracker_file(file);

    size_t pos=ip_port.find(":");
    if(pos==string::npos) {
        cout<<"Invalid ip:port"<<endl;
        return 0;
    }

    string tracker_ip=ip_port.substr(0,pos);
    int tracker_port=atoi(ip_port.substr(pos+1).c_str());

    int initial=-1;
    for(int i=0;i<trackers.size();i++){
        if(trackers[i].ip==tracker_ip && trackers[i].port==tracker_port){
            initial=i;
            break;
        }
    }
    if(initial>=0) {
        sock=connect_to_tracker(initial);
        if(sock<0){
            cout<<"Cannot connect to the tracker. Trying other tracker"<<endl;
            try_connect();
        } 
        else{
            cout<<"Connected to tracker "<<trackers[initial].ip<<":"<<trackers[initial].port<<"\n";
        }
    } 
    else{
        try_connect();
    }
    if (localip.empty()) {
        localip = get_local_ip_from_socket(sock >= 0 ? sock : 0);
    }
    // Hooks the peer engine uses from its background threads.
    p2p::tracker_request = [](const string &c, string &reply) {
        return send_with_failover(c, reply);
    };
    p2p::announce_ip = []() {
        lock_guard<recursive_mutex> lg(tracker_mtx);
        return get_local_ip_from_socket(sock >= 0 ? sock : 0);
    };
    p2p::on_download_complete = [](const string &gid, const string &fname, const string &path) {
        lock_guard<recursive_mutex> lg(tracker_mtx);
        save_upload_record(cached_uid, gid, fname, path);
    };
    while(true){
        cout<<"> ";
        string cmd;
        if(!getline(cin,cmd)) break;
        if(cmd=="quit") {
            break;
        }
        // Commands run one at a time against the tracker; background
        // downloads wait for the current command to finish.
        lock_guard<recursive_mutex> tracker_guard(tracker_mtx);
        if(cmd.size()==0) continue;
        stringstream ssin(cmd);
        vector<string> words; 
        string w;
        while(ssin>>w) words.push_back(w);
        if(words.size()==0) continue;
        //handle command on client side
        if(words[0] == "create_user") {
            if(words.size() != 3) {
                cout << "Invalid arguments for create_user in client"<<endl;
                continue;
            }
            string cmd="create_user "+words[1]+" "+words[2];
            string reply;
            if(!send_with_failover(cmd, reply)) {
                cout << "Tracker request failed\n";
                continue;
            }
            cout<<reply<<endl;
            continue;
        }
        // If user tries to login via this client, intercept to capture session token
        else if(words[0] == "login") {
            if(words.size()!=3){
                cout<<"Invalid arguments for login"<<endl;
                continue;
            }
            if(!cached_uid.empty()){
                cout<<"already_logged_in_on_this_client\n";
                continue;
            }
            string reply;
            if(sock<0) {
                if(!try_connect()) {
                    cout << "Tracker request failed\n";
                    continue;
                }
            }
            if(!send_command(cmd, reply)) {
                cout << "Tracker request failed, trying next tracker...\n";
                int start = (current_tracker+1) % trackers.size();
                int cnt = 0;
                bool logged_in = false;
                while(cnt < trackers.size()) {
                    int s = connect_to_tracker(start);
                    if(s >= 0) {
                        if(sock>0 && sock!=s) close(sock);
                        sock = s;
                        cout<<"Connected to tracker "<<trackers[start].ip<<":"<<trackers[start].port<<"\n";
                        if(send_command(cmd, reply)) {
                            logged_in = true;
                            break;
                        }
                    }
                    start = (start+1)%trackers.size();
                    cnt++;
                }
                if(!logged_in) {
                    cout << "Tracker request failed\n";
                    continue;
                }
            }
            size_t posn = reply.find('\n');
            string firstline = (posn==string::npos)?reply:reply.substr(0,posn);
            stringstream ls(firstline);
            string ok_or_err; ls >> ok_or_err;
            if(ok_or_err == "OK") {
                string second; ls >> second;
                if(second == "login_success") {
                    string token; ls >> token;
                    if(!token.empty()){
                        cached_uid = words[1];
                        cached_session = token;
                        cached_password=words[2];
                        cout << firstline << "\n";
                        //Ensure peer server is running so peer_listen_port is set
                        if(!start_peer_server()) {
                            cout << "could not start peer server for re-announce"<<endl;
                        }
                        //re-announce only for files uploaded by this user
                        auto records = load_upload_records();
                        set<pair<string,std::string>> announced;
                        for(auto &rec : records){
                            string uid, gid, filename, filepath;
                            tie(uid, gid, filename,filepath) = rec;
                            if(uid != cached_uid)continue;  
                            if(announced.count({gid, filename})) continue;
                            announced.insert({gid, filename});   
                            if(access(filepath.c_str(), F_OK) != -1) {
                                // compute hashes and filesize
                                vector<string> piece_hashes;
                                string full_hash;
                                uint64_t filesize = 0;
                                if(!compute_file_hashes(filepath, piece_hashes, full_hash, filesize))continue;
                                p2p::seed_file(gid, filename, filepath, filesize, full_hash, piece_hashes);
                                string localip = get_local_ip_from_socket(sock >= 0 ? sock : 0);
                                if(!start_peer_server())localip = "0.0.0.0";
                                stringstream out;
                                out << "upload_file "<<gid <<" "<<filename << " "
                                    <<filesize<< " " << localip << " " << peer_listen_port << " "
                                    << full_hash<<" " << piece_hashes.size();
                                for(auto &ph : piece_hashes) out << " " << ph;
                                string dummy;
                                if(!send_with_failover(out.str(),dummy))
                                    cout << "Announce " << filename << " failed"<<endl;
                                else
                                    cout << "Announce " << filename << " success"<<endl;
                            }
                        }
                        continue;
                    }
                }
                cout << firstline << "\n";
                continue;
            } 
            else{
                cout << firstline << "\n";
                continue;
            }
        }
        else if(words[0] == "create_group") {
            if(words.size() != 2) { cout << "Invalid arguments for create_group in client"<<endl; 
                continue; 
            }
            if(cached_uid.empty()||cached_session.empty()){ 
                cout<<"you should login first\n"; 
                continue; 
            }
            string cmdline="create_group "+words[1];
            string reply;
            if(!send_with_failover(cmdline, reply)){ 
                cout<<"Tracker request failed\n"; 
                continue; 
            }
            cout<<reply<<endl;
            continue;
        }
        else if(words[0]=="join_group"){
            if(words.size() != 2){ 
                cout << "Invalid arguments for join group in client"<<endl; 
                continue; 
            }
            if(cached_uid.empty() || cached_session.empty()) { 
                cout<<"you should login first"<<endl; 
                continue; 
            }
            string cmdline = "join_group " + words[1];
            string reply;
            if(!send_with_failover(cmdline, reply)) { 
                cout<<"Tracker request failed"<<endl; 
                continue; 
            }
            cout << reply<<endl;
            continue;
        }
        else if(words[0] == "leave_group") {
            if(words.size() != 2) { 
                cout << "Invalid arguments for leave group in client"<<endl; 
                continue; 
            }
            if(cached_uid.empty() || cached_session.empty()) { 
                cout << "you should login first\n"; 
                continue; 
            }
            string cmdline = "leave_group " + words[1];
            string reply;
            if(!send_with_failover(cmdline, reply)) { 
                cout << "Tracker request failed\n"; 
                continue; 
            }
            cout << reply << "\n";
            string gid_to_remove = words[1];
            auto records = load_upload_records();
            ofstream out(UPLOADS_REGISTRY, ios::trunc);
            for(auto &rec : records) {
                string uid, gid, filename, filepath;
                tie(uid, gid, filename, filepath) = rec;
                if(uid != cached_uid || gid != gid_to_remove) {
                    out << uid << " " << gid << " " << filename << " " << filepath << "\n";
                }
            }
            out.close();
            for(auto &rec : records) {
                string uid, gid, filename, filepath;
                tie(uid, gid, filename, filepath) = rec;
                if(uid == cached_uid && gid == gid_to_remove) {
                    string fname_only;
                    size_t pos = filepath.find_last_of("/\\");
                    if(pos != string::npos) fname_only = filepath.substr(pos + 1);
                    else fname_only = filepath;
                    string cmd_stop = "stop_share " + gid + " " + fname_only + " " 
                                        + localip + " " 
                                        + to_string(peer_listen_port);
                    string tmp;
                    send_with_failover(cmd_stop, tmp);
                    p2p::stop_share(gid, fname_only);
                }
            }
        }
        else if(words[0] == "list_groups") {
            if(words.size() != 1) { 
                cout << "Invalid arguments for list groups in client"<<endl; 
                continue; 
            }
            if(cached_uid.empty() || cached_session.empty()) { 
                cout << "you should login first"<<endl; 
                continue; 
            }
            string reply;
            if(!send_with_failover("list_groups", reply)) { 
                cout << "Tracker request failed"<<endl; 
                continue; 
            }
            cout << reply << "\n";
            continue;
        }
        else if(words[0] == "list_requests") {
            if(words.size() != 2) { 
                cout << "Invalid arguments for list_requests"<<endl; 
                continue; 
            }
            if(cached_uid.empty() || cached_session.empty()) { 
                cout << "you should login first"<<endl; 
                continue; 
            }
            string cmdline = "list_requests " + words[1];
            string reply;
            if(!send_with_failover(cmdline, reply)) { 
                cout << "Tracker request failed\n"; 
                continue; 
            }
            cout << reply << "\n";
            continue;
        }
        else if(words[0] == "accept_request") {
            if(words.size() != 3) { 
                cout << "Invalid arguments for accept requests in client"<<endl; 
                continue; 
            }
            if(cached_uid.empty() || cached_session.empty()) { 
                cout << "you should login first"<<endl; 
                continue; 
            }
            string cmdline = "accept_request " + words[1] + " " + words[2];
            string reply;
            if(!send_with_failover(cmdline, reply)) { 
                cout << "Tracker request failed\n"; 
                continue; 
            }
            cout << reply <<endl;
            continue;
        }
        else if(words[0] == "logout") {
            string reply;
            if(!send_with_failover(cmd,reply)){
                cout<<"Tracker request failed"<<endl;
                continue;
            }
            size_t posn = reply.find('\n');
            string firstline = (posn==string::npos)?reply:reply.substr(0,posn);
            if(firstline.rfind("OK",0) == 0) {
                cached_uid.clear();
                cached_session.clear();
            }
            cout << firstline <<endl;
            continue;
        }
        else if(words[0] == "upload_file") {
            if(words.size() != 3) {
                cout << "Invalid arguments for upload file in client"<<endl;
                continue;
            }
            string gid = words[1];
            string filepath = words[2];
            vector<string> piece_hashes;
            string full_hash;
            uint64_t filesize = 0;
            if(!compute_file_hashes(filepath, piece_hashes, full_hash, filesize)) {
                cout << "cannot_open_file\n";
                continue;
            }
            string filename;
            size_t pos = filepath.find_last_of("/\\");
            if(pos != string::npos) filename = filepath.substr(pos + 1);
            else filename = filepath;
            if(!start_peer_server()) {
                cout << "cannot_start_peer_server"<<endl;
                continue;
            }
            // Serve the file before announcing it, so peers that hear about it can connect at once.
            if(!p2p::seed_file(gid, filename, filepath, filesize, full_hash, piece_hashes)) {
                cout << "cannot_open_file"<<endl;
                continue;
            }
            string localip = get_local_ip_from_socket(sock >= 0 ? sock : 0);
            stringstream out;
            out << "upload_file " << gid << " " << filename << " " 
                << filesize << " " << localip << " " << peer_listen_port << " " 
                << full_hash << " " << piece_hashes.size();
            for(auto &ph : piece_hashes) out << " " << ph;
            string upr;
            if(!send_with_failover(out.str(),upr)) {
                cout << "upload_failed in sending to tracker"<<endl;
            }
            else {
                string firstline;
                size_t ppos = upr.find('\n');
                firstline = (ppos==string::npos) ? upr : upr.substr(0, ppos);
                if(firstline.rfind("OK",0) == 0) {
                    cout << "Upload registered"<<endl;
                    save_upload_record(cached_uid,gid,filename,filepath);
                } else {
                    cout << firstline << endl;
                }
            }
            continue;
        }
        else if(words[0]=="list_files"){
            if(words.size()!=2){
                cout<<"Invalid arguments for list files in client"<<endl;
                continue;
            }
            string lrep;
            send_with_failover(cmd,lrep);
            cout<<lrep<<endl;
            continue;
        }
        else if(words[0] == "download_file") {
            if(words.size() != 4) {
                cout << "Invalid arguments for download file in client"<<endl;
                continue;
            }
            string gid = words[1];
            string filename = words[2];
            string dest_folder = words[3];
            if(dest_folder.back() != '/' && dest_folder.back() != '\\') dest_folder += "/";
            auto create_dir_recursive = [](const string &path) -> bool {
                if(path.empty()) return false;
                char tmp[1024];
                strncpy(tmp, path.c_str(), sizeof(tmp));
                tmp[sizeof(tmp)-1] = 0;
                for(char *p = tmp + 1; *p; p++) {
                    if(*p == '/' || *p == '\\') {
                        *p = 0;
                        if(mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
                        *p = '/';
                    }
                }
                if(mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
                return true;
            };
            if(!create_dir_recursive(dest_folder)) {
                cout << "cannot_create_folder"<<endl;
                continue;
            }
            string fullpath = dest_folder + filename;
            string ask = "download_file " + gid + " " + filename;
            string reply;
            if(!send_with_failover(ask,reply)) {
                cout << "Tracker request failed"<<endl;
                if(!try_connect() || !send_command(ask, reply)) {
                    cout << "All trackers unavailable"<<endl;
                    continue;
                }
            }
            stringstream ls(reply);
            string status; ls >> status;
            if(status != "OK") {
                cout << reply << "\n";
                continue;
            }
            uint64_t filesize; ls >> filesize;
            string filehash; ls >> filehash;
            int num_pieces; ls >> num_pieces;
            vector<string> piece_hashes(num_pieces);
            for(int i=0; i<num_pieces; i++) ls >> piece_hashes[i];
            int num_seeders; ls >> num_seeders;
            if(num_seeders <= 0) { 
                cout << "No seeders"<<endl; 
                continue; 
            }
            vector<string> seeders(num_seeders);
            for(int i=0;i<num_seeders;i++) ls >> seeders[i];
            // BitTorrent-style download: runs in the background over persistent
            // peer connections, resumes from fullpath.part/.state if present, and
            // starts sharing pieces with other peers as soon as they are verified.
            string msg;
            p2p::start_download(gid, filename, fullpath, filesize, filehash, piece_hashes, seeders, msg);
            peer_listen_port = p2p::listen_port();
            cout << msg << endl;
            continue;
        }
        else if(words[0]=="show_downloads"){
            p2p::print_downloads();
            continue;
        }
        else if(words[0]=="stop_share"){
            if(words.size()!=3){
                cout<<"Invalid arguments for stop share in client"<<endl;
                continue;
            }
            if(peer_listen_port==0){
                cout<<"sharing stopped"<<endl; 
                continue;
            }
            string gid=words[1],filename=words[2];
            string localip=get_local_ip_from_socket(sock>=0?sock:0);
            string cmdline="stop_share "+gid+" "+filename+" "+localip+" "+to_string(peer_listen_port);
            string tmp1;
            send_with_failover(cmdline,tmp1);
            p2p::stop_share(gid,filename);
            cout<<tmp1<<endl;
            continue;
        }
        else{
            cout<<"Invalid command"<<endl;
            continue;
        }
        string tmp;
        send_with_failover(cmd,tmp);
    }
    if(sock>=0) close(sock);
    return 0;
}
