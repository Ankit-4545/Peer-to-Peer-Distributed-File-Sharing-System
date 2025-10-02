// Updated client.cpp
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
// #include<filesystem>
#include <condition_variable>
#include <sys/stat.h>
#include<fstream>

const std::string UPLOADS_REGISTRY = ".uploads_registry";
std::string cached_password="";
#include "files.h"
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
string cached_uid="";            // stored after login
string cached_session="";        // stored session token

// peer server globals
int peer_listen_fd=-1;
int peer_listen_port=0;
thread peer_thread;
mutex downloads_mutex;
struct DownloadStatus {
    string gid;
    string filename;
    uint64_t filesize;
    size_t num_pieces;
    vector<size_t> have;
    bool completed;
};
map<string,DownloadStatus> downloads;

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
        cout<<"Error opening tracker_info.txt\n";
        exit(0);
    }
    char buf[1024];
    int n=read(fd,buf,sizeof(buf)-1);
    close(fd);
    if(n<=0) {
        cout<<"Invalid tracker_info.txt\n";
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
        cout<<"No valid trackers found in tracker_info.txt\n";
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
            // close previous if any
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

// Helper: get first token of a command (without modifying original)
string first_word(const string &cmd) {
    stringstream ss(cmd);
    string w;
    ss >> w;
    return w;
}

// Robust send_command: wraps with session if cached; reads until END_OF_REPLY marker
bool send_command(string cmd, string &response) {
    lock_guard<mutex> lg(sock_lock);
    if(sock<0) {
        return false;
    }

    string to_send = cmd;
    string fw = first_word(cmd);
    if(!cached_uid.empty() && !cached_session.empty()) {
        // don't wrap login/create_user or session commands
        if(fw != "login" && fw != "create_user" && fw != "session") {
            to_send = string("session ") + cached_uid + " " + cached_session + " " + cmd;
        }
    }

    to_send += "\n";
    ssize_t n = send(sock, to_send.c_str(), (int)to_send.size(), 0);
    if (n <= 0) {
        close(sock);
        sock = -1;
        return false;
    }

    // read until marker "END_OF_REPLY\n"
    string acc;
    const int BUF = 8192;
    char buffer[BUF];
    while (true) {
        ssize_t r = recv(sock, buffer, BUF-1, 0);
        if (r <= 0) {
            close(sock);
            sock = -1;
            return false;
        }
        buffer[r] = '\0';
        acc.append(buffer, (size_t)r);
        if (acc.find("END_OF_REPLY\n") != string::npos) break;
    }
    size_t pos = acc.find("END_OF_REPLY\n");
    if (pos != string::npos) {
        response = acc.substr(0, pos);
        // trim trailing newline
        if(!response.empty() && response.back() == '\n') response.pop_back();
    } else {
        response = acc;
    }
    return true;
}

// send without waiting for response (but we still handle wrapping)
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

// old: bool send_with_failover(string cmd, bool is_login = false)
bool send_with_failover(const string &cmd, string &out_reply, bool is_login = false) {
    out_reply.clear();
    int attempts = 0;
    int start = (current_tracker >= 0) ? current_tracker : 0;
    int tried = 0;

    while(attempts < trackers.size()) {
        // ensure socket connected to 'start'
        if(sock < 0) {
            int s = connect_to_tracker(start);
            if(s >= 0) {
                sock = s;
                cout << "Connected to tracker " << trackers[start].ip << ":" << trackers[start].port << "\n";
            } else {
                // could not connect to this tracker; try next
                start = (start + 1) % trackers.size();
                attempts++;
                continue;
            }
        }

        string reply_local;
        if(send_command(cmd, reply_local)) {
            // check for session errors (only if not login/create_user/session)
            if(!is_login &&
               (reply_local.find("ERR you should login first") != string::npos ||
                reply_local.find("ERR already_logged_in_on_this_client") != string::npos)) {

                cout << "[Failover] Session lost on tracker "
                     << trackers[start].ip << ":" << trackers[start].port << "\n";

                // Keep cached_uid (we need it to try auto-login). Clear session token only.
                cached_session.clear();

                // Attempt auto-login only if we have credentials
                if(!cached_password.empty() && !cached_uid.empty()) {
                    string login_cmd = "login " + cached_uid + " " + cached_password;
                    string login_reply;
                    // try login on the same tracker first
                    if(send_command(login_cmd, login_reply)) {
                        // check if login succeeded
                        if(login_reply.find("OK login_success") == 0) {
                            // extract token in case tracker returned it
                            // parse first line for token
                            size_t posn = login_reply.find('\n');
                            string firstline = (posn==string::npos) ? login_reply : login_reply.substr(0,posn);
                            stringstream ls(firstline);
                            string ok, tag, token;
                            ls >> ok >> tag >> token;
                            if(!token.empty()) {
                                cached_session = token;
                                cout << "[Failover] Auto-login succeeded on tracker "
                                     << trackers[start].ip << ":" << trackers[start].port << "\n";
                                // retry original command on same tracker
                                if(send_command(cmd, reply_local)) {
                                    out_reply = reply_local;
                                    return true;
                                }
                            } else {
                                // login was OK but token not found — treat as failure to be safe
                                cout << "[Failover] Auto-login response missing token\n";
                            }
                        } else {
                            cout << "[Failover] Auto-login failed: " << login_reply << "\n";
                        }
                    } else {
                        cout << "[Failover] Auto-login attempt failed to contact tracker\n";
                    }
                } else {
                    cout << "[Failover] No cached credentials for auto-login\n";
                }
                // fall through to try next tracker (after closing current socket)
            } else {
                // success and not a session error (or it's a login request)
                out_reply = reply_local;
                return true;
            }
        } else {
            // send_command failed (socket dropped or read error)
        }

        // failure on this tracker -> close and try next
        if(sock >= 0) { close(sock); sock = -1; }
        start = (start + 1) % trackers.size();
        attempts++;
    }

    cout << "All trackers down or command failed on all trackers\n";
    return false;
}




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

void peer_server_thread(){
    while(true){
        if(peer_listen_fd<0){
            this_thread::sleep_for(chrono::milliseconds(200));
            continue;
        }
        sockaddr_in client_addr; 
        socklen_t cl=sizeof(client_addr);
        int cfd=accept(peer_listen_fd,(sockaddr*)&client_addr,&cl);
        if(cfd<0) continue;
        const int BUF=4096;
        char buf[BUF];
        string acc;
        ssize_t r;
        while((r=recv(cfd,buf,BUF,0))>0){
            acc.append(buf,(size_t)r);
            size_t nl=acc.find('\n');
            if(nl!=string::npos) break;
            if(acc.size()>8192) break;
        }
        if(acc.empty()){ 
            close(cfd); 
            continue; 
        }
        string req=acc;
        if(req.back()=='\n') req.pop_back();
        stringstream ss(req);
        string cmd,filename; 
        int piece_idx;
        ss>>cmd>>filename>>piece_idx;
        if(cmd!="GET_PIECE"){ 
            close(cfd); 
            continue; 
        }
        vector<char> pbuf(PIECE_SIZE);
        ssize_t got=read_piece_from_file(filename,(size_t)piece_idx,pbuf.data(),pbuf.size());
        if(got<=0){ 
            close(cfd); 
            continue; 
        }
        size_t sent=0;
        while(sent<(size_t)got){
            ssize_t w=send(cfd,pbuf.data()+sent,got-sent,0);
            if(w<=0) break;
            sent+=(size_t)w;
        }
        close(cfd);
    }
}

bool start_peer_server(){
    if(peer_listen_fd>0) return true;
    int s=socket(AF_INET,SOCK_STREAM,0);
    if(s<0) return false;
    int opt=1; 
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in addr; 
    memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET; 
    addr.sin_addr.s_addr=INADDR_ANY; 
    addr.sin_port=0;
    if(::bind(s,(sockaddr*)&addr,sizeof(addr))<0){ 
        close(s); 
        return false; 
    }
    if(listen(s,10)<0){ 
        close(s); 
        return false; 
    }
    sockaddr_in as; 
    socklen_t al=sizeof(as);
    if(getsockname(s,(sockaddr*)&as,&al)==0){
        peer_listen_port=ntohs(as.sin_port);
    }
    peer_listen_fd=s;
    peer_thread=thread(peer_server_thread);
    peer_thread.detach();
    return true;
}

int main(int argc,char *argv[]) {
    if(argc!=3) {
        cout<<"Usage: ./client ip:port tracker_info.txt\n";
        return 0;
    }
    string ip_port=argv[1];
    string file=argv[2];
    read_tracker_file(file);

    size_t pos=ip_port.find(":");
    if(pos==string::npos) {
        cout<<"Invalid ip:port\n";
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
            cout<<"Cannot connect to the tracker. Trying other available tracker\n";
            try_connect();
        } 
        else{
            cout<<"Connected to tracker "<<trackers[initial].ip<<":"<<trackers[initial].port<<"\n";
        }
    } 
    else{
        try_connect();
    }

    while(true){
        cout<<"> ";
        string cmd;
        getline(cin,cmd);
        if(cmd=="quit") {
            break;
        }
        if(cmd.size()==0) continue;

        // parse words
        stringstream ssin(cmd);
        vector<string> words; 
        string w;
        while(ssin>>w) words.push_back(w);
        if(words.size()==0) continue;
        if(words[0] == "create_user") {
            if(words.size() != 3) {
                cout << "ERR usage: create_user <uid> <pw>\n";
                continue;
            }

            string cmd = "create_user " + words[1] + " " + words[2];
            string reply;

            // send_with_failover handles tracker failover and session consistency
            if(!send_with_failover(cmd, reply)) {
                cout << "Tracker request failed\n";
                continue;
            }

            cout << reply << "\n";
            continue;
        }
        // If user tries to login via this client, intercept to capture session token
        else if(words[0] == "login") {
            if(words.size()!=3){
                cout<<"Usage: login <uid> <pw>\n";
                continue;
            }
            if(!cached_uid.empty()){
                cout<<"ERR already_logged_in_on_this_client\n";
                continue;
            }

            string reply;

            // <<< CHANGED: attempt failover for login itself
            if(sock<0) {
                if(!try_connect()) {
                    cout << "Tracker request failed\n";
                    continue;
                }
            }

            // <<< CHANGED: send login to tracker and retry if failover needed
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

            // parse first line
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

                        // <<< CHANGED: Ensure peer server is running so peer_listen_port is set
                        if(!start_peer_server()) {
                            cout << "Warning: could not start peer server for re-announce\n";
                        }

                        // <<< CHANGED: Proper re-announce only for files uploaded by this user
                        auto records = load_upload_records();
                        for(auto &rec : records) {
                            string uid, gid, filename, filepath;
                            tie(uid, gid, filename, filepath) = rec;

                            if(uid != cached_uid) continue;  // only re-announce files of logged-in user

                            if(access(filepath.c_str(), F_OK) != -1) {
                                // compute hashes and filesize
                                vector<string> piece_hashes;
                                string full_hash;
                                uint64_t filesize = 0;
                                if(!compute_file_hashes(filepath, piece_hashes, full_hash, filesize)) continue;

                                string localip = get_local_ip_from_socket(sock >= 0 ? sock : 0);
                                if(!start_peer_server()) localip = "0.0.0.0";

                                stringstream out;
                                out << "upload_file " << gid << " " << filename << " "
                                    << filesize << " " << localip << " " << peer_listen_port << " "
                                    << full_hash << " " << piece_hashes.size();
                                for(auto &ph : piece_hashes) out << " " << ph;
                                string dummy;
                                if(!send_with_failover(out.str(),dummy))
                                    cout << "[Auto-Reannounce] " << filename << " -> failed\n";
                                else
                                    cout << "[Auto-Reannounce] " << filename << " -> success\n";
                            }
                        }

                        continue;
                    }
                }
                // other OK responses
                cout << firstline << "\n";
                continue;
            } 
            else{
                cout << firstline << "\n";
                continue;
            }
        }
        else if(words[0] == "create_group") {
            if(words.size() != 2) { cout << "Usage: create_group <group_id>\n"; continue; }
            if(cached_uid.empty() || cached_session.empty()) { cout << "ERR you should login first\n"; continue; }

            string cmdline = "create_group " + words[1];
            string reply;
            if(!send_with_failover(cmdline, reply)) { cout << "Tracker request failed\n"; continue; }

            cout << reply << "\n";
            continue;
        }
        else if(words[0] == "join_group") {
            if(words.size() != 2) { cout << "Usage: join_group <group_id>\n"; continue; }
            if(cached_uid.empty() || cached_session.empty()) { cout << "ERR you should login first\n"; continue; }

            string cmdline = "join_group " + words[1];
            string reply;
            if(!send_with_failover(cmdline, reply)) { cout << "Tracker request failed\n"; continue; }

            cout << reply << "\n";
            continue;
        }
        else if(words[0] == "leave_group") {
            if(words.size() != 2) { cout << "Usage: leave_group <group_id>\n"; continue; }
            if(cached_uid.empty() || cached_session.empty()) { cout << "ERR you should login first\n"; continue; }

            string cmdline = "leave_group " + words[1];
            string reply;
            if(!send_with_failover(cmdline, reply)) { cout << "Tracker request failed\n"; continue; }

            cout << reply << "\n";
            continue;
        }

        else if(words[0] == "list_groups") {
            if(words.size() != 1) { cout << "Usage: list_groups\n"; continue; }
            if(cached_uid.empty() || cached_session.empty()) { cout << "ERR you should login first\n"; continue; }

            string reply;
            if(!send_with_failover("list_groups", reply)) { cout << "Tracker request failed\n"; continue; }

            cout << reply << "\n";
            continue;
        }
        else if(words[0] == "list_requests") {
            if(words.size() != 2) { cout << "Usage: list_requests <group_id>\n"; continue; }
            if(cached_uid.empty() || cached_session.empty()) { cout << "ERR you should login first\n"; continue; }

            string cmdline = "list_requests " + words[1];
            string reply;
            if(!send_with_failover(cmdline, reply)) { cout << "Tracker request failed\n"; continue; }

            cout << reply << "\n";
            continue;
        }

        else if(words[0] == "accept_request") {
            if(words.size() != 3) { cout << "Usage: accept_request <group_id> <user_id>\n"; continue; }
            if(cached_uid.empty() || cached_session.empty()) { cout << "ERR you should login first\n"; continue; }

            string cmdline = "accept_request " + words[1] + " " + words[2];
            string reply;
            if(!send_with_failover(cmdline, reply)) { cout << "Tracker request failed\n"; continue; }

            cout << reply << "\n";
            continue;
        }
        // Intercept logout to clear cached session on success
        else if(words[0] == "logout") {
            string reply;
            if(!send_with_failover(cmd,reply)){
                cout<<"Tracker request failed\n";
                continue;
            }
            size_t posn = reply.find('\n');
            string firstline = (posn==string::npos)?reply:reply.substr(0,posn);
            if(firstline.rfind("OK",0) == 0) {
                // successful logout: clear cached session if it matches
                cached_uid.clear();
                cached_session.clear();
            }
            cout << firstline << "\n";
            continue;
        }

        // dispatch certain commands client-side
        else if(words[0] == "upload_file") {
            // Expected: upload_file <gid> <file_path_or_name>
            if(words.size() != 3) {
                cout << "ERR usage: upload_file <gid> <file_path>\n";
                continue;
            }

            string gid = words[1];
            string filepath = words[2];

            // --- Compute hashes and file size ---
            vector<string> piece_hashes;
            string full_hash;
            uint64_t filesize = 0;
            if(!compute_file_hashes(filepath, piece_hashes, full_hash, filesize)) {
                cout << "ERR cannot_open_file\n";
                continue;
            }

            // --- Extract filename only ---
            string filename;
            size_t pos = filepath.find_last_of("/\\");
            if(pos != string::npos) filename = filepath.substr(pos + 1);
            else filename = filepath;  // just name

            // --- Ensure peer server is running ---
            if(!start_peer_server()) {
                cout << "ERR cannot_start_peer_server\n";
                continue;
            }

            string localip = get_local_ip_from_socket(sock >= 0 ? sock : 0);

            // --- Prepare full command to tracker ---
            stringstream out;
            out << "upload_file " << gid << " " << filename << " " 
                << filesize << " " << localip << " " << peer_listen_port << " " 
                << full_hash << " " << piece_hashes.size();

            for(auto &ph : piece_hashes) out << " " << ph;

            // --- Send with automatic failover ---
            string upr;
            if(!send_with_failover(out.str(),upr)) {
                cout << "ERR upload_failed\n";
            }
            else {
                string firstline;
                size_t ppos = upr.find('\n');
                firstline = (ppos==string::npos) ? upr : upr.substr(0, ppos);
                if(firstline.rfind("OK",0) == 0) {
                    cout << "Upload registered\n";
                    save_upload_record(cached_uid,gid,filename,filepath);
                } else {
                    cout << firstline << "\n";
                }
            }
            continue;
        }
        else if(words[0]=="list_files"){
            if(words.size()!=2){
                cout<<"Usage: list_files <gid>\n";
                continue;
            }
            string lrep;
            send_with_failover(cmd,lrep);
            cout<<lrep<<endl;
            continue;
        }
        else if(words[0] == "download_file") {
            if(words.size() != 4) {
                cout << "ERR usage: download_file <gid> <filename> <destination_folder>\n";
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
                cout << "ERR cannot_create_folder\n";
                continue;
            }

            string fullpath = dest_folder + filename;

            // Request file info from tracker
            string ask = "download_file " + gid + " " + filename;
            string reply;
            if(!send_with_failover(ask,reply)) {
                cout << "Tracker request failed\n";
                if(!try_connect() || !send_command(ask, reply)) {
                    cout << "All trackers unavailable\n";
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
            if(num_seeders <= 0) { cout << "No seeders\n"; continue; }
            vector<string> seeders(num_seeders);
            for(int i=0;i<num_seeders;i++) ls >> seeders[i];

            // Initialize download status
            DownloadStatus ds;
            ds.gid = gid;
            ds.filename = fullpath;
            ds.filesize = filesize;
            ds.num_pieces = num_pieces;
            ds.have.assign(num_pieces, 0);
            ds.completed = false;
            string dkey = gid + ":" + filename;
            {
                lock_guard<mutex> lg(downloads_mutex);
                downloads[dkey] = ds;
            }

            int fd = open(fullpath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if(fd < 0) {
                cout << "Cannot create file\n";
                lock_guard<mutex> lg(downloads_mutex);
                downloads.erase(dkey);
                continue;
            }

            const int MAX_RETRIES = 5;
            const int MAX_THREADS = 8; // parallel threads

            atomic<int> pieces_done(0);
            mutex fd_mutex;

            auto download_piece = [&](int pi) -> bool {
                size_t expected_size = PIECE_SIZE;
                if ((off_t)pi * PIECE_SIZE + PIECE_SIZE > filesize)
                    expected_size = filesize - (off_t)pi * PIECE_SIZE;

                for(int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
                    for(const string &seeder : seeders) {
                        size_t ppos = seeder.find(':');
                        string sip = seeder.substr(0, ppos);
                        int sport = atoi(seeder.substr(ppos+1).c_str());

                        int psock = socket(AF_INET, SOCK_STREAM, 0);
                        if(psock < 0) continue;

                        sockaddr_in peeraddr;
                        memset(&peeraddr,0,sizeof(peeraddr));
                        peeraddr.sin_family = AF_INET;
                        peeraddr.sin_port = htons(sport);
                        peeraddr.sin_addr.s_addr = inet_addr(sip.c_str());

                        struct timeval tv; tv.tv_sec=10; tv.tv_usec=0;
                        setsockopt(psock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

                        if(connect(psock,(sockaddr*)&peeraddr,sizeof(peeraddr))<0){
                            close(psock);
                            continue;
                        }

                        string req = "GET_PIECE " + filename + " " + to_string(pi) + "\n";
                        if(send(psock, req.c_str(), req.size(), 0) <= 0){
                            close(psock);
                            continue;
                        }

                        vector<char> pbuf(expected_size);
                        ssize_t total_rcv = 0;
                        while(total_rcv < expected_size){
                            ssize_t rcv = recv(psock, pbuf.data() + total_rcv, expected_size - total_rcv, 0);
                            if(rcv <= 0) break;
                            total_rcv += rcv;
                        }
                        close(psock);

                        if((size_t)total_rcv != expected_size) continue;
                        if(sha1_hex((unsigned char*)pbuf.data(), pbuf.size()) != piece_hashes[pi]) continue;

                        {
                            lock_guard<mutex> lg(fd_mutex);
                            off_t off = (off_t)pi * PIECE_SIZE;
                            if(lseek(fd, off, SEEK_SET) == (off_t)-1) return false;
                            size_t wrote = 0;
                            while(wrote < pbuf.size()){
                                ssize_t w = write(fd, pbuf.data() + wrote, pbuf.size() - wrote);
                                if(w <=0) break;
                                wrote += w;
                            }
                        }

                        {
                            lock_guard<mutex> lg(downloads_mutex);
                            downloads[dkey].have[pi] = pbuf.size();
                        }

                        int done = ++pieces_done;
                        double perc = (double)done / num_pieces * 100.0;
                        cout << "Piece " << pi+1 << "/" << num_pieces << " downloaded (" << (int)perc << "%)\n";
                        return true;
                    }
                    this_thread::sleep_for(chrono::milliseconds(300));
                }
                cout << "Piece " << pi+1 << " failed after max retries\n";
                return false;
            };

            vector<thread> workers;
            atomic<int> next_piece(0);
            auto worker = [&]() {
                while(true) {
                    int pi = next_piece++;
                    if(pi >= num_pieces) break;
                    download_piece(pi);
                }
            };

            for(int i=0;i<min(MAX_THREADS,num_pieces);i++) workers.emplace_back(worker);
            for(auto &t : workers) t.join();

            close(fd);

            vector<string> ph_dummy;
            string fullh;
            uint64_t fs2;
            if(!compute_file_hashes(fullpath, ph_dummy, fullh, fs2)){
                cout << "Downloaded but cannot compute final hash\n";
            } else if(fullh == filehash){
                cout << "Download completed and verified\n";
                lock_guard<mutex> lg(downloads_mutex);
                downloads[dkey].completed = true;
            } else {
                cout << "Final file hash mismatch\n";
            }

            continue;
        }

        else if(words[0]=="show_downloads"){
            lock_guard<mutex> lg(downloads_mutex);
            if(downloads.empty()){
                cout<<"No downloads\n";
            } 
            else{
                for(auto &p:downloads){
                    const DownloadStatus &ds=p.second;
                    size_t got=0;
                    for(size_t x:ds.have) got+=x;
                    cout<<"["<<(ds.completed?'C':'D')<<"] ["<<ds.gid<<"] "<<ds.filename<<" "<<got<<"/"<<ds.filesize<<"\n";
                }
            }
            continue;
        }

        else if(words[0]=="stop_share"){
            if(words.size()!=3){
                cout<<"Invalid commands\n";
                continue;
            }
            if(peer_listen_port==0){
                cout<<"Not sharing\n"; continue;
            }
            string gid=words[1],filename=words[2];
            string localip=get_local_ip_from_socket(sock>=0?sock:0);
            string cmdline="Stop_share "+gid+" "+filename+" "+localip+" "+to_string(peer_listen_port);
            string tmp1;
            send_with_failover(cmdline,tmp1);
            continue;
        }
        else{
            cout<<"Invalid command"<<endl;
            continue;
        }
        // default: send raw to tracker (send_with_failover will apply session wrapper)
        string tmp;
        send_with_failover(cmd,tmp);
    }
    if(sock>=0) close(sock);
    return 0;
}
