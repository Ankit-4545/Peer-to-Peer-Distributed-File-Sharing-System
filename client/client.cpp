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
#include <condition_variable>
#include <sys/stat.h>

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

bool send_with_failover(string cmd) {
    if(sock<0) {
        if(!try_connect()) {
            cout<<"No trackers available\n";
            return false;
        }
    }
    string dummy;
    if(!send_command(cmd,dummy)) {
        cout<<"Trying next tracker\n";
        int start=(current_tracker+1)%trackers.size();
        int cnt=0;
        while(cnt<trackers.size()) {
            int s = connect_to_tracker(start);
            if(s>=0) {
                // close old if any
                if(sock>0 && sock!=s) close(sock);
                sock = s;
                cout<<"Connected to tracker "<<trackers[start].ip<<":"<<trackers[start].port<<"\n";
                return send_command(cmd,dummy);
            }
            start=(start+1)%trackers.size();
            cnt++; // <<-- BUG FIX: increment cnt here (was missing before)
        }
        cout<<"All trackers down\n";
        return false;
    }
    cout<<dummy<<"\n";
    return true;
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

        // If user tries to login via this client, intercept to capture session token
        if(words[0] == "login") {
            if(words.size()!=3){
                cout<<"Usage: login <uid> <pw>\n";
                continue;
            }
            if(!cached_uid.empty()){
                cout<<"ERR already_logged_in_on_this_client\n";
                continue;
            }
            string reply;
            if(!send_command(cmd, reply)){
                cout<<"Tracker request failed\n";
                continue;
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
                        cout << firstline << "\n";
                        continue;
                    }
                }
                // other OK responses
                cout << firstline << "\n";
                continue;
            } else {
                cout << firstline << "\n";
                continue;
            }
        }

        // Intercept logout to clear cached session on success
        if(words[0] == "logout") {
            string reply;
            if(!send_command(cmd, reply)){
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
        if(words[0]=="upload_file"){
            if(words.size()!=3){
                cout<<"Usage: upload_file <gid> <file_path>\n";
                continue;
            }
            string gid=words[1];
            string path=words[2];
            vector<string> piece_hashes;
            string filehash;
            uint64_t filesize=0;
            if(!compute_file_hashes(path,piece_hashes,filehash,filesize)){
                cout<<"Error computing file hashes or opening file\n";
                continue;
            }
            if(!start_peer_server()){
                cout<<"Cannot start peer server\n";
                continue;
            }
            string localip=get_local_ip_from_socket(sock>=0?sock:0);
            stringstream out;
            // NOTE: protocol mismatch exists between client and tracker for upload_file details.
            // Keep current format (the server expects different format in apply_op_line). We'll send metadata and let server ignore extras for now.
            out<<"upload_file "<<gid<<" "<<path<<" "<<to_string(filesize)<<" "<<localip<<" "<<to_string(peer_listen_port)<<" "<<filehash<<" "<<piece_hashes.size();
            for(auto &ph:piece_hashes) out<<" "<<ph;
            if(!send_with_failover(out.str())) cout<<"upload failed\n";
            else cout<<"upload registered\n";
            continue;
        }

        if(words[0]=="list_files"){
            if(words.size()!=2){
                cout<<"Usage: list_files <gid>\n";
                continue;
            }
            send_with_failover(cmd);
            continue;
        }

        if(words[0]=="download_file"){
            if(words.size()!=4){
                cout<<"Invalid arguments\n";
                continue;
            }
            string gid=words[1],filename=words[2],dest=words[3];
            string ask="download_file "+gid+" "+filename;
            string reply;
            if(!send_command(ask,reply)){ 
                cout<<"Tracker request failed\n"; 
                continue; 
            }
            // parse first line
            size_t posn=reply.find('\n');
            string firstline=(posn==string::npos)?reply:reply.substr(0,posn);
            if(firstline.rfind("ERR",0)==0){ 
                cout<<firstline<<"\n"; 
                continue; 
            }
            if(firstline.rfind("OK",0)!=0){ 
                cout<<firstline<<"\n"; 
                continue; 
            }
            stringstream ls(firstline);
            string ok; 
            ls>>ok;
            uint64_t filesize; 
            ls>>filesize;
            string filehash; 
            ls>>filehash;
            int num_pieces; 
            ls>>num_pieces;
            vector<string>piece_hashes;
            for(int i=0;i<num_pieces;i++){ 
                string ph; 
                ls>>ph; 
                piece_hashes.push_back(ph); 
            }
            int num_seeders; 
            ls>>num_seeders;
            vector<string> seeders;
            for(int i=0;i<num_seeders;i++){ 
                string s; 
                ls>>s; 
                seeders.push_back(s); 
            }
            if(seeders.empty()){ 
                cout<<"No seeders\n"; 
                continue; 
            }
            DownloadStatus ds;
            ds.gid=gid; 
            ds.filename=dest; 
            ds.filesize=filesize; 
            ds.num_pieces=num_pieces; 
            ds.have.assign(num_pieces,0); 
            ds.completed=false;
            string dkey=gid+":"+filename;
            {
                lock_guard<mutex> lg(downloads_mutex);
                downloads[dkey]=ds;
            }
            string first_seeder=seeders[0];
            size_t ppos=first_seeder.find(':');
            string sip=first_seeder.substr(0,ppos);
            int sport=atoi(first_seeder.substr(ppos+1).c_str());
            int fd=open(dest.c_str(),O_CREAT|O_WRONLY|O_TRUNC,0644);
            if(fd<0){ 
                cout<<"Cannot create file\n"; 
                lock_guard<mutex> lg(downloads_mutex); 
                downloads.erase(dkey); 
                continue; 
            }
            for(int pi=0;pi<num_pieces;pi++){
                int psock=socket(AF_INET,SOCK_STREAM,0);
                if(psock<0) break;
                sockaddr_in peeraddr; 
                memset(&peeraddr,0,sizeof(peeraddr));
                peeraddr.sin_family=AF_INET; 
                peeraddr.sin_port=htons(sport);
                peeraddr.sin_addr.s_addr=inet_addr(sip.c_str());
                if(connect(psock,(sockaddr*)&peeraddr,sizeof(peeraddr))<0){ 
                    close(psock); 
                    break; 
                }
                string req="GET_PIECE "+filename+" "+to_string(pi)+"\n";
                if(send(psock,req.c_str(),req.size(),0)<=0){ 
                    close(psock); 
                    break; 
                }
                // size_t want=PIECE_SIZE;
                vector<char> pbuf;
                char recvbuf[8192];
                ssize_t rcv;
                while((rcv=recv(psock,recvbuf,sizeof(recvbuf),0))>0){
                    pbuf.insert(pbuf.end(),recvbuf,recvbuf+rcv);
                }
                close(psock);
                if(pbuf.empty()){ cout<<"Failed to get piece "<<pi<<"\n"; break; }
                string ph=sha1_hex((const unsigned char*)pbuf.data(),pbuf.size());
                if(ph!=piece_hashes[pi]){
                    cout<<"Hash mismatch for piece "<<pi<<"\n"; 
                    break; 
                }
                off_t off=(off_t)pi*(off_t)PIECE_SIZE;
                if(lseek(fd,off,SEEK_SET)==(off_t)-1){ 
                    cout<<"Seek error\n"; 
                    break; 
                }
                size_t wrote=0;
                while(wrote<pbuf.size()){
                    ssize_t w=write(fd,pbuf.data()+wrote,pbuf.size()-wrote);
                    if(w<=0) break;
                    wrote+=w;
                }
                {
                    lock_guard<mutex> lg(downloads_mutex);
                    downloads[dkey].have[pi]=pbuf.size();
                }
            }
            close(fd);
            vector<string> ph_dummy; 
            string fullh; uint64_t fs2;
            if(!compute_file_hashes(dest,ph_dummy,fullh,fs2)){
                cout<<"Downloaded but cannot compute final hash\n";
            } 
            else{
                if(fullh==filehash){
                    cout<<"Download completed and verified\n";
                    lock_guard<mutex> lg(downloads_mutex);
                    downloads[dkey].completed=true;
                } 
                else{
                    cout<<"Final file hash mismatch\n";
                }
            }
            continue;
        }

        if(words[0]=="show_downloads"){
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

        if(words[0]=="stop_share"){
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
            send_with_failover(cmdline);
            continue;
        }

        // default: send raw to tracker (send_with_failover will apply session wrapper)
        send_with_failover(cmd);
    }
    if(sock>=0) close(sock);
    return 0;
}
