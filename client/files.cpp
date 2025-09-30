#include "files.h"
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// ---------- minimal SHA1 implementation ----------
#include <stdint.h>
typedef uint32_t u32;
typedef uint8_t u8;

struct SHA1_CTX {
    u32 state[5];
    u32 count[2];
    u8 buffer[64];
};

static void SHA1Transform(u32 state[5], const u8 buffer[64]);

static void SHA1Init(SHA1_CTX* context){
    context->state[0]=0x67452301;
    context->state[1]=0xEFCDAB89;
    context->state[2]=0x98BADCFE;
    context->state[3]=0x10325476;
    context->state[4]=0xC3D2E1F0;
    context->count[0]=context->count[1]=0;
    memset(context->buffer,0,64);
}

static void SHA1Update(SHA1_CTX* context,const u8* data,size_t len){
    size_t i=0;
    u32 j=(context->count[0]>>3)&63;
    u32 bits=(u32)(len<<3);
    context->count[0]+=bits;
    if(context->count[0]<bits) context->count[1]++;
    context->count[1]+=(u32)(len>>29);
    size_t partLen=64-j;
    if(len>=partLen){
        memcpy(&context->buffer[j],data,partLen);
        SHA1Transform(context->state,context->buffer);
        for(i=partLen;i+63<len;i+=64){
            SHA1Transform(context->state,&data[i]);
        }
        j=0;
    } else i=0;
    if(i<len) memcpy(&context->buffer[j],&data[i],len-i);
}

static void SHA1Final(u8 digest[20],SHA1_CTX* context){
    u8 finalcount[8];
    for(int i=0;i<8;i++){
        finalcount[i]=(u8)((context->count[(i>=4)?0:1]>>((3-(i&3))*8))&255);
    }
    u8 c=0x80;
    SHA1Update(context,&c,1);
    while(((context->count[0]>>3)&63)!=56){
        c=0x00;
        SHA1Update(context,&c,1);
    }
    SHA1Update(context,finalcount,8);
    for(int i=0;i<20;i++){
        digest[i]=(u8)((context->state[i>>2]>>((3-(i&3))*8))&255);
    }
    memset(context,0,sizeof(*context));
    memset(&finalcount,0,sizeof(finalcount));
}

#define ROL(value, bits) (((value) << (bits)) | ((value) >> (32-(bits))))

static void SHA1Transform(u32 state[5], const u8 buffer[64]){
    u32 a,b,c,d,e,t;
    u32 w[80];
    for(int i=0;i<16;i++){
        w[i]=(u32)buffer[4*i]<<24;
        w[i]|=(u32)buffer[4*i+1]<<16;
        w[i]|=(u32)buffer[4*i+2]<<8;
        w[i]|=(u32)buffer[4*i+3];
    }
    for(int i=16;i<80;i++){
        w[i]=ROL((w[i-3]^w[i-8]^w[i-14]^w[i-16]),1);
    }
    a=state[0];b=state[1];c=state[2];d=state[3];e=state[4];
    for(int i=0;i<80;i++){
        if(i<20) t=ROL(a,5)+((b&c)|((~b)&d))+e+w[i]+0x5A827999;
        else if(i<40) t=ROL(a,5)+(b^c^d)+e+w[i]+0x6ED9EBA1;
        else if(i<60) t=ROL(a,5)+((b&c)|(b&d)|(c&d))+e+w[i]+0x8F1BBCDC;
        else t=ROL(a,5)+(b^c^d)+e+w[i]+0xCA62C1D6;
        e=d;d=c;c=ROL(b,30);b=a;a=t;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;state[4]+=e;
    for(int i=0;i<80;i++) w[i]=0;
}

std::string sha1_hex(const unsigned char *data,size_t len){
    SHA1_CTX ctx;
    SHA1Init(&ctx);
    SHA1Update(&ctx,data,len);
    unsigned char digest[20];
    SHA1Final(digest,&ctx);
    std::ostringstream oss;
    oss<<std::hex<<std::setfill('0');
    for(int i=0;i<20;i++){
        oss<<std::setw(2)<<((int)digest[i]&0xff);
    }
    return oss.str();
}

std::string sha1_hex(const std::string &s){
    return sha1_hex((const unsigned char*)s.data(),s.size());
}

bool compute_file_hashes(const std::string &path,std::vector<std::string> &piece_hashes,std::string &full_hash,uint64_t &filesize){
    piece_hashes.clear();
    full_hash.clear();
    filesize=0;
    int fd=open(path.c_str(),O_RDONLY);
    if(fd<0) return false;
    struct stat st;
    if(fstat(fd,&st)<0){
        close(fd);return false;
    }
    filesize=(uint64_t)st.st_size;
    size_t bufsize=PIECE_SIZE;
    std::vector<char> buf(bufsize);
    ssize_t r;
    SHA1_CTX ctx;
    SHA1Init(&ctx);
    while((r=read(fd,buf.data(),(size_t)bufsize))>0){
        std::string ph=sha1_hex((const unsigned char*)buf.data(),(size_t)r);
        piece_hashes.push_back(ph);
        SHA1Update(&ctx,(const unsigned char*)buf.data(),(size_t)r);
    }
    unsigned char digest[20];
    SHA1Final(digest,&ctx);
    std::ostringstream oss;
    oss<<std::hex<<std::setfill('0');
    for(int i=0;i<20;i++){
        oss<<std::setw(2)<<((int)digest[i]&0xff);
    }
    full_hash=oss.str();
    close(fd);
    return true;
}

ssize_t read_piece_from_file(const std::string &path,size_t piece_index,char *buf,size_t bufsize){
    int fd=open(path.c_str(),O_RDONLY);
    if(fd<0) return -1;
    off_t offset=(off_t)piece_index*(off_t)PIECE_SIZE;
    if(lseek(fd,offset,SEEK_SET)==(off_t)-1){
        close(fd);return -1;
    }
    ssize_t r=read(fd,buf,bufsize);
    close(fd);
    return r;
}

std::string join_piece_hashes(const std::vector<std::string> &v){
    std::string out;
    for(size_t i=0;i<v.size();i++){
        if(i) out.push_back(',');
        out+=v[i];
    }
    return out;
}

std::vector<std::string> split_piece_hashes(const std::string &s){
    std::vector<std::string> out;
    std::string cur;
    for(char c:s){
        if(c==','){
            out.push_back(cur);
            cur.clear();
        } else cur.push_back(c);
    }
    if(!cur.empty()) out.push_back(cur);
    return out;
}
