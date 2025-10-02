#ifndef FILES_H
#define FILES_H

#include <string>
#include <vector>
#include <cstdint>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
using namespace std;

static const size_t PIECE_SIZE = 512*1024; 

struct FileMeta {
    string filename;
    uint64_t filesize;
    string filehash;
    vector<string> piece_hashes;
    vector<string> seeders;
};

string sha1_hex(const unsigned char *data,size_t len);
string sha1_hex(const string &s);
bool compute_file_hashes(const string &path, vector<string> &piece_hashes, string &full_hash, uint64_t &filesize);
ssize_t read_piece_from_file(const string &path,size_t piece_index,char *buf,size_t bufsize);
string join_piece_hashes(const vector<string> &v);
vector<string> split_piece_hashes(const string &s);

#endif 
