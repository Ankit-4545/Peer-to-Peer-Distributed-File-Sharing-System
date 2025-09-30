#ifndef FILES_H
#define FILES_H

#include <string>
#include <vector>
#include <cstdint>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static const size_t PIECE_SIZE = 512*1024; // 512KB

struct FileMeta {
    std::string filename;
    uint64_t filesize;
    std::string filehash;
    std::vector<std::string> piece_hashes;
    std::vector<std::string> seeders;
};

std::string sha1_hex(const unsigned char *data,size_t len);
std::string sha1_hex(const std::string &s);
bool compute_file_hashes(const std::string &path, std::vector<std::string> &piece_hashes, std::string &full_hash, uint64_t &filesize);
ssize_t read_piece_from_file(const std::string &path,size_t piece_index,char *buf,size_t bufsize);
std::string join_piece_hashes(const std::vector<std::string> &v);
std::vector<std::string> split_piece_hashes(const std::string &s);

#endif // FILES_H
