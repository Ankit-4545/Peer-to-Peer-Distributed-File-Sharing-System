#ifndef PEER_H
#define PEER_H

// BitTorrent-style peer engine.
//
// Every file being shared or downloaded is a "torrent" identified by its full
// SHA-1 hash (the info-hash). Peers keep one long-lived TCP connection per
// torrent and talk a length-prefixed message protocol over it:
//
//   handshake : <pstrlen=14>"P2PFS protocol"<8 reserved><20 info_hash><20 peer_id>
//   message   : <4-byte big-endian length><1-byte id><payload>   (length 0 = keep-alive)
//   ids       : 0 choke, 1 unchoke, 2 interested, 3 not_interested, 4 have,
//               5 bitfield, 6 request, 7 piece, 8 cancel
//
// Pieces (PIECE_SIZE) are fetched as 16 KB blocks with several requests in
// flight per peer, chosen rarest-first, verified by SHA-1, and announced to
// all peers with `have`. Uploads are rationed by choke/unchoke (tit-for-tat
// plus one optimistic unchoke), and the last blocks are fetched in endgame mode.

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace p2p {

// Hooks into the tracker connection, set by client.cpp before use.
// tracker_request sends one tracker command and returns its reply.
extern std::function<bool(const std::string &cmd, std::string &reply)> tracker_request;
// announce_ip returns the IP address this client announces to the tracker.
extern std::function<std::string()> announce_ip;
// Called once a download has finished and the full-file hash has been verified.
extern std::function<void(const std::string &gid, const std::string &filename,
                          const std::string &path)> on_download_complete;

// Starts the peer listener and the background maintenance thread (idempotent).
bool start_engine();
int listen_port();

// Serves a complete local file to other peers.
bool seed_file(const std::string &gid, const std::string &filename, const std::string &path,
               uint64_t filesize, const std::string &filehash,
               const std::vector<std::string> &piece_hashes);

// Starts or resumes a background download into dest_path. Returns false if the
// download could not be started; message says what happened either way.
bool start_download(const std::string &gid, const std::string &filename,
                    const std::string &dest_path, uint64_t filesize,
                    const std::string &filehash, const std::vector<std::string> &piece_hashes,
                    const std::vector<std::string> &peers, std::string &message);

// Stops serving (and downloading) gid/filename. Returns true if it was active.
bool stop_share(const std::string &gid, const std::string &filename);

void print_downloads();

}

#endif
