#include "peer.h"
#include "files.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <memory>
#include <random>
#include <algorithm>
#include <chrono>
#include <climits>
#include <cstring>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

namespace p2p {

function<bool(const string &, string &)> tracker_request;
function<string()> announce_ip;
function<void(const string &, const string &, const string &)> on_download_complete;

typedef chrono::steady_clock Clock;

static const string PSTR = "P2PFS protocol";
static const uint32_t BLOCK_SIZE = 16 * 1024;        // unit of a request, as in BitTorrent
static const uint32_t MAX_REQUEST_LEN = 128 * 1024;  // largest block we agree to serve
static const uint32_t MAX_MSG_LEN = 2 * 1024 * 1024;
static const size_t PIPELINE_DEPTH = 8;              // outstanding requests per peer
static const size_t MAX_QUEUED_UPLOADS = 64;         // pending requests we accept per peer
static const size_t MAX_PEERS = 30;                  // connections per torrent
static const int REGULAR_UNCHOKES = 3;               // + 1 optimistic unchoke
static const int CHOKE_INTERVAL = 10;                // seconds
static const int OPTIMISTIC_INTERVAL = 30;           // seconds
static const int ANNOUNCE_INTERVAL = 30;             // seconds between tracker peer queries
static const int REQUEST_TIMEOUT = 30;               // seconds before a request is re-issued
static const int DIAL_BACKOFF = 30;                  // seconds before re-dialing a failed peer
static const int HANDSHAKE_TIMEOUT = 10;
static const int IDLE_TIMEOUT = 150;                 // no traffic at all -> drop the peer
static const int KEEPALIVE_INTERVAL = 60;
static const int MAX_ENDGAME_DUPLICATES = 3;         // peers asked for the same block in endgame
static const int RANDOM_FIRST_PIECES = 4;            // pick the first pieces at random

enum MsgId : uint8_t {
    MSG_CHOKE = 0, MSG_UNCHOKE = 1, MSG_INTERESTED = 2, MSG_NOT_INTERESTED = 3,
    MSG_HAVE = 4, MSG_BITFIELD = 5, MSG_REQUEST = 6, MSG_PIECE = 7, MSG_CANCEL = 8
};

struct Torrent;

// One item in a connection's outgoing queue: either a ready message, or a
// request from the peer that the writer thread serves by reading from disk.
struct OutItem {
    bool serve = false;
    string data;
    uint32_t index = 0, begin = 0, length = 0;
};

struct PeerConn {
    int fd = -1;
    mutex fdmtx;
    string addr;             // dialed listen address, or remote address for incoming
    string peer_id;
    bool outgoing = false;
    shared_ptr<Torrent> t;

    // Guarded by t->mtx.
    bool am_choking = true, am_interested = false;
    bool peer_choking = true, peer_interested = false;
    vector<bool> peer_have;
    uint32_t peer_have_count = 0;
    map<pair<uint32_t, uint32_t>, Clock::time_point> inflight;  // (piece, begin) -> sent at
    uint64_t down_window = 0, up_window = 0;                     // bytes this choke round
    bool snubbed = false;

    // Outgoing queue, drained by the writer thread.
    mutex qmtx;
    condition_variable qcv;
    deque<OutItem> q;
    atomic<bool> dead{false};
    thread writer;
};

struct ActivePiece {
    vector<char> buf;
    vector<char> got;      // per block: received
    vector<int> reqs;      // per block: number of outstanding requests
    vector<string> from;   // per block: peer id that sent it
    uint32_t nblocks = 0, received = 0;
};

// A block of a piece that failed its hash check: who sent it and what it hashed to.
struct SuspectBlock {
    uint32_t block;
    string peer_id;
    string hash;
};

struct Torrent {
    // Immutable after registration.
    string info_hash;   // 20 raw bytes
    string filehash;    // hex
    string gid, filename;
    string final_path, part_path, state_path;
    uint64_t filesize = 0;
    uint32_t num_pieces = 0;
    vector<string> piece_hashes;
    bool is_download = false;
    int fd = -1;

    // Everything below is guarded by mtx.
    mutex mtx;
    set<pair<string, string>> names;   // (gid, filename) pairs sharing this content
    string data_path;
    vector<bool> have;
    uint32_t have_count = 0;
    vector<int> avail;                 // how many connected peers have each piece
    map<uint32_t, ActivePiece> active; // pieces being downloaded
    vector<shared_ptr<PeerConn>> peers;
    set<string> connecting;
    map<string, Clock::time_point> failed;
    shared_ptr<PeerConn> optimistic;
    bool complete = false, stopped = false, just_completed = false;
    bool announced = false, announcing = false, querying = false;
    int ticks = 0, next_announce_tick = 0;
    uint64_t downloaded = 0, uploaded = 0, rate_bytes = 0;
    double down_rate = 0;
    uint32_t hash_failures = 0;
    map<uint32_t, vector<SuspectBlock>> suspects;   // failed pieces awaiting a good copy
    set<string> banned_ids, banned_addrs;
    string error;

    ~Torrent() { if (fd >= 0) close(fd); }

    uint32_t piece_len(uint32_t i) const {
        uint64_t start = (uint64_t)i * PIECE_SIZE;
        return (uint32_t)min<uint64_t>(PIECE_SIZE, filesize - start);
    }
    uint32_t block_len(uint32_t i, uint32_t begin) const {
        return min<uint32_t>(BLOCK_SIZE, piece_len(i) - begin);
    }
};

static mutex g_mtx;                                   // guards the three below
static map<string, shared_ptr<Torrent>> g_torrents;   // by raw info-hash
static vector<shared_ptr<Torrent>> g_history;         // downloads started this session
static set<string> g_self_addrs;                      // addresses that turned out to be us
static string g_peer_id;
static int g_listen_fd = -1;
static int g_listen_port = 0;

// ---------- small helpers ----------

static mt19937 &rng() {
    static thread_local mt19937 g((unsigned)Clock::now().time_since_epoch().count() ^
                                  (unsigned)hash<thread::id>()(this_thread::get_id()));
    return g;
}

static void put_u32(string &s, uint32_t v) {
    s.push_back((char)(v >> 24)); s.push_back((char)(v >> 16));
    s.push_back((char)(v >> 8));  s.push_back((char)v);
}

static uint32_t get_u32(const char *p) {
    const unsigned char *u = (const unsigned char *)p;
    return ((uint32_t)u[0] << 24) | ((uint32_t)u[1] << 16) | ((uint32_t)u[2] << 8) | u[3];
}

static bool send_all(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t w = send(fd, p, n, 0);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w; n -= (size_t)w;
    }
    return true;
}
static bool send_all(int fd, const string &s) { return send_all(fd, s.data(), s.size()); }

static bool recv_all(int fd, char *p, size_t n) {
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        p += r; n -= (size_t)r;
    }
    return true;
}

static bool pwrite_all(int fd, const char *p, size_t n, off_t off) {
    while (n) {
        ssize_t w = pwrite(fd, p, n, off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w; n -= (size_t)w; off += w;
    }
    return true;
}

static bool pread_all(int fd, char *p, size_t n, off_t off) {
    while (n) {
        ssize_t r = pread(fd, p, n, off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        p += r; n -= (size_t)r; off += r;
    }
    return true;
}

static string hex_to_raw(const string &h) {
    if (h.size() != 40) return "";
    string out;
    for (size_t i = 0; i < 40; i += 2) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            char c = h[i + k];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return "";
            v = v * 16 + d;
        }
        out.push_back((char)v);
    }
    return out;
}

static string human_rate(double bps) {
    ostringstream o;
    o << fixed << setprecision(1);
    if (bps >= 1024 * 1024) o << bps / (1024 * 1024) << " MB/s";
    else o << bps / 1024 << " KB/s";
    return o.str();
}

static void tune_socket(int fd, int timeout_secs) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    timeval tv;
    tv.tv_sec = timeout_secs; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int connect_timeout(const string &addr, int secs) {
    size_t pos = addr.rfind(':');
    if (pos == string::npos) return -1;
    string ip = addr.substr(0, pos);
    int port = atoi(addr.c_str() + pos + 1);
    if (port <= 0 || port > 65535) return -1;
    sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    if (connect(fd, (sockaddr *)&sa, sizeof(sa)) < 0) {
        if (errno != EINPROGRESS) { close(fd); return -1; }
        pollfd pfd;
        pfd.fd = fd; pfd.events = POLLOUT; pfd.revents = 0;
        if (poll(&pfd, 1, secs * 1000) <= 0) { close(fd); return -1; }
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) { close(fd); return -1; }
    }
    fcntl(fd, F_SETFL, fl);
    return fd;
}

// ---------- wire messages ----------

static string make_msg(uint8_t id, const string &payload = string()) {
    string m;
    put_u32(m, (uint32_t)(1 + payload.size()));
    m.push_back((char)id);
    m += payload;
    return m;
}

static string msg_have(uint32_t i) {
    string p;
    put_u32(p, i);
    return make_msg(MSG_HAVE, p);
}

static string msg_triple(uint8_t id, uint32_t i, uint32_t b, uint32_t l) {
    string p;
    put_u32(p, i); put_u32(p, b); put_u32(p, l);
    return make_msg(id, p);
}

static string msg_bitfield(const vector<bool> &have) {
    string p((have.size() + 7) / 8, '\0');
    for (size_t i = 0; i < have.size(); i++)
        if (have[i]) p[i / 8] = (char)(p[i / 8] | (0x80 >> (i % 8)));
    return make_msg(MSG_BITFIELD, p);
}

static string make_handshake(const string &info_hash) {
    string h;
    h.push_back((char)PSTR.size());
    h += PSTR;
    h.append(8, '\0');
    h += info_hash;
    h += g_peer_id;
    return h;
}

static bool read_handshake(int fd, string &info_hash, string &peer_id) {
    char l;
    if (!recv_all(fd, &l, 1) || (unsigned char)l != PSTR.size()) return false;
    string rest(PSTR.size() + 8 + 20 + 20, '\0');
    if (!recv_all(fd, &rest[0], rest.size())) return false;
    if (rest.compare(0, PSTR.size(), PSTR) != 0) return false;
    info_hash = rest.substr(PSTR.size() + 8, 20);
    peer_id = rest.substr(PSTR.size() + 28, 20);
    return true;
}

// ---------- connection queue (callable with t->mtx held; qmtx is a leaf lock) ----------

static void enqueue(const shared_ptr<PeerConn> &c, OutItem it) {
    {
        lock_guard<mutex> lk(c->qmtx);
        if (c->dead) return;
        c->q.push_back(std::move(it));
    }
    c->qcv.notify_one();
}

static void send_msg(const shared_ptr<PeerConn> &c, const string &m) {
    OutItem it;
    it.data = m;
    enqueue(c, std::move(it));
}

static void kill_conn(const shared_ptr<PeerConn> &c) {
    {
        lock_guard<mutex> lk(c->qmtx);
        c->dead = true;
    }
    c->qcv.notify_all();
    lock_guard<mutex> lk(c->fdmtx);
    if (c->fd >= 0) shutdown(c->fd, SHUT_RDWR);
}

static void drop_serve_jobs(const shared_ptr<PeerConn> &c) {
    lock_guard<mutex> lk(c->qmtx);
    deque<OutItem> keep;
    for (auto &it : c->q) if (!it.serve) keep.push_back(std::move(it));
    c->q.swap(keep);
}

// ---------- download logic (all called with t.mtx held) ----------

static void release_requests(Torrent &t, PeerConn &c) {
    for (auto &kv : c.inflight) {
        auto a = t.active.find(kv.first.first);
        if (a == t.active.end()) continue;
        uint32_t b = kv.first.second / BLOCK_SIZE;
        if (b < a->second.reqs.size() && a->second.reqs[b] > 0) a->second.reqs[b]--;
    }
    c.inflight.clear();
}

static void activate_piece(Torrent &t, uint32_t pi) {
    ActivePiece &ap = t.active[pi];
    uint32_t plen = t.piece_len(pi);
    ap.nblocks = (plen + BLOCK_SIZE - 1) / BLOCK_SIZE;
    ap.buf.assign(plen, 0);
    ap.got.assign(ap.nblocks, 0);
    ap.reqs.assign(ap.nblocks, 0);
    ap.from.assign(ap.nblocks, string());
    ap.received = 0;
}

// Endgame: every missing block has already been requested from someone.
static bool in_endgame(const Torrent &t) {
    if (t.complete) return false;
    if (t.active.size() < t.num_pieces - t.have_count) return false;  // unstarted pieces remain
    for (auto &kv : t.active)
        for (uint32_t b = 0; b < kv.second.nblocks; b++)
            if (!kv.second.got[b] && kv.second.reqs[b] == 0) return false;
    return true;
}

static bool pick_block(Torrent &t, PeerConn &c, uint32_t &pi, uint32_t &bi) {
    // 1. Strict priority: finish pieces that are already started.
    for (auto &kv : t.active) {
        if (!c.peer_have[kv.first]) continue;
        const ActivePiece &ap = kv.second;
        for (uint32_t b = 0; b < ap.nblocks; b++)
            if (!ap.got[b] && ap.reqs[b] == 0) { pi = kv.first; bi = b; return true; }
    }
    // 2. Start a new piece: random for the first few, rarest-first afterwards.
    bool random_first = t.have_count < (uint32_t)RANDOM_FIRST_PIECES;
    vector<uint32_t> cands;
    int best = INT_MAX;
    for (uint32_t i = 0; i < t.num_pieces; i++) {
        if (t.have[i] || !c.peer_have[i] || t.active.count(i)) continue;
        if (random_first) { cands.push_back(i); continue; }
        if (t.avail[i] < best) { best = t.avail[i]; cands.clear(); }
        if (t.avail[i] == best) cands.push_back(i);
    }
    if (!cands.empty()) {
        pi = cands[uniform_int_distribution<size_t>(0, cands.size() - 1)(rng())];
        activate_piece(t, pi);
        bi = 0;
        return true;
    }
    // 3. Endgame: ask this peer for blocks already requested from others.
    if (!in_endgame(t)) return false;
    for (auto &kv : t.active) {
        if (!c.peer_have[kv.first]) continue;
        const ActivePiece &ap = kv.second;
        for (uint32_t b = 0; b < ap.nblocks; b++) {
            if (ap.got[b] || ap.reqs[b] >= MAX_ENDGAME_DUPLICATES) continue;
            if (c.inflight.count(make_pair(kv.first, b * BLOCK_SIZE))) continue;
            pi = kv.first; bi = b;
            return true;
        }
    }
    return false;
}

static void fill_requests(Torrent &t, const shared_ptr<PeerConn> &c) {
    if (t.complete || t.stopped || c->dead || c->peer_choking) return;
    size_t depth = c->snubbed ? 1 : PIPELINE_DEPTH;
    while (c->inflight.size() < depth) {
        uint32_t pi, bi;
        if (!pick_block(t, *c, pi, bi)) break;
        t.active[pi].reqs[bi]++;
        uint32_t begin = bi * BLOCK_SIZE;
        c->inflight[make_pair(pi, begin)] = Clock::now();
        send_msg(c, msg_triple(MSG_REQUEST, pi, begin, t.block_len(pi, begin)));
    }
}

static void fill_all(Torrent &t) {
    for (auto &p : t.peers) fill_requests(t, p);
}

static void update_interest(Torrent &t, const shared_ptr<PeerConn> &c) {
    bool need = false;
    if (!t.complete)
        for (uint32_t i = 0; i < t.num_pieces && !need; i++)
            if (c->peer_have[i] && !t.have[i]) need = true;
    if (need != c->am_interested) {
        c->am_interested = need;
        send_msg(c, make_msg(need ? MSG_INTERESTED : MSG_NOT_INTERESTED));
    }
}

static void set_choke(const shared_ptr<PeerConn> &c, bool choke) {
    if (c->am_choking == choke) return;
    c->am_choking = choke;
    if (choke) drop_serve_jobs(c);  // a choke discards the peer's pending requests
    send_msg(c, make_msg(choke ? MSG_CHOKE : MSG_UNCHOKE));
}

// Tit-for-tat: unchoke the peers that gave us the most data this round (or,
// once we are a seed, the ones we uploaded to fastest), plus one optimistic
// unchoke that rotates so new peers get a chance to prove themselves.
static void choke_round(Torrent &t, bool rotate_optimistic) {
    vector<shared_ptr<PeerConn>> cand;
    for (auto &p : t.peers)
        if (p->peer_interested && !p->dead) cand.push_back(p);
    bool seeding = t.complete;
    auto score = [seeding](const shared_ptr<PeerConn> &p) -> uint64_t {
        if (seeding) return p->up_window;
        return p->snubbed ? 0 : p->down_window;
    };
    stable_sort(cand.begin(), cand.end(),
                [&](const shared_ptr<PeerConn> &a, const shared_ptr<PeerConn> &b) {
                    return score(a) > score(b);
                });
    set<PeerConn *> keep;
    for (size_t i = 0; i < cand.size() && (int)i < REGULAR_UNCHOKES; i++) keep.insert(cand[i].get());

    shared_ptr<PeerConn> opt = t.optimistic;
    bool valid = opt && !opt->dead && opt->peer_interested && !keep.count(opt.get());
    if (rotate_optimistic || !valid) {
        vector<shared_ptr<PeerConn>> rest;
        for (auto &p : cand) if (!keep.count(p.get())) rest.push_back(p);
        opt = rest.empty() ? shared_ptr<PeerConn>()
                           : rest[uniform_int_distribution<size_t>(0, rest.size() - 1)(rng())];
        t.optimistic = opt;
    }
    if (opt) keep.insert(opt.get());

    for (auto &p : t.peers) {
        set_choke(p, keep.count(p.get()) == 0);
        p->up_window = p->down_window = 0;
    }
}

static void save_state(Torrent &t) {
    if (!t.is_download || t.state_path.empty() || t.complete) return;
    string tmp = t.state_path + ".tmp";
    {
        ofstream o(tmp.c_str(), ios::trunc);
        if (!o) return;
        o << "P2PFS-STATE 1\n" << t.filehash << "\n" << t.filesize << " " << t.num_pieces << "\n";
        for (uint32_t i = 0; i < t.num_pieces; i++) o << (t.have[i] ? '1' : '0');
        o << "\n";
    }
    rename(tmp.c_str(), t.state_path.c_str());
}

// Re-checks every piece the state file claims we have, like a client's
// "recheck" on resume, so a damaged .part file is never trusted.
static void load_state(Torrent &t) {
    ifstream in(t.state_path.c_str());
    if (!in) return;
    string magic, ver, hash, bits;
    uint64_t fs;
    uint32_t n;
    if (!(in >> magic >> ver >> hash >> fs >> n)) return;
    if (magic != "P2PFS-STATE" || hash != t.filehash || fs != t.filesize || n != t.num_pieces) return;
    if (n > 0 && !(in >> bits)) return;
    if (bits.size() != n) return;
    vector<char> buf(PIECE_SIZE);
    for (uint32_t i = 0; i < n; i++) {
        if (bits[i] != '1') continue;
        uint32_t len = t.piece_len(i);
        if (!pread_all(t.fd, buf.data(), len, (off_t)i * PIECE_SIZE)) continue;
        if (sha1_hex((const unsigned char *)buf.data(), len) != t.piece_hashes[i]) continue;
        t.have[i] = true;
        t.have_count++;
    }
}

static void finish_download(Torrent &t) {
    t.complete = true;
    t.active.clear();
    fsync(t.fd);
    if (rename(t.part_path.c_str(), t.final_path.c_str()) == 0) {
        t.data_path = t.final_path;
    } else {
        t.error = string("cannot rename .part file: ") + strerror(errno);
    }
    unlink(t.state_path.c_str());
    t.just_completed = true;
    for (auto &p : t.peers) {
        release_requests(t, *p);
        update_interest(t, p);   // sends not_interested
    }
}

static void piece_completed(Torrent &t, uint32_t pi) {
    t.have[pi] = true;
    t.have_count++;
    save_state(t);
    string have = msg_have(pi);
    for (auto &p : t.peers) {
        send_msg(p, have);
        if (p->am_interested) update_interest(t, p);
    }
    if (t.have_count == t.num_pieces) finish_download(t);
}

static string block_hash(const Torrent &t, const ActivePiece &ap, uint32_t pi, uint32_t b) {
    return sha1_hex((const unsigned char *)ap.buf.data() + b * BLOCK_SIZE, t.block_len(pi, b * BLOCK_SIZE));
}

// Smart ban, step 1: a piece failed its hash check. We can't tell yet which
// block was bad, so remember what every sender gave us.
static void record_suspects(Torrent &t, uint32_t pi, const ActivePiece &ap) {
    vector<SuspectBlock> &v = t.suspects[pi];
    for (uint32_t b = 0; b < ap.nblocks; b++) {
        SuspectBlock s;
        s.block = b;
        s.peer_id = ap.from[b];
        s.hash = block_hash(t, ap, pi, b);
        v.push_back(s);
    }
}

// Smart ban, step 2: the piece has now passed, so any peer whose earlier
// block differs from the verified one provably sent corrupt data: ban it.
static void convict_liars(Torrent &t, uint32_t pi, const ActivePiece &ap) {
    for (auto &s : t.suspects[pi]) {
        if (s.peer_id.empty() || t.banned_ids.count(s.peer_id)) continue;
        if (s.hash == block_hash(t, ap, pi, s.block)) continue;
        t.banned_ids.insert(s.peer_id);
        for (auto &p : t.peers) {
            if (p->peer_id != s.peer_id) continue;
            if (p->outgoing) t.banned_addrs.insert(p->addr);
            kill_conn(p);
        }
    }
    t.suspects.erase(pi);
}

static void on_block(Torrent &t, const shared_ptr<PeerConn> &c, uint32_t pi, uint32_t begin,
                     const char *data, uint32_t len) {
    if (pi >= t.num_pieces) return;
    auto key = make_pair(pi, begin);
    auto ait = t.active.find(pi);
    auto iit = c->inflight.find(key);
    if (iit != c->inflight.end()) {
        c->inflight.erase(iit);
        if (ait != t.active.end()) {
            uint32_t b = begin / BLOCK_SIZE;
            if (b < ait->second.reqs.size() && ait->second.reqs[b] > 0) ait->second.reqs[b]--;
        }
    }
    c->snubbed = false;
    c->down_window += len;
    t.downloaded += len;
    t.rate_bytes += len;

    if (ait == t.active.end() || begin % BLOCK_SIZE != 0) { fill_requests(t, c); return; }
    ActivePiece &ap = ait->second;
    uint32_t b = begin / BLOCK_SIZE;
    if (b >= ap.nblocks || len != t.block_len(pi, begin) || ap.got[b]) { fill_requests(t, c); return; }

    memcpy(ap.buf.data() + begin, data, len);
    ap.got[b] = 1;
    ap.from[b] = c->peer_id;
    ap.received++;

    // Endgame: the block arrived, so cancel the duplicate requests to other peers.
    for (auto &o : t.peers) {
        if (o == c) continue;
        auto oit = o->inflight.find(key);
        if (oit == o->inflight.end()) continue;
        o->inflight.erase(oit);
        if (ap.reqs[b] > 0) ap.reqs[b]--;
        send_msg(o, msg_triple(MSG_CANCEL, pi, begin, len));
    }

    if (ap.received == ap.nblocks) {
        bool ok = sha1_hex((const unsigned char *)ap.buf.data(), ap.buf.size()) == t.piece_hashes[pi];
        if (!ok) {
            t.hash_failures++;
            record_suspects(t, pi, ap);
        } else if (t.suspects.count(pi)) {
            convict_liars(t, pi, ap);
        }
        if (ok && !pwrite_all(t.fd, ap.buf.data(), ap.buf.size(), (off_t)pi * PIECE_SIZE)) {
            ok = false;
            t.error = string("disk write failed: ") + strerror(errno);
        }
        for (auto &o : t.peers) {   // forget any stray requests for this piece
            for (auto it = o->inflight.begin(); it != o->inflight.end();) {
                if (it->first.first == pi) it = o->inflight.erase(it);
                else ++it;
            }
        }
        t.active.erase(ait);   // on a hash failure the piece is simply downloaded again
        if (ok) piece_completed(t, pi);
        fill_all(t);
        return;
    }
    fill_requests(t, c);
}

// Returns false when the peer broke the protocol and must be disconnected.
static bool handle_msg(Torrent &t, const shared_ptr<PeerConn> &c, const string &m) {
    uint8_t id = (uint8_t)m[0];
    const char *p = m.data() + 1;
    size_t plen = m.size() - 1;
    lock_guard<mutex> lk(t.mtx);
    if (t.stopped) return false;
    switch (id) {
    case MSG_CHOKE:
        c->peer_choking = true;
        release_requests(t, *c);
        fill_all(t);
        break;
    case MSG_UNCHOKE:
        c->peer_choking = false;
        fill_requests(t, c);
        break;
    case MSG_INTERESTED: {
        c->peer_interested = true;
        // Fill a free upload slot right away instead of waiting for the next round.
        int unchoked = 0;
        for (auto &q : t.peers) if (!q->am_choking) unchoked++;
        if (unchoked < REGULAR_UNCHOKES + 1) set_choke(c, false);
        break;
    }
    case MSG_NOT_INTERESTED:
        c->peer_interested = false;
        set_choke(c, true);
        break;
    case MSG_HAVE: {
        if (plen != 4) return false;
        uint32_t i = get_u32(p);
        if (i >= t.num_pieces) return false;
        if (!c->peer_have[i]) {
            c->peer_have[i] = true;
            c->peer_have_count++;
            t.avail[i]++;
            if (!t.complete && !t.have[i] && !c->am_interested) {
                c->am_interested = true;
                send_msg(c, make_msg(MSG_INTERESTED));
            }
            fill_requests(t, c);
        }
        break;
    }
    case MSG_BITFIELD: {
        if (plen != (t.num_pieces + 7) / 8) return false;
        for (uint32_t i = 0; i < t.num_pieces; i++) {
            bool h = ((((unsigned char)p[i / 8]) >> (7 - i % 8)) & 1) != 0;
            if (h && !c->peer_have[i]) {
                c->peer_have[i] = true;
                c->peer_have_count++;
                t.avail[i]++;
            }
        }
        update_interest(t, c);
        fill_requests(t, c);
        break;
    }
    case MSG_REQUEST: {
        if (plen != 12) return false;
        uint32_t i = get_u32(p), b = get_u32(p + 4), l = get_u32(p + 8);
        if (i >= t.num_pieces || l == 0 || l > MAX_REQUEST_LEN || (uint64_t)b + l > t.piece_len(i))
            return false;
        if (c->am_choking || !t.have[i]) break;
        {
            lock_guard<mutex> qk(c->qmtx);
            size_t queued = 0;
            for (auto &it : c->q) if (it.serve) queued++;
            if (queued >= MAX_QUEUED_UPLOADS || c->dead) break;
            OutItem it;
            it.serve = true; it.index = i; it.begin = b; it.length = l;
            c->q.push_back(std::move(it));
        }
        c->qcv.notify_one();
        break;
    }
    case MSG_PIECE: {
        if (plen < 8) return false;
        on_block(t, c, get_u32(p), get_u32(p + 4), p + 8, (uint32_t)(plen - 8));
        break;
    }
    case MSG_CANCEL: {
        if (plen != 12) return false;
        uint32_t i = get_u32(p), b = get_u32(p + 4), l = get_u32(p + 8);
        lock_guard<mutex> qk(c->qmtx);
        for (auto it = c->q.begin(); it != c->q.end(); ++it) {
            if (it->serve && it->index == i && it->begin == b && it->length == l) { c->q.erase(it); break; }
        }
        break;
    }
    default:
        break;   // unknown messages are ignored, as BitTorrent extensions would be
    }
    return true;
}

// ---------- connection threads ----------

static void writer_loop(shared_ptr<PeerConn> c) {
    vector<char> blk;
    while (true) {
        OutItem it;
        {
            unique_lock<mutex> lk(c->qmtx);
            bool woke = c->qcv.wait_for(lk, chrono::seconds(KEEPALIVE_INTERVAL),
                                        [&] { return c->dead.load() || !c->q.empty(); });
            if (c->dead) break;
            if (!woke) it.data = string(4, '\0');   // keep-alive
            else { it = std::move(c->q.front()); c->q.pop_front(); }
        }
        if (it.serve) {
            Torrent &t = *c->t;
            blk.resize(it.length);
            off_t off = (off_t)it.index * PIECE_SIZE + it.begin;
            if (!pread_all(t.fd, blk.data(), it.length, off)) continue;
            string m;
            m.reserve(13 + it.length);
            put_u32(m, 9 + it.length);
            m.push_back((char)MSG_PIECE);
            put_u32(m, it.index);
            put_u32(m, it.begin);
            m.append(blk.data(), it.length);
            if (!send_all(c->fd, m)) break;
            lock_guard<mutex> lk(t.mtx);
            c->up_window += it.length;
            t.uploaded += it.length;
        } else if (!send_all(c->fd, it.data)) {
            break;
        }
    }
    kill_conn(c);
}

static void detach_peer(Torrent &t, const shared_ptr<PeerConn> &c) {
    lock_guard<mutex> lk(t.mtx);
    auto it = find(t.peers.begin(), t.peers.end(), c);
    if (it == t.peers.end()) return;
    t.peers.erase(it);
    for (uint32_t i = 0; i < t.num_pieces; i++)
        if (c->peer_have[i] && t.avail[i] > 0) t.avail[i]--;
    release_requests(t, *c);
    if (t.optimistic == c) t.optimistic.reset();
    fill_all(t);
}

// Runs a connection after a successful handshake; the calling thread becomes
// the reader and a second thread drains the outgoing queue.
static void run_peer(shared_ptr<Torrent> tp, int fd, const string &addr, const string &pid, bool outgoing) {
    auto c = make_shared<PeerConn>();
    c->fd = fd;
    c->addr = addr;
    c->peer_id = pid;
    c->outgoing = outgoing;
    c->t = tp;
    c->peer_have.assign(tp->num_pieces, false);
    tune_socket(fd, IDLE_TIMEOUT);

    shared_ptr<PeerConn> victim;
    bool rejected = false;
    {
        lock_guard<mutex> lk(tp->mtx);
        if (tp->stopped || tp->peers.size() >= MAX_PEERS || tp->banned_ids.count(pid)) rejected = true;
        for (auto &o : tp->peers) {
            if (rejected || o->peer_id != pid) continue;
            // Both sides dialed each other: keep the connection opened by the
            // smaller peer id, so the two ends agree on which one survives.
            const string &new_init = outgoing ? g_peer_id : pid;
            const string &old_init = o->outgoing ? g_peer_id : pid;
            if (new_init < old_init) victim = o;
            else rejected = true;
        }
        if (!rejected) {
            tp->peers.push_back(c);
            if (tp->have_count > 0) send_msg(c, msg_bitfield(tp->have));
        }
    }
    if (rejected) { close(fd); return; }
    if (victim) kill_conn(victim);

    c->writer = thread(writer_loop, c);
    while (!c->dead) {
        char hdr[4];
        if (!recv_all(fd, hdr, 4)) break;
        uint32_t len = get_u32(hdr);
        if (len == 0) continue;   // keep-alive
        if (len > MAX_MSG_LEN) break;
        string m(len, '\0');
        if (!recv_all(fd, &m[0], len)) break;
        if (!handle_msg(*tp, c, m)) break;
    }
    kill_conn(c);
    c->writer.join();
    detach_peer(*tp, c);
    lock_guard<mutex> lk(c->fdmtx);
    close(c->fd);
    c->fd = -1;
}

static shared_ptr<Torrent> find_torrent(const string &info_hash) {
    lock_guard<mutex> lk(g_mtx);
    auto it = g_torrents.find(info_hash);
    return it == g_torrents.end() ? shared_ptr<Torrent>() : it->second;
}

static void handle_incoming(int fd, string addr) {
    tune_socket(fd, HANDSHAKE_TIMEOUT);
    string ih, pid;
    shared_ptr<Torrent> t;
    if (!read_handshake(fd, ih, pid) || pid == g_peer_id || !(t = find_torrent(ih)) ||
        !send_all(fd, make_handshake(ih))) {
        close(fd);
        return;
    }
    run_peer(t, fd, addr, pid, false);
}

static void dial_peer(shared_ptr<Torrent> t, string addr) {
    int fd = connect_timeout(addr, 5);
    bool ok = false, self = false;
    string ih, pid;
    if (fd >= 0) {
        tune_socket(fd, HANDSHAKE_TIMEOUT);
        if (send_all(fd, make_handshake(t->info_hash)) && read_handshake(fd, ih, pid) &&
            ih == t->info_hash) {
            if (pid == g_peer_id) self = true;
            else ok = true;
        }
    }
    if (self) {
        lock_guard<mutex> lk(g_mtx);
        g_self_addrs.insert(addr);
    }
    {
        lock_guard<mutex> lk(t->mtx);
        t->connecting.erase(addr);
        if (!ok) t->failed[addr] = Clock::now();
    }
    if (!ok) {
        if (fd >= 0) close(fd);
        return;
    }
    run_peer(t, fd, addr, pid, true);
}

static void connect_peers(const shared_ptr<Torrent> &t, const vector<string> &addrs) {
    string self = announce_ip ? announce_ip() + ":" + to_string(g_listen_port) : string();
    set<string> selfs;
    {
        lock_guard<mutex> lk(g_mtx);
        selfs = g_self_addrs;
    }
    lock_guard<mutex> lk(t->mtx);
    if (t->stopped || t->complete) return;
    Clock::time_point now = Clock::now();
    for (auto &addr : addrs) {
        if (addr == self || selfs.count(addr) || t->banned_addrs.count(addr)) continue;
        if (t->peers.size() + t->connecting.size() >= MAX_PEERS) break;
        if (t->connecting.count(addr)) continue;
        bool connected = false;
        for (auto &p : t->peers) if (p->addr == addr) { connected = true; break; }
        if (connected) continue;
        auto f = t->failed.find(addr);
        if (f != t->failed.end() && now - f->second < chrono::seconds(DIAL_BACKOFF)) continue;
        t->connecting.insert(addr);
        thread(dial_peer, t, addr).detach();
    }
}

// ---------- tracker interaction (never called with an engine lock held) ----------

static bool parse_peer_reply(const string &reply, vector<string> &peers) {
    stringstream ls(reply);
    string status, hash, tmp;
    uint64_t fs;
    int n, k;
    if (!(ls >> status) || status != "OK") return false;
    if (!(ls >> fs >> hash >> n)) return false;
    for (int i = 0; i < n; i++) ls >> tmp;
    if (!(ls >> k)) return false;
    for (int i = 0; i < k && (ls >> tmp); i++) peers.push_back(tmp);
    return true;
}

static void tracker_work(shared_ptr<Torrent> t, bool announce, bool finish, bool query) {
    if (finish) {
        string path;
        {
            lock_guard<mutex> lk(t->mtx);
            path = t->data_path;
        }
        vector<string> ph;
        string full;
        uint64_t fs = 0;
        bool ok = compute_file_hashes(path, ph, full, fs) && full == t->filehash;
        if (!ok) {
            lock_guard<mutex> lk(t->mtx);
            t->error = "final hash mismatch";
        }
        // One write() call, so this never races with the command loop's use of cout.
        string note = "\n[download] " + t->gid + "/" + t->filename + " -> " + path +
                      (ok ? " completed and verified" : " FINAL HASH MISMATCH") + "\n> ";
        ssize_t ignored = write(STDOUT_FILENO, note.data(), note.size());
        (void)ignored;
        if (ok && on_download_complete) on_download_complete(t->gid, t->filename, path);
    }
    if (announce) {
        ostringstream out;
        out << "upload_file " << t->gid << " " << t->filename << " " << t->filesize << " "
            << (announce_ip ? announce_ip() : string("127.0.0.1")) << " " << g_listen_port << " "
            << t->filehash << " " << t->num_pieces;
        for (auto &h : t->piece_hashes) out << " " << h;
        string reply;
        bool ok = tracker_request && tracker_request(out.str(), reply) && reply.compare(0, 2, "OK") == 0;
        lock_guard<mutex> lk(t->mtx);
        t->announced = ok;
        t->announcing = false;
        if (!ok) t->next_announce_tick = t->ticks + ANNOUNCE_INTERVAL;
    }
    if (query) {
        string reply;
        vector<string> peers;
        if (tracker_request && tracker_request("download_file " + t->gid + " " + t->filename, reply))
            parse_peer_reply(reply, peers);
        connect_peers(t, peers);
        lock_guard<mutex> lk(t->mtx);
        t->querying = false;
    }
}

static void expire_requests(Torrent &t) {
    Clock::time_point now = Clock::now();
    for (auto &p : t.peers) {
        bool expired = false;
        for (auto it = p->inflight.begin(); it != p->inflight.end();) {
            if (now - it->second < chrono::seconds(REQUEST_TIMEOUT)) { ++it; continue; }
            uint32_t pi = it->first.first, begin = it->first.second;
            auto a = t.active.find(pi);
            if (a != t.active.end()) {
                uint32_t b = begin / BLOCK_SIZE;
                if (b < a->second.reqs.size() && a->second.reqs[b] > 0) a->second.reqs[b]--;
            }
            send_msg(p, msg_triple(MSG_CANCEL, pi, begin, t.block_len(pi, begin)));
            it = p->inflight.erase(it);
            expired = true;
        }
        if (expired) p->snubbed = true;   // slow peer: keep only one request outstanding
    }
}

static void maintenance_loop() {
    while (true) {
        this_thread::sleep_for(chrono::seconds(1));
        vector<shared_ptr<Torrent>> ts;
        {
            lock_guard<mutex> lk(g_mtx);
            for (auto &kv : g_torrents) ts.push_back(kv.second);
        }
        for (auto &tp : ts) {
            bool announce = false, finish = false, query = false;
            vector<shared_ptr<PeerConn>> seeds;
            {
                lock_guard<mutex> lk(tp->mtx);
                Torrent &t = *tp;
                if (t.stopped) continue;
                t.ticks++;
                t.down_rate = 0.7 * t.down_rate + 0.3 * (double)t.rate_bytes;
                t.rate_bytes = 0;
                expire_requests(t);
                if (t.ticks % CHOKE_INTERVAL == 0) choke_round(t, t.ticks % OPTIMISTIC_INTERVAL == 0);
                fill_all(t);
                if (t.complete)   // two seeds have nothing to give each other
                    for (auto &p : t.peers)
                        if (p->peer_have_count == t.num_pieces) seeds.push_back(p);
                // Announce as soon as the download starts (BitTorrent's "started"
                // event), so peers that join later can also fetch pieces from us.
                if (t.is_download && !t.announced && !t.announcing && t.ticks >= t.next_announce_tick) {
                    announce = true;
                    t.announcing = true;
                }
                if (t.just_completed) {
                    t.just_completed = false;
                    finish = true;
                }
                // Refresh the peer list shortly after starting (to find peers that
                // started at the same time), then every ANNOUNCE_INTERVAL.
                if (!t.complete && !t.querying &&
                    (t.ticks == 2 || t.ticks % ANNOUNCE_INTERVAL == 0 ||
                     (t.peers.empty() && t.connecting.empty() && t.ticks % 5 == 0))) {
                    query = true;
                    t.querying = true;
                }
            }
            for (auto &p : seeds) kill_conn(p);
            if (announce || finish || query) thread(tracker_work, tp, announce, finish, query).detach();
        }
    }
}

static void accept_loop() {
    while (true) {
        sockaddr_in a;
        socklen_t l = sizeof(a);
        int fd = accept(g_listen_fd, (sockaddr *)&a, &l);
        if (fd < 0) {
            if (errno != EINTR) this_thread::sleep_for(chrono::milliseconds(100));
            continue;
        }
        char ip[64];
        inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));
        thread(handle_incoming, fd, string(ip) + ":" + to_string(ntohs(a.sin_port))).detach();
    }
}

// ---------- public API ----------

bool start_engine() {
    static mutex start_mtx;
    lock_guard<mutex> lk(start_mtx);
    if (g_listen_fd >= 0) return true;
    signal(SIGPIPE, SIG_IGN);
    const char *alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    g_peer_id = "-PF0100-";
    random_device rd;
    while (g_peer_id.size() < 20) g_peer_id.push_back(alnum[rd() % 62]);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return false;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;
    if (::bind(s, (sockaddr *)&addr, sizeof(addr)) < 0 || listen(s, 64) < 0) {
        close(s);
        return false;
    }
    sockaddr_in as;
    socklen_t al = sizeof(as);
    if (getsockname(s, (sockaddr *)&as, &al) == 0) g_listen_port = ntohs(as.sin_port);
    g_listen_fd = s;
    thread(accept_loop).detach();
    thread(maintenance_loop).detach();
    return true;
}

int listen_port() { return g_listen_port; }

bool seed_file(const string &gid, const string &filename, const string &path, uint64_t filesize,
               const string &filehash, const vector<string> &piece_hashes) {
    if (!start_engine()) return false;
    string ih = hex_to_raw(filehash);
    if (ih.empty()) return false;
    lock_guard<mutex> g(g_mtx);
    auto it = g_torrents.find(ih);
    if (it != g_torrents.end()) {
        lock_guard<mutex> lk(it->second->mtx);
        it->second->names.insert(make_pair(gid, filename));
        return true;
    }
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    auto t = make_shared<Torrent>();
    t->info_hash = ih;
    t->filehash = filehash;
    t->gid = gid;
    t->filename = filename;
    t->final_path = t->data_path = path;
    t->filesize = filesize;
    t->num_pieces = (uint32_t)piece_hashes.size();
    t->piece_hashes = piece_hashes;
    t->fd = fd;
    t->names.insert(make_pair(gid, filename));
    t->have.assign(t->num_pieces, true);
    t->have_count = t->num_pieces;
    t->avail.assign(t->num_pieces, 0);
    t->complete = true;
    t->announced = true;   // client.cpp announces seeds itself
    g_torrents[ih] = t;
    return true;
}

bool start_download(const string &gid, const string &filename, const string &dest_path,
                    uint64_t filesize, const string &filehash, const vector<string> &piece_hashes,
                    const vector<string> &peers, string &message) {
    if (!start_engine()) { message = "cannot start peer engine"; return false; }
    string ih = hex_to_raw(filehash);
    if (ih.empty()) { message = "invalid file hash from tracker"; return false; }
    uint64_t expected = (filesize + PIECE_SIZE - 1) / PIECE_SIZE;
    if (expected != piece_hashes.size()) { message = "piece count does not match file size"; return false; }

    if (auto existing = find_torrent(ih)) {
        lock_guard<mutex> lk(existing->mtx);
        message = existing->complete ? "already_have_file at " + existing->data_path
                                     : "already_downloading";
        return false;
    }

    auto t = make_shared<Torrent>();
    t->info_hash = ih;
    t->filehash = filehash;
    t->gid = gid;
    t->filename = filename;
    t->final_path = dest_path;
    t->part_path = dest_path + ".part";
    t->state_path = dest_path + ".state";
    t->data_path = t->part_path;
    t->filesize = filesize;
    t->num_pieces = (uint32_t)piece_hashes.size();
    t->piece_hashes = piece_hashes;
    t->is_download = true;
    t->names.insert(make_pair(gid, filename));
    t->have.assign(t->num_pieces, false);
    t->avail.assign(t->num_pieces, 0);

    t->fd = open(t->part_path.c_str(), O_RDWR | O_CREAT, 0644);
    if (t->fd < 0) { message = string("cannot create file: ") + strerror(errno); return false; }
    load_state(*t);
    if (ftruncate(t->fd, (off_t)filesize) != 0) {
        message = string("cannot allocate file: ") + strerror(errno);
        return false;
    }
    uint32_t resumed = t->have_count;

    {
        lock_guard<mutex> g(g_mtx);
        if (g_torrents.count(ih)) { message = "already_downloading"; return false; }
        g_torrents[ih] = t;
        // A restarted download replaces its stopped entry in show_downloads.
        g_history.erase(remove_if(g_history.begin(), g_history.end(),
                                  [&](const shared_ptr<Torrent> &h) { return h->info_hash == ih; }),
                        g_history.end());
        g_history.push_back(t);
    }
    {
        lock_guard<mutex> lk(t->mtx);
        if (t->have_count == t->num_pieces) finish_download(*t);
        else save_state(*t);
    }
    connect_peers(t, peers);

    ostringstream m;
    if (resumed == t->num_pieces) m << "All pieces already present, finishing";
    else if (resumed > 0) m << "Resuming download: " << resumed << "/" << t->num_pieces << " pieces already verified";
    else m << "Download started in background (" << t->num_pieces << " pieces, " << peers.size() << " peers)";
    m << ". Use show_downloads to follow it.";
    message = m.str();
    return true;
}

bool stop_share(const string &gid, const string &filename) {
    shared_ptr<Torrent> victim;
    bool found = false;
    {
        lock_guard<mutex> g(g_mtx);
        for (auto it = g_torrents.begin(); it != g_torrents.end(); ++it) {
            shared_ptr<Torrent> t = it->second;
            lock_guard<mutex> lk(t->mtx);
            if (!t->names.erase(make_pair(gid, filename))) continue;
            found = true;
            if (t->names.empty()) {
                t->stopped = true;
                victim = t;
                g_torrents.erase(it);
            }
            break;
        }
    }
    if (victim) {
        vector<shared_ptr<PeerConn>> peers;
        {
            lock_guard<mutex> lk(victim->mtx);
            peers = victim->peers;
        }
        for (auto &p : peers) kill_conn(p);
    }
    return found;
}

void print_downloads() {
    vector<shared_ptr<Torrent>> list;
    {
        lock_guard<mutex> g(g_mtx);
        list = g_history;
    }
    if (list.empty()) {
        cout << "No downloads" << endl;
        return;
    }
    for (auto &tp : list) {
        lock_guard<mutex> lk(tp->mtx);
        Torrent &t = *tp;
        ostringstream o;
        char st = t.complete ? 'C' : (t.stopped ? 'S' : 'D');
        o << "[" << st << "] [" << t.gid << "] " << t.filename;
        if (t.complete) {
            o << " " << t.filesize << "/" << t.filesize << " bytes -> " << t.data_path;
        } else {
            uint64_t got = 0;
            for (uint32_t i = 0; i < t.num_pieces; i++) if (t.have[i]) got += t.piece_len(i);
            double pct = t.filesize ? 100.0 * (double)got / (double)t.filesize : 100.0;
            int unchoked_by = 0;
            for (auto &p : t.peers) if (!p->peer_choking) unchoked_by++;
            o << fixed << setprecision(1) << " " << pct << "% (" << t.have_count << "/" << t.num_pieces
              << " pieces) peers " << t.peers.size() << ", unchoked by " << unchoked_by << ", "
              << human_rate(t.down_rate);
            if (in_endgame(t)) o << " [endgame]";
            if (t.stopped) o << " (stopped; run download_file again to resume)";
            else if (t.peers.empty()) o << " (waiting for peers)";
        }
        o << " | uploaded " << fixed << setprecision(1) << (double)t.uploaded / (1024 * 1024) << " MB";
        if (t.hash_failures) o << " | hash_failures " << t.hash_failures;
        if (!t.banned_ids.empty()) o << " | banned_peers " << t.banned_ids.size();
        if (!t.error.empty()) o << " error: " << t.error;
        cout << o.str() << "\n";
    }
    cout << flush;
}

}
