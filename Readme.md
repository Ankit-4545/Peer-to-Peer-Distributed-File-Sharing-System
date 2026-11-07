# Peer-to-peer File Sharing System:

This project implements a distributed file sharing system with tracker-based coordination and peer-to-peer file transfers. It supports user authentication, group management, file uploads/downloads, and robust failover between multiple trackers.

## Directory Structure:

```
client/
    client.cpp           Client application source (commands, tracker connection)
    peer.cpp, peer.h     BitTorrent-style peer engine (peer protocol, piece picking, choking)
    files.cpp, files.h   File hashing and piece management
    Makefile             Build script for client
    tracker_info.txt     List of tracker IPs and ports
tracker/
    tracker.cpp          Tracker server source
    files.cpp, files.h   File hashing and piece management
    Makefile             Build script for tracker
    tracker_info.txt     List of tracker IPs and ports
    sync_log.txt         Shared log for tracker state
Readme.md              This file
```
## tracker.cpp
### Multiple client handling:
The tracker handles multiple clients concurrently using a TCP socket, assigning each client connection to a separate thread. This allows clients to interact with the server simultaneously without blocking, with responses clearly marked by END_OF_REPLY.
### Tracker synchronization:
State is maintained via a persistent log file (sync_log.txt) where all operations are recorded. On startup or failover, the log is replayed to restore the in-memory state, and a watcher thread continuously monitors new entries to keep the tracker synchronized.
### Command handling:
The tracker supports commands for user management (create_user, login, logout), group management (create_group, join_group, leave_group, list_groups, list_requests, accept_request), and file operations (upload_file, list_files, download_file, stop_share). Each command validates the client’s session, permissions, and group membership before execution.
### Session management:
Secure sessions are implemented with unique 16-character tokens generated on login. The tracker verifies session tokens for authenticated commands and allows session reuse for failover recovery, ensuring clients can reconnect seamlessly.
### Thread safety:
Shared resources such as users, groups, requests, and file metadata are protected by mutexes, and log file access is synchronized. This ensures data consistency and prevents race conditions even under high concurrency.
### File sharing and seeder tracking:
The tracker maintains detailed file metadata, including size, piece hashes, full hash, and seeder lists. It updates the state on uploads, provides seeder information for downloads, and automatically removes files with no active seeders when clients stop sharing.

## client.cpp
### Initialization and Global Setup:
The client includes libraries for networking, threading, file I/O, and synchronization. It defines structures for Tracker and Peer, and maintains global variables for tracker connections, session info (cached_uid and cached_session), peer server state, and active downloads.
### Tracker Connection and Failover:
Functions like read_tracker_file, connect_to_tracker, try_connect, and send_with_failover handle tracker connections, send commands with session handling, and perform automatic failover and auto-login if a tracker is down or session is lost.
### Peer-to-Peer Engine (peer.cpp):
Downloads and uploads work like BitTorrent. Each shared file is a torrent identified by its full SHA-1 hash (the info-hash), and peers keep **one persistent TCP connection per peer**, used in both directions:
* **Handshake** `<14>"P2PFS protocol"<8 reserved><20-byte info-hash><20-byte peer id>`, then length-prefixed messages `<4-byte length><id><payload>`: choke, unchoke, interested, not_interested, have, bitfield, request, piece, cancel, plus keep-alives.
* **Bitfield / have**: peers exchange which pieces they hold and broadcast `have` for every newly verified piece.
* **Blocks and pipelining**: pieces (512 KB) are requested as 16 KB blocks with 8 requests in flight per peer. Requests that time out are re-issued elsewhere, and slow (snubbed) peers get one request at a time.
* **Piece selection**: the first 4 pieces are random, then rarest-first. Pieces already started are finished first.
* **Endgame mode**: once every missing block has been requested, the remaining blocks are requested from several peers, and the duplicates are cancelled when one arrives.
* **Choking**: each peer uploads to 3 peers chosen by tit-for-tat (the best download rate, or the best upload rate when seeding), plus 1 optimistic unchoke rotated every 30 s.
* **Smart ban**: when a piece fails its hash check, every block's hash and sender is recorded. Once the piece verifies, any peer whose block differed is banned.
* **Swarming**: a downloader announces itself to the tracker as soon as the download starts and serves every verified piece, so peers can finish from each other even after the original seeder leaves. The peer list is refreshed from the tracker every 30 s.
* **Background downloads and resume**: `download_file` returns immediately. Data goes to `<file>.part`, progress to `<file>.state`, and the file is renamed to its real name only after the full-file hash matches. Running `download_file` again after a crash or `quit` re-verifies the saved pieces and fetches only the missing ones.
### Command Handling:
The main loop interprets user commands, including create_user and login for account management, group commands (create_group, join_group, leave_group, etc.), file operations (upload_file, download_file, list_files), and download management (show_downloads, stop_share). Commands interact with trackers or peers as needed, and responses are validated for correctness.
### File Upload and Download Logic:
Uploads compute file hashes, register the file with the peer engine, and announce it to the tracker. Downloads run in the background in the peer engine (see above). `show_downloads` shows progress, connected peers, download rate, bytes uploaded, and any hash failures or banned peers.
### Error Handling and Cleanup:
The client provides feedback for invalid commands, connection failures, or hash mismatches. On exit, it closes sockets and cleans up resources to ensure a graceful shutdown.

## files.cpp (similiar for both tracker and client)
### SHA-1 Based Hashing:
The system implements SHA-1 hashing (SHA1Init, SHA1Update, SHA1Final, SHA1Transform) to compute both piece-level and full-file hashes. Helper functions (sha1_hex) convert data or strings to hexadecimal for storage, transmission, and verification.
### File Chunking and Piece Hashing:
Files are split into fixed-size pieces (PIECE_SIZE). compute_file_hashes reads each piece, generates its SHA-1 hash, and simultaneously updates a running hash for the entire file. This produces a vector of piece hashes and a full-file hash for end-to-end integrity.
### Random Access and Piece Management:
Pieces can be independently read from disk using read_piece_from_file, supporting parallel and out-of-order downloads. Hash utilities (join_piece_hashes / split_piece_hashes) serialize and parse piece hashes for storage and network communication.
### Integrity Verification and P2P Strategy:
Each downloaded piece is verified against its hash, and the complete file is checked against the full-file hash. This allows safe, parallel downloads from multiple seeders, with retries for failed pieces, ensuring robust file sharing with full integrity guarantees.

### Assumption made
* Both tracker is up at the start.
* If a tracker goes down it wont come up in the current session.

## Execution instruction:
1. For tracker:
* cd tracker
* make
* ./tracker tracker_info.txt tracker_no(1/2)
2. For client:
* cd ..
* cd client
* make
* ./client IP:PORT tracker_info.txt
