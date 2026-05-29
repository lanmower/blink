#ifdef __EMSCRIPTEN__
#include "blink/unixsock_shim.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Trace the in-process unix layer to the guest's stderr (temporary, unconditional
// — emscripten getenv reads the Module ENV not the host env, so gating is dead).
#define USDBG(...)                                  \
  do {                                              \
    fprintf(stderr, "[unixsock] " __VA_ARGS__);     \
    fputc('\n', stderr);                            \
    fflush(stderr);                                 \
  } while (0)

// Append a line to a fixed MEMFS marker file (cross-thread coherent, unlike the
// per-thread emscripten stdout callbacks) so the host can observe the X-client
// handshake events from a worker thread.
static void USMARK(const char *line) {
  FILE *mk = fopen("/em-unixsock.log", "a");
  if (mk) { fputs(line, mk); fputc('\n', mk); fclose(mk); }
}
// Public alias so other shims (epoll) can append to the same marker log.
void blink_usmark(const char *line) { USMARK(line); }

// Track which fds we created as in-process AF_UNIX sockets, and the listener /
// connection state for each. Single-threaded-enough for blink's emscripten
// build: the X server + clients are cooperatively scheduled in one host
// process, so no locking is required around the tables.

#define UNIX_MAX_SOCKS    256
#define UNIX_MAX_BACKLOG  16
#define UNIX_PATH_MAX     108

enum UnixState {
  UNIX_FREE = 0,
  UNIX_OPEN,       // socket() created, not bound/connected
  UNIX_LISTENING,  // bind()+listen() done; accepts connections
  UNIX_CONNECTED,  // data flows over the paired socketpair fd
};

struct UnixSock {
  int fd;                      // the fd handed back to the caller (-1 = slot free for non-tracked)
  int wake_wr;                 // write end of the fd's backing pipe; a byte here
                               // makes `fd` (the read end) poll-readable so the
                               // X server's epoll loop wakes to accept().
  enum UnixState state;
  int bound;                   // bind() has been called on this fd
  int vmid;                    // which concurrent VM created this socket
  char path[UNIX_PATH_MAX];    // bind path (listeners) — empty otherwise
  int pending[UNIX_MAX_BACKLOG];  // (legacy) queued slot markers
  void *pconn[UNIX_MAX_BACKLOG];  // queued shared connections awaiting accept()
  int npending;
};

static struct UnixSock g_socks[UNIX_MAX_SOCKS];

// Thread-local current-vmid (defined here so the connected-fd table below can
// reference it; commentary at first use farther down). Each VM thread has its
// own current vmid so listener-readiness / fd-scoping use THIS thread's VM.
_Thread_local int g_blink_unixsock_vmid = 0;

// ---- In-process connected-pair data path -----------------------------------
// socketpair() is unsupported on the emscripten host, and even a pipe-pair would
// not be poll-coherent across worker threads. So a connected pair is a shared
// UnixConn with two byte rings; each endpoint reads one ring and writes the
// other. Readiness is the inbound ring's count (shared memory, cross-thread
// coherent). A real pipe read-end backs each endpoint fd so it stays a valid,
// closable, distinct fd, but no data flows through that pipe.

#define UNIX_RING_SZ  (1 << 18)  // 256 KiB per direction; X protocol bursts fit

struct UnixRing {
  unsigned char buf[UNIX_RING_SZ];
  volatile unsigned head;  // write index (producer)
  volatile unsigned tail;  // read index (consumer)
};

struct UnixConn {
  struct UnixRing a2b;  // bytes written by endpoint A, read by endpoint B
  struct UnixRing b2a;  // bytes written by endpoint B, read by endpoint A
  volatile int refs;    // 2 while both ends open; entry freed at 0
  volatile int a_open;
  volatile int b_open;
};

#define UNIX_MAX_CONNFDS 512
struct UnixConnFd {
  int fd;                  // host fd handed to this endpoint (-1 = free)
  int vmid;                // owning VM (fd numbers collide across VMs)
  int wake_wr;             // backing pipe write end (parked; never written)
  struct UnixConn *conn;   // shared connection
  int side;                // 0 = side A, 1 = side B
};
static struct UnixConnFd g_connfds[UNIX_MAX_CONNFDS];

static struct UnixConnFd *FindConnFd(int fd) {
  for (int i = 0; i < UNIX_MAX_CONNFDS; i++)
    if (g_connfds[i].fd == fd && g_connfds[i].conn &&
        g_connfds[i].vmid == g_blink_unixsock_vmid)
      return &g_connfds[i];
  return 0;
}

static struct UnixConnFd *AllocConnFd(void) {
  for (int i = 0; i < UNIX_MAX_CONNFDS; i++)
    if (!g_connfds[i].conn) return &g_connfds[i];
  return 0;
}

static unsigned RingUsed(struct UnixRing *r) { return r->head - r->tail; }
static unsigned RingFree(struct UnixRing *r) { return UNIX_RING_SZ - RingUsed(r); }

static size_t RingWrite(struct UnixRing *r, const unsigned char *p, size_t n) {
  size_t w = 0;
  unsigned freeb = RingFree(r);
  if (n > freeb) n = freeb;
  while (w < n) {
    unsigned pos = r->head & (UNIX_RING_SZ - 1);
    size_t chunk = UNIX_RING_SZ - pos;
    if (chunk > n - w) chunk = n - w;
    memcpy(r->buf + pos, p + w, chunk);
    r->head += chunk;
    w += chunk;
  }
  return w;
}

static size_t RingRead(struct UnixRing *r, unsigned char *p, size_t n) {
  size_t got = 0;
  unsigned used = RingUsed(r);
  if (n > used) n = used;
  while (got < n) {
    unsigned pos = r->tail & (UNIX_RING_SZ - 1);
    size_t chunk = UNIX_RING_SZ - pos;
    if (chunk > n - got) chunk = n - got;
    memcpy(p + got, r->buf + pos, chunk);
    r->tail += chunk;
    got += chunk;
  }
  return got;
}

// Endpoint's inbound (read) and outbound (write) ring for its side.
static struct UnixRing *ConnInRing(struct UnixConnFd *c) {
  return c->side == 0 ? &c->conn->b2a : &c->conn->a2b;
}
static struct UnixRing *ConnOutRing(struct UnixConnFd *c) {
  return c->side == 0 ? &c->conn->a2b : &c->conn->b2a;
}
static int ConnPeerOpen(struct UnixConnFd *c) {
  return c->side == 0 ? c->conn->b_open : c->conn->a_open;
}

// Which concurrent VM is currently executing (set by blinkenlib on vm switch).
// close() is VM-scoped: a close in VM-B must not free VM-A's socket entry even
// if the guest fd numbers collide across the two VMs' fd spaces. Listener LOOKUP
// stays global so a client VM can find the server VM's listener by path.
// Thread-local: each VM thread (server/client) has its own current vmid, so the
// listener-readable + close VM-scoping checks use THIS thread's VM, not whichever
// VM the main thread spawned last (a shared global got clobbered to the client's
// vmid, breaking the server thread's listener-readiness match).
// (g_blink_unixsock_vmid is defined near the top of this file.)

// Match by (vmid, fd): guest fd numbers can collide across concurrent VMs, so a
// socket op must only see the CURRENT VM's own entry.
static struct UnixSock *FindByFd(int fd) {
  for (int i = 0; i < UNIX_MAX_SOCKS; i++)
    if (g_socks[i].state != UNIX_FREE && g_socks[i].fd == fd &&
        g_socks[i].vmid == g_blink_unixsock_vmid)
      return &g_socks[i];
  return 0;
}

static struct UnixSock *AllocSlot(int fd) {
  for (int i = 0; i < UNIX_MAX_SOCKS; i++) {
    if (g_socks[i].state == UNIX_FREE) {
      struct UnixSock *s = &g_socks[i];
      memset(s, 0, sizeof(*s));
      s->fd = fd;
      s->wake_wr = -1;
      s->vmid = g_blink_unixsock_vmid;
      s->state = UNIX_OPEN;
      for (int j = 0; j < UNIX_MAX_BACKLOG; j++) s->pending[j] = -1;
      return s;
    }
  }
  return 0;
}

static struct UnixSock *FindListenerByPath(const char *path) {
  for (int i = 0; i < UNIX_MAX_SOCKS; i++)
    if (g_socks[i].state == UNIX_LISTENING && !strcmp(g_socks[i].path, path))
      return &g_socks[i];
  return 0;
}

// Shared-memory readiness for a tracked LISTENER fd (cross-thread coherent),
// bypassing the emscripten host pipe whose poll is not synchronized across
// worker threads. Match by fd within the current VM (the server polls its own
// listener fd). 1 = pending conn, 0 = listener but idle, -1 = not a listener.
int blink_unix_listener_readable(int fd) {
  for (int i = 0; i < UNIX_MAX_SOCKS; i++)
    if (g_socks[i].state == UNIX_LISTENING && g_socks[i].fd == fd &&
        g_socks[i].vmid == g_blink_unixsock_vmid) {
      if (g_socks[i].npending > 0) {
        char b[120];
        snprintf(b, sizeof(b), "listener_readable HIT fd=%d vmid=%d npending=%d",
                 fd, g_blink_unixsock_vmid, g_socks[i].npending);
        USMARK(b);
      }
      return g_socks[i].npending > 0 ? 1 : 0;
    }
  // Not matched as a listener in THIS vm. Log once-ish what listeners exist so we
  // can tell whether the poll fd, the vmid, or the registry visibility is wrong.
  {
    static int dumped = 0;
    if (!dumped) {
      dumped = 1;
      char b[160];
      for (int i = 0; i < UNIX_MAX_SOCKS; i++)
        if (g_socks[i].state == UNIX_LISTENING) {
          snprintf(b, sizeof(b),
                   "listener_readable MISS qfd=%d qvmid=%d | LISTENER fd=%d vmid=%d path=%s npending=%d",
                   fd, g_blink_unixsock_vmid, g_socks[i].fd, g_socks[i].vmid,
                   g_socks[i].path, g_socks[i].npending);
          USMARK(b);
        }
    }
  }
  return -1;
}

int blink_unix_socket(int domain, int type, int protocol) {
  USDBG("socket(domain=%d type=%d proto=%d) AF_UNIX=%d", domain, type, protocol,
        AF_UNIX);
  if (domain != AF_UNIX) return socket(domain, type, protocol);
  // Back the socket fd with a pipe: the read end is the caller's fd (real,
  // pollable, closable); the write end is kept so connect() can poke a wakeup
  // byte that makes the listener fd readable to poll()/the epoll shim.
  int pp[2];
  if (pipe(pp) != 0) { USDBG("socket: pipe() failed errno=%d", errno); return -1; }
  struct UnixSock *s = AllocSlot(pp[0]);
  if (!s) { close(pp[0]); close(pp[1]); errno = EMFILE; USDBG("socket: no slot"); return -1; }
  s->wake_wr = pp[1];
  USDBG("socket -> fd=%d (wake_wr=%d)", pp[0], pp[1]);
  return pp[0];
}

// Build a stable string key for a unix address into `out` (size UNIX_PATH_MAX).
// Handles both filesystem paths (NUL-terminated sun_path) and Linux abstract
// sockets (sun_path[0] == '\0', name in the bytes that follow up to addrlen).
// Returns 0 on success, -1 on a malformed address.
static int UnixKey(const struct sockaddr *addr, socklen_t len, char *out) {
  if (!addr || addr->sa_family != AF_UNIX) return -1;
  const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
  size_t base = offsetof(struct sockaddr_un, sun_path);
  if (len < (socklen_t)base) return -1;
  size_t plen = (size_t)len - base;
  if (plen == 0) {  // unnamed
    out[0] = 0;
    return 0;
  }
  if (un->sun_path[0] == '\0') {
    // Abstract: prefix '@' then the raw bytes after the leading NUL.
    size_t n = plen - 1;
    if (n > UNIX_PATH_MAX - 2) n = UNIX_PATH_MAX - 2;
    out[0] = '@';
    memcpy(out + 1, un->sun_path + 1, n);
    out[1 + n] = 0;
  } else {
    size_t n = strnlen(un->sun_path, plen);
    if (n > UNIX_PATH_MAX - 1) n = UNIX_PATH_MAX - 1;
    memcpy(out, un->sun_path, n);
    out[n] = 0;
  }
  return 0;
}

int blink_unix_bind(int fd, const struct sockaddr *addr, socklen_t len) {
  struct UnixSock *s = FindByFd(fd);
  USDBG("bind(fd=%d) tracked=%d fam=%d", fd, s ? 1 : 0,
        addr ? addr->sa_family : -1);
  if (!s) return bind(fd, addr, len);  // not ours -> libc
  char key[UNIX_PATH_MAX];
  if (UnixKey(addr, len, key) != 0) { errno = EINVAL; return -1; }
  USDBG("bind path='%s'", key);
  if (key[0] && FindListenerByPath(key)) { errno = EADDRINUSE; return -1; }
  strncpy(s->path, key, UNIX_PATH_MAX - 1);
  s->path[UNIX_PATH_MAX - 1] = 0;
  s->bound = 1;
  return 0;
}

int blink_unix_listen(int fd, int backlog) {
  struct UnixSock *s = FindByFd(fd);
  USDBG("listen(fd=%d) tracked=%d path='%s'", fd, s ? 1 : 0,
        s ? s->path : "(none)");
  if (!s) return listen(fd, backlog);
  (void)backlog;
  if (!s->bound) { errno = EINVAL; return -1; }  // must bind() first
  s->state = UNIX_LISTENING;
  {
    int n = 0;
    for (int i = 0; i < UNIX_MAX_SOCKS; i++) if (g_socks[i].state != UNIX_FREE) n++;
    USDBG("listen OK vmid=%d total-live-entries=%d &g_socks=%p", g_blink_unixsock_vmid, n, (void*)g_socks);
  }
  return 0;
}

int blink_unix_connect(int fd, const struct sockaddr *addr, socklen_t len) {
  struct UnixSock *s = FindByFd(fd);
  if (!s) return connect(fd, addr, len);
  char key[UNIX_PATH_MAX];
  if (UnixKey(addr, len, key) != 0) { errno = EINVAL; return -1; }
  USDBG("connect path='%s'", key);
  { char b[160]; snprintf(b, sizeof(b), "connect vmid=%d path=%s", g_blink_unixsock_vmid, key); USMARK(b); }
  struct UnixSock *l = FindListenerByPath(key);
  USMARK(l ? "connect: listener FOUND" : "connect: listener NOT FOUND (refused)");
  if (!l) {
    int n = 0;
    for (int i = 0; i < UNIX_MAX_SOCKS; i++) if (g_socks[i].state != UNIX_FREE) n++;
    USDBG("connect-refused vmid=%d total-live-entries=%d &g_socks=%p", g_blink_unixsock_vmid, n, (void*)g_socks);
    // Dump the registry so we can see whether the server's listener is visible
    // here (shared g_socks across VMs) or not.
    for (int di = 0; di < UNIX_MAX_SOCKS; di++)
      if (g_socks[di].state != UNIX_FREE)
        USDBG("  registry[%d] state=%d fd=%d path='%s'", di,
              (int)g_socks[di].state, g_socks[di].fd, g_socks[di].path);
    errno = ECONNREFUSED; return -1;
  }
  if (l->npending >= UNIX_MAX_BACKLOG) { errno = EAGAIN; return -1; }
  // Allocate a shared connection (two byte rings) for this client/server pair.
  // socketpair() is unsupported on the emscripten host, so the rings ARE the
  // data channel; read/write are routed through blink_unix_readv/writev.
  struct UnixConn *conn = (struct UnixConn *)calloc(1, sizeof(struct UnixConn));
  if (!conn) { errno = ENOMEM; return -1; }
  conn->refs = 2; conn->a_open = 1; conn->b_open = 1;
  // The CLIENT keeps its existing fd as endpoint A: reuse its backing pipe
  // read-end (valid/pollable/closable) but route its data through the rings.
  struct UnixConnFd *ca = AllocConnFd();
  if (!ca) { free(conn); errno = EMFILE; return -1; }
  ca->fd = fd; ca->vmid = g_blink_unixsock_vmid; ca->wake_wr = s->wake_wr;
  ca->conn = conn; ca->side = 0;
  // The client socket entry is now a connected endpoint tracked in g_connfds;
  // release its listener-table slot (keep the pipe fd alive via ca->wake_wr).
  s->wake_wr = -1; s->state = UNIX_FREE; s->fd = -1;
  // Hand the shared connection to the listener's accept queue (server makes its
  // own endpoint-B fd in accept()).
  l->pending[l->npending++] = 0;  // slot marker (unused int)
  l->pconn[l->npending - 1] = conn;
  // Wake the listener's poll via shared-memory readiness (npending>0); also poke
  // its backing pipe in case anything still polls it directly.
  if (l->wake_wr >= 0) { char b = 1; (void)write(l->wake_wr, &b, 1); }
  return 0;
}

int blink_unix_accept(int fd, struct sockaddr *addr, socklen_t *len) {
  struct UnixSock *s = FindByFd(fd);
  { char b[120]; snprintf(b, sizeof(b), "accept fd=%d vmid=%d tracked=%d npending=%d", fd, g_blink_unixsock_vmid, s?1:0, s?s->npending:-1); USMARK(b); }
  USDBG("accept(fd=%d) vmid=%d tracked=%d npending=%d", fd,
        g_blink_unixsock_vmid, s ? 1 : 0, s ? s->npending : -1);
  if (!s) return accept(fd, addr, len);
  if (s->state != UNIX_LISTENING) { errno = EINVAL; return -1; }
  if (s->npending == 0) { errno = EAGAIN; return -1; }  // nonblocking: nothing yet
  struct UnixConn *conn = (struct UnixConn *)s->pconn[0];
  for (int i = 1; i < s->npending; i++) {
    s->pending[i - 1] = s->pending[i];
    s->pconn[i - 1] = s->pconn[i];
  }
  s->npending--;
  s->pending[s->npending] = -1;
  s->pconn[s->npending] = 0;
  // Build endpoint B: a fresh backing pipe read-end (valid/closable fd) whose
  // data is routed through the shared rings. The server reads b2a / writes a2b.
  int pp[2];
  if (pipe(pp) != 0) { errno = EMFILE; return -1; }
  struct UnixConnFd *cb = AllocConnFd();
  if (!cb) { close(pp[0]); close(pp[1]); conn->b_open = 0; errno = EMFILE; return -1; }
  cb->fd = pp[0]; cb->vmid = g_blink_unixsock_vmid; cb->wake_wr = pp[1];
  cb->conn = conn; cb->side = 1;
  USDBG("accept -> endpoint-B fd=%d vmid=%d", pp[0], g_blink_unixsock_vmid);
  // Drain one readiness byte (written by connect) so the listener fd's poll
  // level matches the remaining queue depth.
  { char b; (void)read(s->fd, &b, 1); }
  if (addr && len) {
    // Report an empty unix address (clients do not rely on the peer path here).
    if (*len >= (socklen_t)sizeof(sa_family_t)) {
      addr->sa_family = AF_UNIX;
      *len = sizeof(sa_family_t);
    }
  }
  { char b[64]; snprintf(b, sizeof(b), "accept RETURN fd=%d", cb->fd); USMARK(b); }
  return cb->fd;  // connected endpoint, data via shared rings
}

// Xtrans calls setsockopt(SO_REUSEADDR), getsockopt(SO_ERROR), getsockname()
// on the listener fd. Our fd is a pipe, so the libc socket-option calls would
// fail with ENOTSOCK and Xtrans treats that as "Unable to open socket". For
// tracked fds these are no-ops / synthesized; untracked fds fall through.
int blink_unix_setsockopt(int fd, int level, int optname, const void *optval,
                          socklen_t optlen) {
  if (FindByFd(fd) || FindConnFd(fd)) { USDBG("setsockopt(fd=%d lvl=%d opt=%d) noop", fd, level, optname); return 0; }
  return setsockopt(fd, level, optname, optval, optlen);
}

int blink_unix_getsockopt(int fd, int level, int optname, void *optval,
                          socklen_t *optlen) {
  if (FindByFd(fd) || FindConnFd(fd)) {
    // SO_ERROR (and friends) -> 0; report a 4-byte zero where there's room.
    if (optval && optlen && *optlen >= (socklen_t)sizeof(int)) {
      *(int *)optval = 0;
      *optlen = sizeof(int);
    } else if (optlen) {
      *optlen = 0;
    }
    USDBG("getsockopt(fd=%d lvl=%d opt=%d) ->0", fd, level, optname);
    return 0;
  }
  return getsockopt(fd, level, optname, optval, optlen);
}

int blink_unix_getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
  struct UnixSock *s = FindByFd(fd);
  struct UnixConnFd *c = s ? 0 : FindConnFd(fd);
  if (!s && !c) return getsockname(fd, addr, len);
  if (c) {  // connected endpoint: report a unix family with an empty path
    if (addr && len && *len >= (socklen_t)sizeof(sa_family_t)) {
      addr->sa_family = AF_UNIX;
      *len = sizeof(sa_family_t);
    }
    return 0;
  }
  if (addr && len) {
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, s->path, sizeof(un.sun_path) - 1);
    socklen_t n = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                              strlen(un.sun_path) + 1);
    if (n > *len) n = *len;
    memcpy(addr, &un, n);
    *len = n;
  }
  return 0;
}

// --- connected-pair readiness + data path ----------------------------------

int blink_unix_conn_readable(int fd) {
  struct UnixConnFd *c = FindConnFd(fd);
  if (!c) return -1;
  if (RingUsed(ConnInRing(c)) > 0) return 1;
  // Peer closed with no buffered data -> readable (read returns EOF), so the X
  // server's poll wakes and read() returns 0 rather than blocking forever.
  if (!ConnPeerOpen(c)) return 1;
  return 0;
}

ssize_t blink_unix_readv(int fd, const struct iovec *iov, int iovcnt) {
  struct UnixConnFd *c = FindConnFd(fd);
  if (!c) return readv(fd, iov, iovcnt);
  struct UnixRing *r = ConnInRing(c);
  { static int rc2 = 0; if (rc2 < 20) { rc2++; char b[96];
    snprintf(b, sizeof(b), "readv ENTER fd=%d side=%d vmid=%d used=%u peeropen=%d",
             fd, c->side, g_blink_unixsock_vmid, RingUsed(r), ConnPeerOpen(c)); USMARK(b); } }
  if (RingUsed(r) == 0) {
    if (!ConnPeerOpen(c)) return 0;  // EOF
    errno = EAGAIN;                  // nonblocking: caller polls + retries
    return -1;
  }
  ssize_t total = 0;
  for (int i = 0; i < iovcnt && RingUsed(r) > 0; i++) {
    size_t got = RingRead(r, (unsigned char *)iov[i].iov_base, iov[i].iov_len);
    total += (ssize_t)got;
    if (got < iov[i].iov_len) break;
  }
  { char b[80]; snprintf(b, sizeof(b), "readv fd=%d side=%d got=%zd", fd, c->side, total); USMARK(b); }
  return total;
}

ssize_t blink_unix_writev(int fd, const struct iovec *iov, int iovcnt) {
  struct UnixConnFd *c = FindConnFd(fd);
  if (!c) return writev(fd, iov, iovcnt);
  if (!ConnPeerOpen(c)) { errno = EPIPE; return -1; }
  struct UnixRing *r = ConnOutRing(c);
  ssize_t total = 0;
  for (int i = 0; i < iovcnt; i++) {
    if (RingFree(r) == 0) break;
    size_t w = RingWrite(r, (const unsigned char *)iov[i].iov_base,
                         iov[i].iov_len);
    total += (ssize_t)w;
    if (w < iov[i].iov_len) break;
  }
  if (total == 0) { errno = EAGAIN; return -1; }
  { char b[80]; snprintf(b, sizeof(b), "writev fd=%d side=%d put=%zd", fd, c->side, total); USMARK(b); }
  return total;
}

ssize_t blink_unix_recvmsg(int fd, struct msghdr *msg, int flags) {
  struct UnixConnFd *c = FindConnFd(fd);
  if (!c) return recvmsg(fd, msg, flags);
  { static int rmc = 0; if (rmc < 12) { rmc++; char b[64];
    snprintf(b, sizeof(b), "recvmsg fd=%d side=%d", fd, c->side); USMARK(b); } }
  (void)flags;
  ssize_t n = blink_unix_readv(fd, msg->msg_iov, (int)msg->msg_iovlen);
  if (n >= 0) { msg->msg_controllen = 0; msg->msg_flags = 0; }
  return n;
}

ssize_t blink_unix_sendmsg(int fd, const struct msghdr *msg, int flags) {
  struct UnixConnFd *c = FindConnFd(fd);
  if (!c) return sendmsg(fd, msg, flags);
  (void)flags;
  return blink_unix_writev(fd, msg->msg_iov, (int)msg->msg_iovlen);
}

int blink_unix_poll(struct pollfd *fds, unsigned long nfds, int timeout) {
  // Replace tracked fds (listeners + connected endpoints) with shared-memory
  // readiness; poll the rest via libc. Cross-thread coherent.
  int ready = 0, has_untracked = 0;
  for (unsigned long i = 0; i < nfds; i++) {
    fds[i].revents = 0;
    int lr = blink_unix_listener_readable(fds[i].fd);
    if (lr >= 0) {
      static int lpc = 0;
      if (lpc < 8) { lpc++; char b[80];
        snprintf(b, sizeof(b), "poll listener fd=%d vmid=%d lr=%d", fds[i].fd, g_blink_unixsock_vmid, lr); USMARK(b); }
      if (lr == 1 && (fds[i].events & POLLIN)) { fds[i].revents |= POLLIN; ready++; } continue;
    }
    int cr = blink_unix_conn_readable(fds[i].fd);
    if (cr >= 0) {
      static int pc = 0;
      if (pc < 30) { pc++; char b[96];
        snprintf(b, sizeof(b), "poll conn fd=%d vmid=%d ev=%d cr=%d", fds[i].fd,
                 g_blink_unixsock_vmid, fds[i].events, cr); USMARK(b); }
      if (cr == 1 && (fds[i].events & POLLIN)) { fds[i].revents |= POLLIN; ready++; }
      if (fds[i].events & POLLOUT) { fds[i].revents |= POLLOUT; ready++; }  // ring rarely full
      continue;
    }
    has_untracked = 1;
  }
  if (ready > 0) return ready;
  if (!has_untracked) return 0;  // only tracked fds, none ready (caller re-polls)
  // Cap the libc poll so we re-check shared readiness promptly.
  int to = timeout; if (to < 0 || to > 20) to = 20;
  int rc = poll(fds, (nfds_t)nfds, to);
  // Re-stamp tracked fds after the libc poll (they were passed through unchanged).
  for (unsigned long i = 0; i < nfds; i++) {
    int cr = blink_unix_conn_readable(fds[i].fd);
    if (cr >= 0) {
      short add = 0;
      if (cr == 1 && (fds[i].events & POLLIN) && !(fds[i].revents & POLLIN)) add |= POLLIN;
      if ((fds[i].events & POLLOUT) && !(fds[i].revents & POLLOUT)) add |= POLLOUT;
      if (add) { if (!fds[i].revents) rc++; fds[i].revents |= add; }
    }
  }
  return rc;
}

int blink_unix_getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
  if (FindConnFd(fd)) { char b[64]; snprintf(b, sizeof(b), "getpeername conn fd=%d vmid=%d", fd, g_blink_unixsock_vmid); USMARK(b); }
  if (FindByFd(fd) || FindConnFd(fd)) {
    // In-process unix peer: report AF_UNIX with an empty path. Xtrans uses this
    // only for local access control, which our loopback layer always permits.
    if (addr && len && *len >= (socklen_t)sizeof(sa_family_t)) {
      addr->sa_family = AF_UNIX;
      *len = sizeof(sa_family_t);
    }
    return 0;
  }
  return getpeername(fd, addr, len);
}

int blink_unix_close(int fd) {
  struct UnixConnFd *c = FindConnFd(fd);
  if (c) {
    { char b[80]; snprintf(b, sizeof(b), "close conn fd=%d side=%d vmid=%d", fd, c->side, g_blink_unixsock_vmid); USMARK(b); }
    // Mark this endpoint closed so the peer sees EOF; free the conn at refs 0.
    if (c->side == 0) c->conn->a_open = 0; else c->conn->b_open = 0;
    if (--c->conn->refs <= 0) free(c->conn);
    if (c->wake_wr >= 0) close(c->wake_wr);
    c->conn = 0; c->fd = -1; c->wake_wr = -1;
    return close(fd);
  }
  struct UnixSock *s = FindByFd(fd);
  if (s) {
    if (s->wake_wr >= 0) close(s->wake_wr);
    s->wake_wr = -1;
    s->state = UNIX_FREE;
    s->fd = -1;
  }
  return close(fd);
}
#endif /* __EMSCRIPTEN__ */
