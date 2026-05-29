#ifdef __EMSCRIPTEN__
#include "blink/unixsock_shim.h"

#include <errno.h>
#include <fcntl.h>
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
  char path[UNIX_PATH_MAX];    // bind path (listeners) — empty otherwise
  int pending[UNIX_MAX_BACKLOG];  // queued server-side fds awaiting accept()
  int npending;
};

static struct UnixSock g_socks[UNIX_MAX_SOCKS];

static struct UnixSock *FindByFd(int fd) {
  for (int i = 0; i < UNIX_MAX_SOCKS; i++)
    if (g_socks[i].state != UNIX_FREE && g_socks[i].fd == fd) return &g_socks[i];
  return 0;
}

static struct UnixSock *AllocSlot(int fd) {
  for (int i = 0; i < UNIX_MAX_SOCKS; i++) {
    if (g_socks[i].state == UNIX_FREE) {
      struct UnixSock *s = &g_socks[i];
      memset(s, 0, sizeof(*s));
      s->fd = fd;
      s->wake_wr = -1;
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
  return 0;
}

int blink_unix_connect(int fd, const struct sockaddr *addr, socklen_t len) {
  struct UnixSock *s = FindByFd(fd);
  if (!s) return connect(fd, addr, len);
  char key[UNIX_PATH_MAX];
  if (UnixKey(addr, len, key) != 0) { errno = EINVAL; return -1; }
  USDBG("connect path='%s'", key);
  struct UnixSock *l = FindListenerByPath(key);
  if (!l) {
    // Dump the registry so we can see whether the server's listener is visible
    // here (shared g_socks across VMs) or not.
    for (int di = 0; di < UNIX_MAX_SOCKS; di++)
      if (g_socks[di].state != UNIX_FREE)
        USDBG("  registry[%d] state=%d fd=%d path='%s'", di,
              (int)g_socks[di].state, g_socks[di].fd, g_socks[di].path);
    errno = ECONNREFUSED; return -1;
  }
  if (l->npending >= UNIX_MAX_BACKLOG) { errno = EAGAIN; return -1; }
  // Real bidirectional data channel between client and server.
  int sp[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
  // Hand the server end to the listener's accept queue.
  l->pending[l->npending++] = sp[1];
  // Turn the client fd into the client end of the pair: dup2 over the backing
  // pipe read-end so the caller's fd number keeps working and now carries data.
  if (dup2(sp[0], fd) < 0) { close(sp[0]); close(sp[1]); l->npending--; return -1; }
  close(sp[0]);
  // The client fd is now a real socketpair end; drop its pipe write side and
  // stop tracking it (libc read/write/close handle it natively from here).
  if (s->wake_wr >= 0) { close(s->wake_wr); s->wake_wr = -1; }
  s->state = UNIX_FREE;
  s->fd = -1;
  // Wake the listener's epoll/poll: write a readiness byte to its read-end so
  // the X server's event loop returns and calls accept().
  if (l->wake_wr >= 0) { char b = 1; (void)write(l->wake_wr, &b, 1); }
  return 0;
}

int blink_unix_accept(int fd, struct sockaddr *addr, socklen_t *len) {
  struct UnixSock *s = FindByFd(fd);
  if (!s) return accept(fd, addr, len);
  if (s->state != UNIX_LISTENING) { errno = EINVAL; return -1; }
  if (s->npending == 0) { errno = EAGAIN; return -1; }  // nonblocking: nothing yet
  int conn = s->pending[0];
  for (int i = 1; i < s->npending; i++) s->pending[i - 1] = s->pending[i];
  s->pending[--s->npending] = -1;
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
  return conn;  // already a connected socketpair end
}

// Xtrans calls setsockopt(SO_REUSEADDR), getsockopt(SO_ERROR), getsockname()
// on the listener fd. Our fd is a pipe, so the libc socket-option calls would
// fail with ENOTSOCK and Xtrans treats that as "Unable to open socket". For
// tracked fds these are no-ops / synthesized; untracked fds fall through.
int blink_unix_setsockopt(int fd, int level, int optname, const void *optval,
                          socklen_t optlen) {
  if (FindByFd(fd)) { USDBG("setsockopt(fd=%d lvl=%d opt=%d) noop", fd, level, optname); return 0; }
  return setsockopt(fd, level, optname, optval, optlen);
}

int blink_unix_getsockopt(int fd, int level, int optname, void *optval,
                          socklen_t *optlen) {
  if (FindByFd(fd)) {
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
  if (!s) return getsockname(fd, addr, len);
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

int blink_unix_close(int fd) {
  struct UnixSock *s = FindByFd(fd);
  if (s) {
    for (int i = 0; i < s->npending; i++)
      if (s->pending[i] >= 0) close(s->pending[i]);
    if (s->wake_wr >= 0) close(s->wake_wr);
    s->wake_wr = -1;
    s->state = UNIX_FREE;
    s->fd = -1;
  }
  return close(fd);
}
#endif /* __EMSCRIPTEN__ */
