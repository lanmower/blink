#ifndef BLINK_UNIXSOCK_SHIM_H_
#define BLINK_UNIXSOCK_SHIM_H_
#ifdef __EMSCRIPTEN__
// In-process AF_UNIX stream sockets for the emscripten/wasm build. Emscripten's
// libc socket() has no working server-side AF_UNIX (bind/listen/accept) — it
// only bridges client TCP/UDP over WebSocket — so an X server (Xvfb) cannot
// open its /tmp/.X11-unix/Xnn listener. But under blink the X server AND its X
// clients run in the SAME host process, so a loopback AF_UNIX layer backed by
// an in-memory {path -> listener, pending-connection queue} table is enough:
// the real data channel is a socketpair() (which emscripten does provide), and
// bind/listen/accept/connect just route fds through the table. No host network,
// matching the in-page no-external-services constraint.
//
// These wrappers fall through to the libc call for any family other than
// AF_UNIX, so non-unix sockets behave exactly as before.
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

int blink_unix_socket(int domain, int type, int protocol);
int blink_unix_bind(int fd, const struct sockaddr *addr, socklen_t len);
int blink_unix_connect(int fd, const struct sockaddr *addr, socklen_t len);
int blink_unix_listen(int fd, int backlog);
int blink_unix_accept(int fd, struct sockaddr *addr, socklen_t *len);
int blink_unix_close(int fd);
// Cross-thread readiness for a tracked in-process unix LISTENER fd, checked from
// shared memory (npending) instead of an emscripten host pipe (whose poll is not
// coherent across worker threads). Returns: 1 = a connection is pending (POLLIN),
// 0 = tracked listener but nothing pending, -1 = not a tracked listener (caller
// should fall through to the normal host poll). VM-scope-agnostic on purpose:
// any thread polling this fd sees pending connections in the shared registry.
int blink_unix_listener_readable(int fd);
// Data path for in-process connected pairs (socketpair is unsupported on the
// emscripten host). Tracked connected fds carry bytes through shared-memory ring
// buffers, coherent across worker threads; untracked fds fall through to libc.
ssize_t blink_unix_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t blink_unix_writev(int fd, const struct iovec *iov, int iovcnt);
struct pollfd;
int blink_unix_poll(struct pollfd *fds, unsigned long nfds, int timeout);
struct msghdr;
ssize_t blink_unix_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t blink_unix_sendmsg(int fd, const struct msghdr *msg, int flags);
// Readiness of a tracked CONNECTED fd's inbound ring (cross-thread coherent).
// 1 = bytes available, 0 = tracked but empty, -1 = not a tracked connected fd.
int blink_unix_conn_readable(int fd);
// FIONREAD for connected endpoints: writes the inbound ring byte count to *out
// and returns 1 if fd is a tracked connected endpoint, else 0 (fall through).
int blink_unix_fionread(int fd, int *out);
int blink_unix_is_tracked(int fd);
int blink_unix_setsockopt(int fd, int level, int optname, const void *optval,
                          socklen_t optlen);
int blink_unix_getsockopt(int fd, int level, int optname, void *optval,
                          socklen_t *optlen);
int blink_unix_getsockname(int fd, struct sockaddr *addr, socklen_t *len);
int blink_unix_getpeername(int fd, struct sockaddr *addr, socklen_t *len);
int blink_unix_shutdown(int fd, int how);

#endif /* __EMSCRIPTEN__ */
#endif /* BLINK_UNIXSOCK_SHIM_H_ */
