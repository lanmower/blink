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

int blink_unix_socket(int domain, int type, int protocol);
int blink_unix_bind(int fd, const struct sockaddr *addr, socklen_t len);
int blink_unix_connect(int fd, const struct sockaddr *addr, socklen_t len);
int blink_unix_listen(int fd, int backlog);
int blink_unix_accept(int fd, struct sockaddr *addr, socklen_t *len);
int blink_unix_close(int fd);
int blink_unix_setsockopt(int fd, int level, int optname, const void *optval,
                          socklen_t optlen);
int blink_unix_getsockopt(int fd, int level, int optname, void *optval,
                          socklen_t *optlen);
int blink_unix_getsockname(int fd, struct sockaddr *addr, socklen_t *len);

#endif /* __EMSCRIPTEN__ */
#endif /* BLINK_UNIXSOCK_SHIM_H_ */
