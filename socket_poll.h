#ifndef __SOCKET_POLL_H__
#define __SOCKET_POLL_H__

struct SocketPoll_ {
	int control_sockets[2];
};

typedef SocketPoll struct SocketPoll_;

SocketPoll *
socket_poll_new();

void
socket_poll_free(SocketPoll *sp);

int
socket_poll_forward_socket(SocketPoll *sp,
                           int socket_a,
                           int socket_b);

int
socket_poll_forward_socket_to_callback(SocketPoll   *sp,
                                       int           socket,
                                       SendCallback  cb);

int
socket_poll_add_timeout_function(SocketPoll     *sp,
                                 TimeoutFunc     timeout,
                                 double          timeout_unit_in_sec,
                                 TimeoutCallback cb);

#endif
