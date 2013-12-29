#include "socket_poll.h"

SocketPoll *
socket_poll_new() {
	SocketPoll *sp = (SocketPoll *) malloc(sizeof(SocketPoll));
	memset(sp, 0, sizeof(SocketPoll));

	return sp;
}

void
socket_poll_free(SocketPoll *sp) {
	close(sp->control_socket[0]);

	free(sp);
}
