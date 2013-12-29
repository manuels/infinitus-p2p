#ifndef __PSEUDO_TCP_CHANNEL__
#define __PSEUDO_TCP_CHANNEL__

#include <pseudotcp.h>

struct PseudoTcpChannel_ {
	int reliable_sockets[2];
	int unreliable_socket;

	PseudoTcpSocket pseudo_tcp;

	Signal *on_connected;
	Signal *on_data_received;
	Signal *on_closed;
};

typedef PseudoTcpChannel struct PseudoTcpChannel_;

PseudoTcpChannel *
pseudo_tcp_channel_new(int unreliable_socket,
                       int conn_id);

void
pseudo_tcp_channel_free(PseudoTcpChannel *);

#endif
