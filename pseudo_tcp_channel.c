#include "pseudo_tcp_channel.h"

static GTimer*
timer = NULL;

static void
update_timer(PseudoTcpChannel *tcp) {
	gboolean res;
	long relative_timeout;
	res = pseudo_tcp_socket_get_next_clock(tcp->pseudo_tcp, &relative_timeout);

	if(res == FALSE)
		return;

	static long last_abs_timeout = -1;
	static PseudoTcpChannel *last_tcp;
	static guint timer = -1;

	if(timer = -1) {
		guint new_timeout = timeout;
	}
	else {
		long abs_time
		if(last_timeout )
		g_source_remove
	}

	timer = g_timeout_add(new_timeout, timedout, tcp);
}

static void
opened(PseudoTcpSocket *s, gpointer user_data) {
	PseudoTcpChannel *tcp = (PseudoTcpChannel *) user_data;
	signal_emit(tcp->on_connected, tcp);
}

static void
readable(PseudoTcpSocket *s, gpointer user_data) {
	PseudoTcpChannel *tcp = (PseudoTcpChannel *) user_data;

	int len;
	static char buf[4*1024];
	len = pseudo_tcp_socket_recv(tcp->pseudo_tcp, buf, sizeof(buf));

	if(len > 0) {
		send(tcp->reliable_sockets[0], buf, len, 0);
		signal_emit(tcp->on_data_received, tcp, buf, len);
	}
}

static void
writable(PseudoTcpSocket *s, gpointer user_data) {
}

static PseudoTcpWriteResult
needs_write(PseudoTcpSocket *tcp,
            const gchar     *buffer,
            guint32          len,
            gpointer         user_data)
{
	PseudoTcpChannel *tcp = (PseudoTcpChannel *) user_data;

	int res = send(tcp->unreliable_socket, buf, len, 0);
	if(res == len)
		return WR_SUCCESS;
	else
		return WR_FAIL;

}

static void
closed(PseudoTcpSocket *s, gpointer user_data) {
	PseudoTcpChannel *tcp = (PseudoTcpChannel *) user_data;
	signal_emit(tcp->on_closed, tcp);
}

PseudoTcpChannel *
pseudo_tcp_channel_new(int unreliable_socket,
                       int conn_id)
{
	PseudoTcpChannel *tcp = (PseudoTcpChannel *) malloc(sizeof(PseudoTcpChannel));
	memset(tcp, 0, sizeof(PseudoTcpChannel));
	
	if(socketpair(AF_UNIX, SOCK_STREAM, AF_UNSPEC, tcp->reliable_sockets) != 0) {
		free(tcp);
		return NULL;
	}

	PseudoTcpCallbacks callbacks;
	callbacks.user_data = tcp;
	callbacks.PseudoTcpOpened = opened;
	callbacks.PseudoTcpReadable = readable;
	callbacks.PseudoTcpWritable = writable;
	callbacks.PseudoTcpClosed = closed;
	callbacks.PseudoTcpWriteResult = needs_write;
	tcp->pseudo_tcp = pseudo_tcp_socket_new(conn_id, &callbacks);

	pseudo_tcp_socket_notify_mtu(tcp->pseudo_tcp, 1400);

	tcp->on_connected = signal_new();
	tcp->on_data_received = signal_new();
	tcp->on_closed = signal_new();

	return tcp;
}

void
pseudo_tcp_channel_free(PseudoTcpChannel *tcp) {
	signal_free(tcp->on_connected);
	signal_free(tcp->on_data_received);

	// TODO: how to free pseudo_tcp?

	free(tcp);
}
