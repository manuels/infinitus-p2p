#include "ice_connection.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const gchar *
candidate_type_name[] = {"host", "srflx", "prflx", "relay"};

static const int
component_id = 1;

static void
cb_nice_recv(NiceAgent *agent,
             guint stream_id,
             guint component_id,
             guint len,
             gchar *buf,
             gpointer user_data)
{
	IceConnection *ice = (IceConnection *) user_data;

	send(ice->sockets[0], buf, len, 0);

	signal_emit(ice->on_data_received, ice, buf, len);
}


static void
cb_candidate_gathering_done(NiceAgent *agent,
                            guint      stream_id,
                            gpointer   user_data)
{
	IceConnection *ice = (IceConnection *) user_data;
	signal_emit(ice->on_candidates_gathered, ice);
}

static void
cb_component_state_changed(NiceAgent *agent,
                           guint      stream_id,
                           guint      component_id,
                           guint      state,
                           gpointer   user_data)
{
	IceConnection *ice = (IceConnection *) user_data;

	switch(state) {
		case NICE_COMPONENT_STATE_READY:
			signal_emit(ice->on_connected, ice);
		break;

		case NICE_COMPONENT_STATE_FAILED:
		case NICE_COMPONENT_STATE_DISCONNECTED:
			signal_emit(ice->on_disconnected, ice);
		break;
	}
}

static gboolean
cb_send_data(GIOChannel *source,
             GIOCondition condition,
             gpointer user_data)
{
	IceConnection *ice = (IceConnection *) user_data;

	static char buf[4*1024];

	struct iovec iov[1];
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);

	struct msghdr msg;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = 0;
	msg.msg_controllen = 0;

	size_t len = recvmsg(ice->sockets[0], &msg, MSG_DONTWAIT);
	g_assert(len > 0);

	ice_connection_send(ice, buf, len);

	return TRUE;
}

IceConnection *
ice_connection_new(GMainContext *ctx) {
	IceConnection *ice = (IceConnection *) malloc(sizeof(IceConnection));

	memset(ice, 0, sizeof(IceConnection));

	if(socketpair(AF_UNIX, SOCK_DGRAM, AF_UNSPEC, ice->sockets) != 0) {
		free(ice);
		return NULL;
	}

	GIOChannel *io;
	io = g_io_channel_unix_new(ice->sockets[0]);
	guint source_id = g_io_add_watch(io, G_IO_IN, cb_send_data, ice);

	ice->on_connected = signal_new();
	ice->on_disconnected = signal_new();
	ice->on_candidates_gathered = signal_new();
	ice->on_data_received = signal_new();

	ice->agent = nice_agent_new(ctx, NICE_COMPATIBILITY_RFC5245);

	g_signal_connect(G_OBJECT(ice->agent), "candidate-gathering-done",
	                 G_CALLBACK(cb_candidate_gathering_done), ice);
	g_signal_connect(G_OBJECT(ice->agent), "component-state-changed",
	                 G_CALLBACK(cb_component_state_changed), ice);

	ice->stream_id = nice_agent_add_stream(ice->agent, 1);

	nice_agent_attach_recv(ice->agent,
	                       ice->stream_id,
	                       component_id,
	                       ctx,
	                       cb_nice_recv,
	                       ice);

	return ice;
}

void
ice_connection_free(IceConnection *ice) {
	g_object_unref(ice->agent);
	signal_free(ice->on_connected);
	signal_free(ice->on_disconnected);
	signal_free(ice->on_candidates_gathered);
	signal_free(ice->on_data_received);

	free(ice);
}

int
ice_connection_gather_candidates(IceConnection *ice) {
	return nice_agent_gather_candidates(ice->agent, ice->stream_id) == TRUE;
}

void
ice_connection_on_data_received(IceConnection *ice,
                                Callback cb,
                                void *user_arg) {
	signal_on(ice->on_data_received, cb, user_arg);
}

void
ice_connection_on_connected(IceConnection *ice,
                            Callback cb,
                            void *user_arg) {
	signal_on(ice->on_connected, cb, user_arg);
}

void
ice_connection_on_disconnected(IceConnection *ice,
                               Callback cb,
                               void *user_arg) {
	signal_on(ice->on_disconnected, cb, user_arg);
}

void
ice_connection_on_candidates_gathered(IceConnection *ice,
                                      Callback cb,
                                      void *user_arg) {
	signal_on(ice->on_candidates_gathered, cb, user_arg);
}

static void
stringify_candidate(gpointer data, gpointer user_data) {
	NiceCandidate *cand = (NiceCandidate *) data;
	char **res = (char **) user_data;

	g_assert(cand != NULL);
	g_assert(res != NULL);

	gchar ipaddr[INET6_ADDRSTRLEN];
	nice_address_to_string(&cand->addr, ipaddr);

	guint port;
	port = nice_address_get_port(&cand->addr);

	char *old_res = *res;
	*res = g_strdup_printf("%s %s,%u,%s,%u,%s",
	                       *res,
	                       cand->foundation,
	                       cand->priority,
	                       ipaddr,
	                       port,
	                       candidate_type_name[cand->type]);
	g_free(old_res);
}

char *
ice_connection_local_credentials(IceConnection *ice) {
	g_assert(ice != NULL);

	char *res = NULL;
	gchar *ufrag;
	gchar *pwd;

	if(!nice_agent_get_local_credentials(ice->agent,
	                                     ice->stream_id,
	                                     &ufrag,
	                                     &pwd))
		goto out;

	res = g_strdup_printf("%s %s", ufrag, pwd);

	GSList *candidates = NULL;
	candidates = nice_agent_get_local_candidates(ice->agent,
	                                             ice->stream_id,
	                                             component_id);
	if(candidates != NULL)
		g_slist_foreach(candidates, stringify_candidate, &res);
	else {
		g_free(res);
		res = NULL;
	}

out:
	if(ufrag != NULL)
		g_free(ufrag);
	if(pwd != NULL)
		g_free(pwd);
	g_slist_free_full(candidates, g_free);

	return res;
}

static NiceCandidate *
parse_candidate(gchar *str,
                guint stream_id) {
	g_assert(str);

	NiceCandidate *cand = NULL;
	NiceCandidateType ntype;

	int res;
	int i;
	gchar foundation[100];
	guint32 priority;
	gchar ipaddr[100];
	guint port;
	gchar type_str[100];

	res = sscanf(str,
	             "%99[^,],%u,%99[^,],%u,%99[^ ]",
	             foundation,
	             &priority,
	             ipaddr,
	             &port,
	             type_str);
	if(res != 5)
		goto out;

	// parse candidate type
	for (i = 0; i < G_N_ELEMENTS(candidate_type_name); i++) {
		if (strcmp(type_str, candidate_type_name[i]) == 0) {
			ntype = i;
			break;
		}
	}
	if(ntype == G_N_ELEMENTS(candidate_type_name))
		goto out;

	// setup nice candidate
	cand = nice_candidate_new(ntype);
	cand->component_id = component_id;
	cand->stream_id = stream_id;
	cand->transport = NICE_CANDIDATE_TRANSPORT_UDP;
	strncpy(cand->foundation, foundation, NICE_CANDIDATE_MAX_FOUNDATION);
	cand->priority = priority;

	if(!nice_address_set_from_string(&cand->addr, ipaddr)) {
		nice_candidate_free(cand);
		cand = NULL;
		goto out;
	}
	nice_address_set_port(&cand->addr, port);

out:
	return cand;
}

static int
parse_credentials(IceConnection *ice,
                  char const *credentials,
                  gchar **ufrag,
                  gchar **pwd,
                  GSList **candidate_list) {
	gchar **elements = NULL;
	NiceCandidate *cand;
	int res = 0;

	elements = g_strsplit(credentials, " ", 0);

	if(g_strv_length(elements) < 3)
		goto out;

	*ufrag = g_strdup(elements[0]);
	*pwd = g_strdup(elements[1]);
	*candidate_list = NULL;

	int i;
	for(i = 2; elements[i] != NULL; ++i) {
		cand = parse_candidate(elements[i], ice->stream_id);
		if(cand != NULL)
			*candidate_list = g_slist_append(*candidate_list, cand);
		else
			goto out;
	}

	res = 1;

out:
	g_strfreev(elements);

	return res;
}

int
ice_connection_set_remote_credentials(IceConnection *ice,
                                      char *credentials) {
	GSList *candidates;
	gchar *ufrag;
	gchar *pwd;
	int res = 0;

	if(!parse_credentials(ice, credentials, &ufrag, &pwd, &candidates))
		return 0;

	if(!nice_agent_set_remote_credentials(ice->agent,
	                                      ice->stream_id,
	                                      ufrag,
	                                      pwd))
		goto out;

	int len;
	len = nice_agent_set_remote_candidates(ice->agent,
	                                       ice->stream_id,
	                                       component_id,
	                                       candidates);
	if(len != g_slist_length(candidates))
		goto out;

	res = 1;

out:
	g_free(ufrag);
	g_free(pwd);
	g_slist_free_full(candidates, g_free);

	return res;
}

size_t
ice_connection_send(IceConnection *ice, void *buf, size_t len) {
	return nice_agent_send(ice->agent,
	                       ice->stream_id,
	                       component_id,
	                       len,
	                       buf);
}

const int
ice_connection_get_socket(IceConnection *ice) {
	return ice->sockets[1];
}
