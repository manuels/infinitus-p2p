#ifndef __ICE_CONNECTION__
#define __ICE_CONNECTION__

#include <agent.h>
#include <glib.h>

#include <sys/socket.h>

#include "signal.h"

struct IceConnection_ {
	NiceAgent *agent;
	guint stream_id;

	int sockets[2];

	Signal *on_connected;
	Signal *on_disconnected;
	Signal *on_candidates_gathered;
	Signal *on_data_received;
};

typedef struct IceConnection_ IceConnection;

IceConnection *
ice_connection_new(GMainContext *ctx);

void
ice_connection_free(IceConnection *ice);

const int
ice_connection_get_socket(IceConnection *ice);

void
ice_connection_on_data_received(IceConnection *ice,
                                Callback cb,
                                void *user_arg);

void
ice_connection_on_connected(IceConnection *ice,
                            Callback cb,
                          	void *user_arg);

void
ice_connection_on_disconnected(IceConnection *ice,
                               Callback cb,
                               void *user_arg);

void
ice_connection_on_candidates_gathered(IceConnection *ice,
                                      Callback cb,
                                      void *user_arg);

char *
ice_connection_local_credentials(IceConnection *ice);

int
ice_connection_set_remote_credentials(IceConnection *ice,
                                      char *credentials);

int
ice_connection_gather_candidates(IceConnection *ice);

size_t
ice_connection_send(IceConnection *ice, void *buf, size_t len);

#endif