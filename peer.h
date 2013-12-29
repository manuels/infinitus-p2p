#ifndef __PEER_H__
#define __PEER_H__

#include "signal.h"

struct Peer_ {
	char *pem_remote_public_key;
	Identity *local_identity;

	Signal *on_connected;
	Signal *on_disconnected;
	/*ICEConnection *ice;
	SSLConnection *ssl;
	int connection_counter;

	Connection *connections[CONNECTION_MAX];*/
};
typedef struct Peer_ Peer;

Peer *
peer_new(Identity *ident,
         char const *pem_remote_public_key);

void
peer_free(Peer *p);

char *
peer_local_fingerprint_string(Peer const *p);

char *
peer_remote_fingerprint_string(Peer const *p);

#endif
