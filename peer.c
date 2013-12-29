#include <string.h>
#include <assert.h>

#include "identity.h"
#include "peer.h"
#include "pem.h"

Peer *
peer_new(Identity *ident,
         char const *pem_remote_public_key) {
	if(ident == NULL)
		return NULL;

	char *parsed_pem = pem_parse_public_key(pem_remote_public_key);
	if(parsed_pem == NULL)
		return NULL;

	Peer *p = (Peer *) malloc(sizeof(Peer));
	assert(p != NULL);

	memset(p, 0, sizeof(Peer));
	p->pem_remote_public_key = parsed_pem;
	p->local_identity = ident;

	p->on_connected = signal_new();
	p->on_disconnected = signal_new();

	return p;
}

void
peer_free(Peer *p) {
	if(p->pem_remote_public_key != NULL)
		free(p->pem_remote_public_key);

	signal_free(p->on_connected);
	signal_free(p->on_disconnected);

	free(p);
}

Identity const *
peer_get_identity(Peer const *p) {
	return p->local_identity;
}

const char const *
peer_get_local_key_pair(Peer const *p) {
	if(p == NULL)
		return NULL;

	Identity const *ident = peer_get_identity(p);
	if(ident == NULL)
		return NULL;

	return identity_get_pem_key_pair(ident);
}

char *
peer_local_public_key(Peer const *p) {
	if(p == NULL)
		return NULL;

	Identity const *ident = peer_get_identity(p);
	if(ident == NULL)
		return NULL;

	return identity_pem_public_key(ident);
}

const char const *
peer_get_remote_public_key(Peer const *p) {
	if(p == NULL)
		return NULL;
	return p->pem_remote_public_key;
}

char *
peer_local_fingerprint_string(Peer const *p) {
	if(p == NULL)
		return NULL;

	Identity const *ident = peer_get_identity(p);
	return identity_fingerprint_string(ident);
}

char *
peer_remote_fingerprint_string(Peer const *p) {
	if(p == NULL)
		return NULL;

	const char *pem = peer_get_remote_public_key(p);
	return pem_fingerprint_string(pem);
}

void
peer_on_connected(Peer *p, Callback cb) {
	signal_on(p->on_connected, cb);
}

void
peer_on_disconnected(Peer *p, Callback cb) {
	signal_on(p->on_disconnected, cb);
}
