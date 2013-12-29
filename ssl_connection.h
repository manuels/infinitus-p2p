#ifndef __SSL_CONNECTION__
#define __SSL_CONNECTION__

#include <openssl/ssl.h>
#include <openssl/crypto.h>

#include "signal.h"

struct SslConnection_ {
	SSL* ssl;

	int is_caller;
	int secure_sockets[2];
	int insecure_socket;
	int handshake_done;

	char *pem_remote_key;

	BIO *rbio;
	BIO *wbio;

	Signal *on_authentication_failed;
	Signal *on_data_received;
};

typedef struct SslConnection_ SslConnection;

SslConnection *
ssl_connection_new(int insecure_socket);

const int
ssl_connection_set_is_caller(SslConnection *conn, int is_caller);

const int
ssl_connection_is_caller(SslConnection *conn);

int
ssl_connection_connect(SslConnection *conn);

size_t
ssl_connection_send(SslConnection *conn, char *buf, size_t len);

void
ssl_connection_on_connected(SslConnection *conn, Callback cb, void *arg);

void
ssl_connection_on_disconnected(SslConnection *conn, Callback cb, void *arg);

void
ssl_connection_on_data_received(SslConnection *conn, Callback cb, void *arg);

int
ssl_connection_set_local_key(SslConnection *conn, char const *pem_key_pair);

int
ssl_connection_set_remote_key(SslConnection *conn, char *pem_public_key);

const char const *
ssl_connection_get_remote_key(SslConnection *conn);

const int
ssl_connection_get_secure_socket(SslConnection *conn);

int
ssl_connection_receive_encrypted_data(SslConnection *conn);

int
ssl_connection_send_secret_data(SslConnection *conn);

void
ssl_connection_on_authentication_failed(SslConnection *conn,
                                        Callback cb,
                                        void* user_arg);

void
ssl_connection_free(SslConnection *conn);

#endif
