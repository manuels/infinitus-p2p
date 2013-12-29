#include "pem.h"
#include "ssl_connection.h"

#include <assert.h>
#include <sys/socket.h>
#include <errno.h>
#include <glib.h>

static int ssl_connection_idx;
static SSL_CTX *ssl_ctx = NULL;

static void
cb_info_verbose(SSL *ssl, int where, int ret) {
	const char *str;
	int w = where & ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT) str = "SSL_connect";
	else if (w & SSL_ST_ACCEPT) str = "SSL_accept";
	else str = "undefined";

	if (where & SSL_CB_LOOP)
		printf("%s:%s\n", str, SSL_state_string_long(ssl));
	else if (where & SSL_CB_ALERT) {
		str = (where & SSL_CB_READ) ? "read" : "write";
		printf("SSL3 alert %s:%s:%s\n",
		       str,
		       SSL_alert_type_string_long(ret),
		       SSL_alert_desc_string_long(ret));
	}
	else if (where & SSL_CB_EXIT) {
		if (ret == 0)
			printf("%s:failed in %s\n",
			       str,
			       SSL_state_string_long(ssl));
		else if (ret < 0) {
			printf("%s:error in %s\n",
			       str,
			       SSL_state_string_long(ssl));
		}
	}
}

static void
cb_info(SSL *ssl, int where, int ret) {
	SslConnection* conn = (SslConnection *) SSL_get_ex_data(ssl, ssl_connection_idx);

	int w;
	w = where & ~SSL_ST_MASK;

	if(where & SSL_CB_ALERT)
		signal_emit(conn->on_authentication_failed, conn);

	if(0)
		cb_info_verbose(ssl, where, ret);
}

static int
ssl_handle_bio(SslConnection *conn) {
	size_t pending;

	pending = BIO_pending(conn->wbio);
	//printf("SSL_handle_bio() %i pending wbio %i\n", ssl_connection_is_caller(conn), pending);
	if(pending > 0) {
		static buf[4*1024];
		int len = BIO_read(conn->wbio, buf, sizeof(buf));
		send(conn->insecure_socket, buf, len, 0);
	}

	if(conn->handshake_done == 0 && SSL_is_init_finished(conn->ssl)) {
		conn->handshake_done = 1;

		ssl_connection_send_secret_data(conn);
		ssl_handle_bio(conn);
	}
}

static void
ssl_init() {
	CRYPTO_malloc_init();
	SSL_library_init();
	ERR_load_crypto_strings();

	OpenSSL_add_all_algorithms();
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
	OpenSSL_add_ssl_algorithms();

	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new(DTLSv1_method());
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
	ssl_connection_idx = SSL_get_ex_new_index(0, "ssl_connection", NULL, NULL, NULL);

	SSL_CTX_set_info_callback(ssl_ctx, (void *) cb_info);
}

void
ssl_cleanup() {
	SSL_CTX_free(ssl_ctx);
}

static gboolean
cb_received_secret_data(GIOChannel *source,
                        GIOCondition condition,
                        gpointer user_data)
{
	//printf("cb_received_secret_data()\n");
	SslConnection *conn = (SslConnection *) user_data;

	ssl_handle_bio(conn);
	ssl_connection_send_secret_data(conn);
	ssl_handle_bio(conn);

	return TRUE;
}

static gboolean
cb_received_encrypted_data(GIOChannel *source,
                           GIOCondition condition,
                           gpointer user_data)
{
	//printf("cb_received_encrypted_data()\n");
	SslConnection *conn = (SslConnection *) user_data;

	ssl_handle_bio(conn);
	ssl_connection_receive_encrypted_data(conn);
	ssl_handle_bio(conn);

	return TRUE;
}

static int
cb_verify_certificate(int preverify_ok, X509_STORE_CTX *ctx) {
	SslConnection* conn;
	int ctx_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
	SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, ctx_idx);
	conn = (SslConnection *)  SSL_get_ex_data(ssl, ssl_connection_idx);

	EVP_PKEY *actual_rsa;
	X509 *cert = ctx->current_cert;
	actual_rsa = X509_get_pubkey(cert);

	EVP_PKEY *expected_rsa;
	char const *pem_expected_public_key = ssl_connection_get_remote_key(conn);
	expected_rsa = pem2evp_public_key(pem_expected_public_key);

	int res = EVP_PKEY_cmp(expected_rsa, actual_rsa);
	if(0)
		printf("cb_verify_certificate(): %i\n %s\n %s\n => res: %i\n",
		       ssl_connection_is_caller(conn),
		       evp2pem_public_key(expected_rsa),
		       evp2pem_public_key(actual_rsa),
		       res);
	EVP_PKEY_free(expected_rsa);
	EVP_PKEY_free(actual_rsa);

	return res;
}

SslConnection *
ssl_connection_new(int insecure_socket) {
	SslConnection *conn;
	conn = (SslConnection *) malloc(sizeof(SslConnection));
	memset(conn, 0, sizeof(SslConnection));

	if(ssl_ctx == NULL)
		ssl_init();
	conn->ssl = SSL_new(ssl_ctx);

	SSL_set_ex_data(conn->ssl, ssl_connection_idx, conn);
	SSL_set_verify_depth(conn->ssl, 1); // peer certificate level only
    SSL_set_verify(conn->ssl,
                   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                   cb_verify_certificate);

	conn->insecure_socket = insecure_socket;
	if(socketpair(AF_UNIX, SOCK_DGRAM, AF_UNSPEC, conn->secure_sockets) != 0) {
		free(conn);
		return NULL;
	}

	GIOChannel *io[2];
	guint source_id[2];
	io[0] = g_io_channel_unix_new(conn->secure_sockets[0]);
	io[1] = g_io_channel_unix_new(conn->insecure_socket);
	source_id[0] = g_io_add_watch(io[0], G_IO_IN, cb_received_secret_data, conn);
	source_id[1] = g_io_add_watch(io[1], G_IO_IN, cb_received_encrypted_data, conn);

	conn->insecure_socket = insecure_socket;
	conn->rbio = BIO_new(BIO_s_mem());
	conn->wbio = BIO_new(BIO_s_mem());
	SSL_set_bio(conn->ssl, conn->rbio, conn->wbio);

	conn->on_data_received = signal_new();
	conn->on_authentication_failed = signal_new();

	return conn;
}

void
ssl_connection_free(SslConnection *conn) {
	SSL_free(conn->ssl);

	if(conn->pem_remote_key != NULL)
		free(conn->pem_remote_key);

	signal_free(conn->on_data_received);
	signal_free(conn->on_authentication_failed);

	free(conn);
}

const int
ssl_connection_set_is_caller(SslConnection *conn, int is_caller) {
	int old_value = conn->is_caller;
	conn->is_caller = is_caller;

	return old_value;
}

const int
ssl_connection_is_caller(SslConnection *conn) {
	return conn->is_caller;
}

int
ssl_connection_connect(SslConnection *conn) {
	if(ssl_connection_is_caller(conn))
		SSL_set_connect_state(conn->ssl);
	else
		SSL_set_accept_state(conn->ssl);

	int res = SSL_do_handshake(conn->ssl);
	ssl_handle_bio(conn);

	return res;
}

int
ssl_connection_set_local_key(SslConnection *conn, char const *pem_key_pair) {
	int serial = 1;
	int ten_years = 10*365;

	X509 *cert = pem_generate_certificate(pem_key_pair, ten_years, serial);
	if(SSL_use_certificate(conn->ssl, cert) != 1)
		return 0;

	EVP_PKEY *key_pair = pem2evp_key_pair(pem_key_pair);
	if(SSL_use_PrivateKey(conn->ssl, key_pair) != 1)
		return 0;

	EVP_PKEY_free(key_pair);
	X509_free(cert);

	return 1;
}

int
ssl_connection_set_remote_key(SslConnection *conn, char *pem_public_key) {
	conn->pem_remote_key = pem_parse_public_key(pem_public_key);
	return (conn->pem_remote_key != NULL);
}

const char const *
ssl_connection_get_remote_key(SslConnection *conn) {
	return conn->pem_remote_key;
}

const int
ssl_connection_get_secure_socket(SslConnection *conn) {
	return conn->secure_sockets[1];
}

static int
ssl_connection_receive_encrypted_data_raw(SslConnection *conn,
                                          void *encrypted_buf,
                                          size_t encrypted_len)
{
	BIO_write(conn->rbio, encrypted_buf, encrypted_len);

	char secret_buf[4*1024];
	int len = SSL_read(conn->ssl, secret_buf, 4*1024);

	int res = 0;
	if(len > 0) {
		res = send(conn->secure_sockets[0], secret_buf, len, 0);
		signal_on(conn->on_data_received, secret_buf, len);
	}
	ssl_handle_bio(conn);

	return res;
}

static int
ssl_connection_send_secret_data_raw(SslConnection *conn,
                                void *buf,
                                size_t len)
{
	int ret = SSL_write(conn->ssl, buf, len);
	ssl_handle_bio(conn);

	return ret;
}

int
ssl_connection_receive_encrypted_data(SslConnection *conn) {
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

	size_t len = recvmsg(conn->insecure_socket, &msg, MSG_DONTWAIT);
	if(len == EWOULDBLOCK || len == EAGAIN)
		return len;

	return ssl_connection_receive_encrypted_data_raw(conn, buf, len);
}

int
ssl_connection_send_secret_data(SslConnection *conn) {
	if(!SSL_is_init_finished(conn->ssl))
		return 0;

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

	size_t len = recvmsg(conn->secure_sockets[0], &msg, MSG_DONTWAIT);
	if(len == EWOULDBLOCK || len == EAGAIN)
		return len;

	return ssl_connection_send_secret_data_raw(conn, buf, len);
}

void
ssl_connection_on_authentication_failed(SslConnection *conn,
                                        Callback cb,
                                        void* user_arg)
{
	signal_on(conn->on_authentication_failed, cb, user_arg);
}
