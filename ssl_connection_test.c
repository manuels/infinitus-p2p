#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <glib.h>

#include "minunit.h"
#include "ssl_connection.h"

static GMainLoop *gloop;

char key_pair0[] = ""
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIBOwIBAAJBAMckQ1vz7PeAGgUGlYQihenoyYQe4Zr1Uy++sNBo5Plsp01Lu+DK\n"
	"XI8vDMSnQFUWZi5a50581VxUqlBPW0IPj1cCAwEAAQJALZRHNoyl+CAB1JSlNBES\n"
	"xW7acLsAuA7ec1cZ8RmRDuVAJDYOG+CxIype58VxMua9T1nPII30YOLqWhvvfoZ1\n"
	"gQIhAOaVbHuE/VSHQHRF5aOLn1Mae1GYCgvrjmiM1GtxWYRPAiEA3Rec20p7TIFA\n"
	"Ehwa44FgaAixU3Qkmwn6FZPb/A+wGnkCIE/mFQoUAggpOZ9QnQr3lYShV3vleA27\n"
	"WMRHkE+OnlsnAiEAovx6ROrmdGLAEdmoNNk2cdsepk/zgFvdgbSrsmj6QLkCIQDM\n"
	"GdyuzlTDbSeHDgChtO4H4gE2mFLT2IP20T9SwQNtRQ==\n"
	"-----END RSA PRIVATE KEY-----\n";

char correct_public_key[] = ""
	"-----BEGIN RSA PUBLIC KEY-----\n"
	"MEgCQQDHJENb8+z3gBoFBpWEIoXp6MmEHuGa9VMvvrDQaOT5bKdNS7vgylyPLwzE\n"
	"p0BVFmYuWudOfNVcVKpQT1tCD49XAgMBAAE=\n"
	"-----END RSA PUBLIC KEY-----\n";

char incorrect_public_key[] = ""
	"-----BEGIN RSA PUBLIC KEY-----\n"
	"MIIBCgKCAQEA+xGZ/wcz9ugFpP07Nspo6U17l0YhFiFpxxU4pTk3Lifz9R3zsIsu\n"
	"ERwta7+fWIfxOo208ett/jhskiVodSEt3QBGh4XBipyWopKwZ93HHaDVZAALi/2A\n"
	"+xTBtWdEo7XGUujKDvC2/aZKukfjpOiUI8AhLAfjmlcD/UZ1QPh0mHsglRNCmpCw\n"
	"mwSXA9VNmhz+PiB+Dml4WWnKW/VHo2ujTXxq7+efMU4H2fny3Se3KYOsFPFGZ1TN\n"
	"QSYlFuShWrHPtiLmUdPoP6CV2mML1tk+l7DIIqXrQhLUKDACeM5roMx0kLhUWB8P\n"
	"+0uj1CNlNN4JRZlC7xFfqiMbFRU9Z4N6YwIDAQAB\n"
	"-----END RSA PUBLIC KEY-----\n";

static gboolean
cb_free_ssl(gpointer user_data) {
	SslConnection **ssl = (SslConnection **) user_data;
	ssl_connection_free(ssl[0]);
	ssl_connection_free(ssl[1]);
}

static int
auth_failed_counter = 0;

static int
cb_authentication_failed(void *user_arg, va_list args) {
	auth_failed_counter++;
	//printf("cb_authentication_failed %i\n", auth_failed_counter);

	if(auth_failed_counter == 2)
		g_main_loop_quit(gloop);
	return 0;
}

static int
connected_counter = 0;

static int
cb_connected(void *user_arg, va_list args) {
	//printf("cb_connected\n");
	connected_counter++;

	g_main_loop_quit(gloop);
	return 0;
}


static gboolean
cb_receive_foo(GIOChannel *source,
               GIOCondition condition,
               gpointer user_data) {
	//printf("cb_receive_foo\n");

	char buf[1024];
	int sock = (int) user_data;
	int res = recv(sock, buf, sizeof(buf), 0);

	//printf("cb_receive_foo len=%i=%s\n", res, buf);
	static int counter = 0;

	if(strcmp(buf, "foo"))
		counter += 1;
	if(strcmp(buf, "bar"))
		counter += 2;

	if(counter == 3) {
		g_main_loop_quit(gloop);
		return FALSE;
	}

	return TRUE;
}


static char *
test_new_success() {
	gloop = g_main_loop_new(NULL, FALSE);

	int insecure_sockets[2];
	mu_assert("socketpair() failed!",
	          socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, AF_UNSPEC, insecure_sockets) == 0);

	GIOChannel *io[2];
	guint source_id[2];

	SslConnection *ssl[2];

	int res;
	int i;
	for(i = 0; i < 2; ++i) {
		ssl[i] = ssl_connection_new(insecure_sockets[i]);

		ssl_connection_set_is_caller(ssl[i], i == 0);
		ssl_connection_set_local_key(ssl[i], key_pair0);

		ssl_connection_on_authentication_failed(ssl[i], cb_authentication_failed, NULL);

		res = ssl_connection_set_remote_key(ssl[i], correct_public_key);
		mu_assert("ssl_connection_set_remote_key() failed!", res == 1);

		int sock = ssl_connection_get_secure_socket(ssl[i]);
		io[i] = g_io_channel_unix_new(sock);
		source_id[i] = g_io_add_watch(io[i], G_IO_IN, cb_receive_foo, (gpointer) sock);
		
		int res = ssl_connection_connect(ssl[i]);
	}

	for(i = 0; i < 2; ++i) {
		int sock = ssl_connection_get_secure_socket(ssl[i]);
		if(i == 0)
			send(sock, "foo", 4, 0);
		else
			send(sock, "bar", 4, 0);
	}

	g_main_loop_run(gloop);

	//mu_assert("on_connected was not called", connected_counter == 2);
	mu_assert("on_auth_failed was called", auth_failed_counter == 0);

	for(i = 0; i < 2; ++i) {
		g_idle_add(cb_free_ssl, ssl);
		g_io_channel_unref(io[i]);
	}

	g_main_loop_unref(gloop);

	return NULL;
}

static char *
test_new_fail(int incorrect_peer_idx) {
	gloop = g_main_loop_new(NULL, FALSE);

	int insecure_sockets[2];
	mu_assert("socketpair() failed!",
	          socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, AF_UNSPEC, insecure_sockets) == 0);

	GIOChannel *io[2];
	guint source_id[2];

	SslConnection *ssl[2];
	auth_failed_counter = 0;

	int res;
	int i;
	for(i = 0; i < 2; ++i) {
		ssl[i] = ssl_connection_new(insecure_sockets[i]);

		ssl_connection_set_is_caller(ssl[i], i == 0);
		ssl_connection_set_local_key(ssl[i], key_pair0);

		ssl_connection_on_authentication_failed(ssl[i], cb_authentication_failed, NULL);

		if(incorrect_peer_idx == i)
			res = ssl_connection_set_remote_key(ssl[i], incorrect_public_key);
		else
			res = ssl_connection_set_remote_key(ssl[i], correct_public_key);
		mu_assert("ssl_connection_set_remote_key() failed!", res == 1);

		int sock = ssl_connection_get_secure_socket(ssl[i]);
		io[i] = g_io_channel_unix_new(sock);
		source_id[i] = g_io_add_watch(io[i], G_IO_IN, cb_receive_foo, (gpointer) sock);
		
		int res = ssl_connection_connect(ssl[i]);
	}

	for(i = 0; i < 2; ++i) {
		int sock = ssl_connection_get_secure_socket(ssl[i]);
		if(i == 0)
			send(sock, "foo", 4, 0);
		else
			send(sock, "bar", 4, 0);
	}

	g_main_loop_run(gloop);

	mu_assert("on_auth_failed was not called", auth_failed_counter == 2);

	for(i = 0; i < 2; ++i) {
		g_idle_add(cb_free_ssl, ssl);
		g_io_channel_unref(io[i]);
	}

	g_main_loop_unref(gloop);

	return NULL;
}

static char *
test_new_fail0() {
	return test_new_fail(0);
}

static char *
test_new_fail1() {
	return test_new_fail(1);
}

static char *
run_all_tests() {
	printf("Running test_new_success()...\n");
	mu_run_test(test_new_success);
	printf("Done!\nRunning test_new_fail1()...\n");
	mu_run_test(test_new_fail1);
	mu_run_test(test_new_fail0);

	ssl_cleanup();
	return NULL;
}

int main() {
	char *result = run_all_tests();
	if (result != 0) {
		printf("%s\n", result);
	}
	else {
		printf("ALL TESTS PASSED\n");
	}
	printf("Tests run: %d\n", tests_run);

	return result != 0;
}
