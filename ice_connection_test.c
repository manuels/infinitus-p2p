#include <stdlib.h>
#include <assert.h>

#include "minunit.h"
#include "ice_connection.h"
#include "signal.h"

static GMainLoop *gloop;

static int
on_gathered(void *user_arg, va_list args) {
	static int gathered_count = 0;
	gathered_count++;

	if(gathered_count != 2)
		return 1;

	IceConnection **ice = (IceConnection **) user_arg;

	int res;
	int i;
	char *credentials;
	for(i = 0; i < 2; ++i) {
		credentials = ice_connection_local_credentials(ice[i]);
		assert(credentials != NULL);

		res = ice_connection_set_remote_credentials(ice[(i+1)%2],
		                                            credentials);
		assert(res == 1);

		free(credentials);
	}

	return 1;
}

static int
on_connected(void *user_arg, va_list args) {
	static int connected_count = 0;
	connected_count++;

	if(connected_count != 2)
		return 1;

	IceConnection **ice = (IceConnection **) user_arg;

	int len;
	int i;
	int sock;
	for(i = 0; i < 2; ++i) {
		int buf = i+1;
		len = ice_connection_send(ice[i], &buf, sizeof(buf));
		assert(len == sizeof(buf));

		sock = ice_connection_get_socket(ice[i]);
		len = send(sock, &buf, sizeof(buf), 0);
		assert(len == sizeof(buf));
	}

	return 1;
}

static int
on_disconnected(void *user_arg, va_list args) {
	printf("on_disconnected()!\n");

	g_main_loop_quit(gloop);

	return 1;
}

static int
on_data(void *user_arg, va_list args) {
	IceConnection *ice = va_arg(args, IceConnection *);
	/*char *buf = va_arg(args, char *);
	int len = va_arg(args, int);
	*/

	static int count = 0;
	int sock = ice_connection_get_socket(ice);
	char buf[sizeof(int)];

	size_t len = recv(sock, &buf, sizeof(buf), 0);
	assert(len == sizeof(int));

	count += (int) *buf;

	int test_succeeded = (count == 2*(1+2));
	if(test_succeeded)
		g_main_loop_quit(gloop);

	return 1;
}

static char *
test_new() {
	IceConnection *ice[2];
	gloop = g_main_loop_new(NULL, FALSE);
	GMainContext *ctx = g_main_loop_get_context(gloop);
	
	int i;
	for(i = 0; i < 2; ++i) {
		ice[i] = ice_connection_new(ctx);

		ice_connection_on_candidates_gathered(ice[i],
		                                      on_gathered,
		                                      &ice);
		ice_connection_on_connected(ice[i], on_connected, &ice);
		ice_connection_on_disconnected(ice[i], on_disconnected, &ice);
		ice_connection_on_data_received(ice[i], on_data, &ice);
	
		ice_connection_gather_candidates(ice[i]);
	}

	g_main_loop_run(gloop);
	
	g_main_context_unref(ctx);
	g_main_loop_unref(gloop);

	return NULL;
}

static char *
run_all_tests() {
	mu_run_test(test_new);
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
