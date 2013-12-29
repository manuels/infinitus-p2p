#include <stdlib.h>
#include <assert.h>

#include "minunit.h"
#include "multi_channel.h"

static char *
test_new() {
	int base_socket[2];
	mu_assert("socketpair() failed!",
	          socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, AF_UNSPEC, insecure_sockets) == 0);

	MultiChannel *mc[2];

	int i;
	for(i = 0; i < 2; ++i) {
		mc[i] = multi_channel_new(base_socket[i]);
		int sock = multi_channel_new_socket(mc[i], "org.infinitus.tcp");
	}
	
	return NULL;
}

static char *
run_all_tests() {
	mu_run_test(test_new);

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
