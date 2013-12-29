#include <stdlib.h>
#include "minunit.h"
#include "signal.h"

static int
counter = 0;

int
inc_counter(void *user_arg, va_list args) {
	int inc = (int) user_arg;
	counter += inc;

	return 1;
}

static char *
test_new() {
	Signal *sig = signal_new();

	signal_emit(sig);
	mu_assert("signal emit failed!", counter == 0);

	signal_on(sig, inc_counter, 1);
	signal_on(sig, inc_counter, 2);
	signal_emit(sig);
	mu_assert("signal emit failed for first emit!", counter == 3);

	signal_emit(sig);
	mu_assert("signal emit failed for second emit!", counter == 6);

	signal_on(sig, inc_counter, 3);
	signal_emit(sig);
	mu_assert("signal emit failed for third emit!", counter == 12);

	signal_free(sig);

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
