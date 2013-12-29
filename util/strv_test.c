#include "../minunit.h"
#include "strv.h"

static char *
test_strvdup() {
	const char *old_strv[] = {"default", "identity", NULL};

	char **new_strv = strvdup(old_strv);
	mu_assert("strvdup() error!", new_strv != NULL);

	int i;
	for(i = 0; i < 3; ++i) {
		if(i < 2)
			mu_assert("strvdup() error: did not copy deeply!", new_strv[i] != old_strv[i]);
		mu_assert_strcmp0("strvdup() error: deep copy is incorrect!", new_strv[i], old_strv[i]);
	}
	strvfree(new_strv);

	return NULL;
}

static char *
test_strvdup_NULL() {
	const char * const *old_strv = NULL;

	char **new_strv = strvdup(old_strv);
	mu_assert("strvdup() error!", new_strv == NULL);

	return NULL;
}

static char *
test_strvlen() {
	size_t len;

	const char * const strv0[] = {"default", "identity", NULL};
	len = strvlen(strv0);
	mu_assert("strvlen() error!", len == 2);

	const char * const strv1[] = {NULL};
	len = strvlen(strv1);
	mu_assert("strvlen() error!", len == 0);

	return NULL;
}

static char *
test_strvlen_NULL() {
	const char * const *strv = NULL;

	size_t len = strvlen(strv);
	mu_assert("strvlen() error!", len == 0);

	return NULL;
}

static char *
run_all_tests() {
	mu_run_test(test_strvdup);
	mu_run_test(test_strvdup_NULL);
	mu_run_test(test_strvlen);
	mu_run_test(test_strvlen_NULL);

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