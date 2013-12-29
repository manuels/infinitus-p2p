#include <stdio.h>

#define mu_assert(message, test) do { if (!(test)) return message; } while (0)
#define mu_run_test(test) do { char *message = test(); tests_run++; \
                            if (message) return message; } while (0)
#define mu_assert_strcmp(msg, str1, str2) do { \
	mu_assert(msg, strcmp(str1, str2) == 0); } while(0)
#define mu_assert_strcmp0(msg, str1, str2) do { \
	if((str1 != NULL) || (str2 != NULL)) \
		mu_assert(msg, strcmp(str1, str2) == 0); } while(0)
int tests_run;
