#include <stdlib.h>
#include "minunit.h"
#include "identity.h"

char valid_normalized_key_pair[] = ""
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIBOwIBAAJBAMckQ1vz7PeAGgUGlYQihenoyYQe4Zr1Uy++sNBo5Plsp01Lu+DK\n"
	"XI8vDMSnQFUWZi5a50581VxUqlBPW0IPj1cCAwEAAQJALZRHNoyl+CAB1JSlNBES\n"
	"xW7acLsAuA7ec1cZ8RmRDuVAJDYOG+CxIype58VxMua9T1nPII30YOLqWhvvfoZ1\n"
	"gQIhAOaVbHuE/VSHQHRF5aOLn1Mae1GYCgvrjmiM1GtxWYRPAiEA3Rec20p7TIFA\n"
	"Ehwa44FgaAixU3Qkmwn6FZPb/A+wGnkCIE/mFQoUAggpOZ9QnQr3lYShV3vleA27\n"
	"WMRHkE+OnlsnAiEAovx6ROrmdGLAEdmoNNk2cdsepk/zgFvdgbSrsmj6QLkCIQDM\n"
	"GdyuzlTDbSeHDgChtO4H4gE2mFLT2IP20T9SwQNtRQ==\n"
	"-----END RSA PRIVATE KEY-----\n";

static char *
test_new() {
	char const *search_terms[] = {"default", "identity", NULL};
	Identity *ident;

	ident = identity_new("Default Identity", "PEM", search_terms);
	mu_assert("identity_new() succeeded unexpectedly with invalid PEM key!", ident == NULL);

	ident = identity_new("Default Identity", valid_normalized_key_pair, search_terms);
	mu_assert("identity_new() failed with valid PEM key!", ident != NULL);
	identity_free(ident);

	return NULL;
}

static char *
test_generate_new() {
	int rsa_bits = 64;
	char const *search_terms[] = {"default", "identity", NULL};

	Identity *ident = identity_generate_new("Default Identity",
	                                        rsa_bits,
	                                        search_terms);
	mu_assert("identity_generate_new error!", ident != NULL);
	identity_free(ident);

	return NULL;
}

static char *
test_pem_public_key() {
	Identity *ident = identity_new("Default Identity", valid_normalized_key_pair, NULL);

	char expected[] =
		"-----BEGIN RSA PUBLIC KEY-----\n"
		"MEgCQQDHJENb8+z3gBoFBpWEIoXp6MmEHuGa9VMvvrDQaOT5bKdNS7vgylyPLwzE\n"
		"p0BVFmYuWudOfNVcVKpQT1tCD49XAgMBAAE=\n"
		"-----END RSA PUBLIC KEY-----\n";
	char *actual = identity_pem_public_key(ident);

	mu_assert("identity_public_key() failed: ",
          strcmp(actual, expected) == 0);

	free(actual);
	identity_free(ident);

	return NULL;
}

static char *
run_all_tests() {
	mu_run_test(test_new);
	mu_run_test(test_generate_new);
	mu_run_test(test_pem_public_key);
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
