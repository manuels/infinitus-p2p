#include <string.h>

#include "minunit.h"
#include "pem.h"

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
test_pem_key_pair_with_valid_key() {
	char *valid_key_pair = valid_normalized_key_pair;

	RSA *rsa;
	rsa = pem2rsa_key_pair(valid_key_pair);
	mu_assert("pem2rsa_key_pair() with valid key failed!",
	          rsa != NULL);
	RSA_free(rsa);
	mu_assert("pem_is_key_pair() with valid key failed!",
	          pem_is_key_pair(valid_key_pair));

	return NULL;
}

static char *
test_pem_key_pair_with_invalid_key() {
	char invalid_key_pair[] = ""
	"-----BEGIN RSA PRIVATE KEY-----"
	"MIIBOwIBAAJBAMckQ1vz7PeAGgUGlYQihenoyYQe4Zr1Uy++sNBo5Plsp01Lu+DK"
	"XI8vDMSnQFUWZi5a50581VxUqlBPW0IPj1cCAwEAAQJALZRHNoyl+CAB1JSlNBES"
	"xW7acLsAuA7ec1cZ8RmRDuVAJDYOG+CxIype58VxMua9T1nPII30YOLqWhvvfoZ1"
	"gQIhAOaVbHuE/VSHQHRF5aOLn1Mae1GYCgvrjmiM1GtxWYRPAiEA3Rec20p7TIFA"
	"Ehwa4 THIS IS INVALID Pb/A+wGnkCIE/mFQoUAggpOZ9QnQr3lYShV3vleA27"
	"WMRHkE+OnlsnAiEAovx6ROrmdGLAEdmoNNk2cdsepk/zgFvdgbSrsmj6QLkCIQDM"
	"GdyuzlTDbSeHDgChtO4H4gE2mFLT2IP20T9SwQNtRQ=="
	"-----END RSA PRIVATE KEY-----";

	mu_assert("pem_is_key_pair() with invalid key failed!",
	          !pem_is_key_pair(invalid_key_pair));
	mu_assert("pem2rsa_key_pair() with invalid key failed!",
	          pem2rsa_key_pair(invalid_key_pair) == NULL);

	return NULL;
}

static char *
test_pem_key_pair_with_NULL() {
	mu_assert("pem2rsa_key_pair() with NULL failed!",
	          pem2rsa_key_pair(NULL) == NULL);
	mu_assert("pem_is_key_pair() with NULL failed!",
	          !pem_is_key_pair(NULL));

	return NULL;
}

static char *
test_pem_key_pair_with_empty_string() {
	mu_assert("pem2rsa_key_pair() with empty string failed!",
	          pem2rsa_key_pair("") == NULL);
	mu_assert("pem_is_key_pair() with empty string failed!",
	          !pem_is_key_pair(""));

	return NULL;
}

static char *
test_pem_generate_key_pair() {
	char *pem = pem_generate_key_pair(64);
	mu_assert("pem_generate_key_pair() failed: too short!",
	          strlen(pem) > 145);
	mu_assert("pem_generate_key_pair() failed: too long!",
	          strlen(pem) < 160);
	free(pem);

	return NULL;
}

static char *
test_pem_parse_private_key() {
	char valid_key_pair[] = ""
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIBOwIBAAJBAMckQ1vz7PeAGgUGlYQihenoyYQe4Zr1Uy++sNBo5Plsp01Lu+DK\n"
	"XI8vDMSnQFUWZi5a50581VxUqlBPW0IPj1cCAwEAAQJALZRHNoyl+CAB1JSlNBES\n"
	"xW7acLsAuA7ec1cZ8RmRDuVAJDYOG+CxIype58VxMua9T1nPII30YOLqWhvvfoZ1\n"
	"gQIhAOaVbHuE/VSHQHRF5aOLn1Mae1GYCgvrjmiM1GtxWYRPAiEA3Rec20p7TIFA\n"
	"Ehwa44FgaAixU3Qkmwn6FZPb/A+wGnkCIE/mFQoUAggpOZ9QnQr3lYShV3vleA27\n"
	"WMRHkE+OnlsnAiEAovx6ROrmdGLAEdmoNNk2cdsepk/zgFvdgbSrsmj6QLkCIQDM\n"
	"GdyuzlTDbSeHDgChtO4H4gE2mFLT2IP20T9SwQNtRQ==\n"
	"-----END RSA PRIVATE KEY-----\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";

	char *expected_key_pair = valid_normalized_key_pair;

	char *actual_key_pair = pem_parse_key_pair(valid_key_pair);
	mu_assert("pem_parse_key_pair() failed: ", strcmp(actual_key_pair, expected_key_pair) == 0);

	free(actual_key_pair);

	return NULL;
}

static char *
test_pem2evp_key_pair() {
	char *key_pair = valid_normalized_key_pair;
	mu_assert("pem2evp_key_pair() failed: ", pem2evp_key_pair(key_pair) != NULL);

	return NULL;
}

static char *
test_pem_public_key() {
	char expected_public_key[] = ""
		"-----BEGIN RSA PUBLIC KEY-----\n"
		"MEgCQQDHJENb8+z3gBoFBpWEIoXp6MmEHuGa9VMvvrDQaOT5bKdNS7vgylyPLwzE\n"
		"p0BVFmYuWudOfNVcVKpQT1tCD49XAgMBAAE=\n"
		"-----END RSA PUBLIC KEY-----\n";

	char *actual_public_key = pem_public_key(valid_normalized_key_pair);
	mu_assert("pem_public_key() failed: ",
	          strcmp(actual_public_key, expected_public_key) == 0);
	free(actual_public_key);

	return NULL;
}

static char *
test_pem_parse_public_key() {
	char expected_public_key[] = ""
		"-----BEGIN RSA PUBLIC KEY-----\n"
		"MEgCQQDHJENb8+z3gBoFBpWEIoXp6MmEHuGa9VMvvrDQaOT5bKdNS7vgylyPLwzE\n"
		"p0BVFmYuWudOfNVcVKpQT1tCD49XAgMBAAE=\n"
		"-----END RSA PUBLIC KEY-----\n";

	char input[] = ""
		"-----BEGIN RSA PUBLIC KEY-----\n"
		"MEgCQQDHJENb8+z3gBoFBpWEIoXp6MmEHuGa9VMvvrDQaOT5bKdNS7vgylyPLwzE\n"
		"p0BVFmYuWudOfNVcVKpQT1tCD49XAgMBAAE=\n"
		"-----END RSA PUBLIC KEY-----\n\n\n\n\n\n\n\n";

	char *actual_public_key = pem_parse_public_key(input);
	mu_assert("pem_parse_public_key() failed: ",
	          strcmp(actual_public_key, expected_public_key) == 0);
	free(actual_public_key);

	return NULL;
}

static char *
test_pem_fingerprint() {
	char *valid_key_pair = valid_normalized_key_pair;

	size_t len;
	unsigned char *actual_md;
	unsigned char expected_md[] = {
		0xc5, 0xdd, 0xe2, 0xdc, 0x9a, 0x5a, 0xdc, 0xf6, 0xcc, 0x3f, 0xd9, 0x1c,
		0x56, 0xb0, 0x8f, 0x77, 0xae, 0xa7, 0x9e, 0xa7, 0x0b, 0x7d, 0x1a, 0x60,
		0xcb, 0xc6, 0x78, 0x8e, 0xcf, 0x40, 0x30, 0xdc, 0x51, 0x57, 0xe3, 0xcf,
		0xc9, 0x61, 0x4e, 0x27, 0xbb, 0x10, 0x0c, 0x5b, 0xa7, 0x1a, 0xef, 0x4e,
		0x05, 0x82, 0x9b, 0x10, 0xed, 0xca, 0xaf, 0x51, 0xf0, 0x2e, 0xc9, 0x14,
		0x3c, 0x10, 0xde, 0x1e};

	len = pem_fingerprint(valid_key_pair, &actual_md);
	mu_assert("pem_fingerprint() with valid key failed with zero-length md",
	          len == sizeof(expected_md));
	mu_assert("pem_fingerprint() with valid key failed with incorrect md!",
	          memcmp(actual_md, expected_md, len) == 0);
	free(actual_md);

	return NULL;
}


static char *
test_pem_fingerprint_string() {
	char *valid_key_pair = valid_normalized_key_pair;

	char *actual_md;
	char expected_md[] = "c5dde2dc9a5adcf6cc3fd91c56b08f77aea79ea70b7d1a60cbc67"
		"88ecf4030dc5157e3cfc9614e27bb100c5ba71aef4e05829b10edcaaf51f02ec9143c1"
		"0de1e";

	actual_md = pem_fingerprint_string(valid_key_pair);
	mu_assert("pem_fingerprint_string() with valid key failed with incorrect md!",
	          strcmp(actual_md, expected_md) == 0);
	free(actual_md);

	return NULL;
}

static char *
run_all_tests() {
	mu_run_test(test_pem_key_pair_with_valid_key);
	mu_run_test(test_pem_key_pair_with_invalid_key);
	mu_run_test(test_pem_key_pair_with_NULL);
	mu_run_test(test_pem_key_pair_with_empty_string);

	mu_run_test(test_pem_generate_key_pair);
	mu_run_test(test_pem_fingerprint);
	mu_run_test(test_pem_fingerprint_string);
	mu_run_test(test_pem_parse_private_key);
	mu_run_test(test_pem_public_key);
	mu_run_test(test_pem_parse_public_key);

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
