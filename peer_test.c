#include <stdlib.h>
#include "minunit.h"
#include "identity.h"
#include "peer.h"
#include "pem.h"

char key_pair1[] = ""
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIBOwIBAAJBAMckQ1vz7PeAGgUGlYQihenoyYQe4Zr1Uy++sNBo5Plsp01Lu+DK\n"
	"XI8vDMSnQFUWZi5a50581VxUqlBPW0IPj1cCAwEAAQJALZRHNoyl+CAB1JSlNBES\n"
	"xW7acLsAuA7ec1cZ8RmRDuVAJDYOG+CxIype58VxMua9T1nPII30YOLqWhvvfoZ1\n"
	"gQIhAOaVbHuE/VSHQHRF5aOLn1Mae1GYCgvrjmiM1GtxWYRPAiEA3Rec20p7TIFA\n"
	"Ehwa44FgaAixU3Qkmwn6FZPb/A+wGnkCIE/mFQoUAggpOZ9QnQr3lYShV3vleA27\n"
	"WMRHkE+OnlsnAiEAovx6ROrmdGLAEdmoNNk2cdsepk/zgFvdgbSrsmj6QLkCIQDM\n"
	"GdyuzlTDbSeHDgChtO4H4gE2mFLT2IP20T9SwQNtRQ==\n"
	"-----END RSA PRIVATE KEY-----\n";

char key_pair2[] = ""
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIIBPAIBAAJBAOFjrG6rokLNlqXdhaq3W9oxK02pgfY6qGY9kUFFan/T3xBRVP3C\n"
	"X/dnDurz3irGy7Pdf01W/2ub5+HbxlKwabUCAwEAAQJBAIr3weGawbkeubwbEcdo\n"
	"tqGZn3GLCi6fjCU94Mm12yxkdfT0Uu0u+2LJGMavmVirBgTl+5d2FXYBmAGYM/va\n"
	"dSECIQDxmwyEzTyzrEzri/IxEovzIBXFlr0NxHT47/TcWuRE+wIhAO7RS3QWw1nF\n"
	"K0wSKy9zIKa0peqwdUTZO5/o7gZgHO0PAiB1l/u93479/Izr0I+u5tILIcC3DSkz\n"
	"PD2atGA/qFWWZQIhAMZiNES+OA8Ve+8YVKl5AJGbFQzNAs1ri10+GKRRKRY/AiEA\n"
	"kIeoJwEqnXVYsi+Mc0CZEJ4aCjkN3KLVQRSLXLrNmtM=\n"
	"-----END RSA PRIVATE KEY-----\n";

static char *
test_new() {
	Peer *p;
	Identity *ident;
	ident = identity_new("Default Identity", key_pair1, NULL);
	char *remote_public_key = pem_public_key(key_pair2);

	p = peer_new(ident, remote_public_key);
	mu_assert("peer_new() with valid remote_key failed!", p != NULL);
	peer_free(p);

	p = peer_new(ident, "");
	mu_assert("peer_new() with invalid remote key succeeded unexpectedly!", p == NULL);

	p = peer_new(NULL, remote_public_key);
	mu_assert("peer_new() with invalid identity succeeded unexpectedly!", p == NULL);

	identity_free(ident);
	free(remote_public_key);

	return NULL;
}

static char *
test_fingerprints() {
	Peer *p;
	Identity *ident;
	ident = identity_new("Default Identity", key_pair1, NULL);
	char *remote_public_key = pem_public_key(key_pair2);

	char expected_local_md[] = "c5dde2dc9a5adcf6cc3fd91c56b08f77aea79ea70b7d1a60cbc67"
		"88ecf4030dc5157e3cfc9614e27bb100c5ba71aef4e05829b10edcaaf51f02ec9143c10de1e";
	char expected_remote_md[] = "641924e6e1e073c1dbb6fb42a6c1c3e266e7331c5f3de714300c"
		"23f7ea6538fff3d36e7b1875e98acf6887db4eefe35c37edf4148e427cd2de535a5ec7694e88";

	p = peer_new(ident, remote_public_key);

	char *actual_local_md = peer_local_fingerprint_string(p);
	char *actual_remote_md = peer_remote_fingerprint_string(p);

	mu_assert("peer_local_fingerprint_string() failed!",
	          strcmp(expected_local_md, actual_local_md) == 0);
	mu_assert("peer_remote_fingerprint_string() failed!",
	          strcmp(expected_remote_md, actual_remote_md) == 0);
	free(actual_local_md);
	free(actual_remote_md);

	peer_free(p);
	identity_free(ident);
	free(remote_public_key);

	return NULL;
}

static char *
run_all_tests() {
	mu_run_test(test_new);
	mu_run_test(test_fingerprints);
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
