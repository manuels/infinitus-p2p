#ifndef __PEM_H__
#define __PEM_H__

#include <openssl/rsa.h>
#include <openssl/pem.h>

RSA *
pem2rsa_key_pair(char const *pem);

int
pem_is_key_pair(char const *pem);

char *
pem_parse_key_pair(char const *pem);

char *
pem_generate_key_pair(int rsa_bits);

size_t
pem_fingerprint(char const *pem, unsigned char **md);

char *
pem_fingerprint_string(char const *pem);

char *
rsa2pem_key_pair(RSA *rsa);

char *
pem_public_key(char const *pem);

char *
rsa2pem_public_key(RSA *rsa);

RSA *
pem2rsa_public_key(char const *pem);

char *
pem_parse_public_key(char const *pem);

char *
rsa2pem_public_key(RSA *rsa);

X509 *
pem_generate_certificate(char const *pem_key_pair,
                         int days,
                         int serial);

EVP_PKEY *
pem2evp_key_pair(char const *pem_key_pair);

EVP_PKEY *
pem2evp_public_key(char const *pem_public_key);

char *
evp2pem_public_key(EVP_PKEY *evp);

#endif
