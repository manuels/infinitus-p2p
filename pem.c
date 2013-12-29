#include <assert.h>
#include <string.h>

#include "pem.h"

int
pem_is_key_pair(const char *pem) {
	if(pem == NULL)
		return 0;

	RSA *rsa;
	rsa = pem2rsa_key_pair(pem);
	if(rsa == NULL)
		return 0;

	RSA_free(rsa);
	return 1;
}

char *
pem_parse_key_pair(char const *pem) {
	RSA *rsa = pem2rsa_key_pair(pem);
	if(rsa == NULL)
		return NULL;

	char *parsed_pem = rsa2pem_key_pair(rsa);
	RSA_free(rsa);

	return parsed_pem;
}

char *
pem_parse_public_key(char const *pem) {
	RSA *rsa = pem2rsa_public_key(pem);
	if(rsa == NULL)
		return NULL;

	char *parsed_pem = rsa2pem_public_key(rsa);
	RSA_free(rsa);

	return parsed_pem;
}

char *
pem_public_key(char const *pem) {
	RSA *rsa = pem2rsa_key_pair(pem);

	if(rsa == NULL)
		rsa = pem2rsa_public_key(pem);

	if(rsa == NULL)
		return NULL;

	char *pem_public_key = rsa2pem_public_key(rsa);
	RSA_free(rsa);

	return pem_public_key;
}

char *
rsa2pem_key_pair(RSA *rsa) {
	BIO *mem = NULL;
	char *pem = NULL;
	char *buf = NULL;
	long len;
	int ret;

	mem = BIO_new(BIO_s_mem());
	assert(mem);
	ret = PEM_write_bio_RSAPrivateKey(mem, rsa, NULL, NULL, 0, NULL, NULL);
	if(ret != 1) {
		BIO_free(mem);
		return NULL;
	}

	len = BIO_get_mem_data(mem, &buf);
	if(len > 0) {
		pem = malloc(len+1);
		assert(pem);
		memcpy(pem, buf, len);
		pem[len] = '\0';
	}

	BIO_free(mem);

	return pem;
}

char *
rsa2pem_public_key(RSA *rsa) {
	BIO *mem = NULL;
	char *pem = NULL;
	char *buf = NULL;
	long len;
	int ret;

	mem = BIO_new(BIO_s_mem());
	ret = PEM_write_bio_RSAPublicKey(mem, rsa);
	if(ret != 1)
		goto out;

	len = BIO_get_mem_data(mem, &buf);
	if(len > 0) {
		pem = malloc(len+1);
		assert(pem);
		memcpy(pem, buf, len);
		pem[len] = '\0';
	}

out:
	BIO_free(mem);

	return pem;
}

static
RSA *
pem2rsa(char const *pem,
        RSA * (*PEM_read_bio_RSAxxx)(BIO *, RSA **, pem_password_cb *, void *)) {
	if(pem == NULL)
		return NULL;

	BIO *mem_key_pair = NULL;

	mem_key_pair = BIO_new(BIO_s_mem());
	assert(mem_key_pair);
	BIO_puts(mem_key_pair, pem);

	RSA *rsa;
	rsa = PEM_read_bio_RSAxxx(mem_key_pair, NULL, NULL, NULL);

	BIO_free(mem_key_pair);
	return rsa;
}

RSA *
pem2rsa_key_pair(char const *pem) {
	return pem2rsa(pem, PEM_read_bio_RSAPrivateKey);
}

RSA *
pem2rsa_public_key(char const *pem) {
	return pem2rsa(pem, PEM_read_bio_RSAPublicKey);
}

static EVP_PKEY *
pem2evp(char const *pem,
        EVP_PKEY * (*PEM_read_bio_xxx)(BIO *, EVP_PKEY **, pem_password_cb *, void *)) {
	BIO *mem = NULL;

	mem = BIO_new(BIO_s_mem());
	assert(mem);
	BIO_puts(mem, pem);

	EVP_PKEY *evp;
	evp = PEM_read_bio_xxx(mem, NULL, NULL, NULL);

	BIO_free(mem);
	return evp;
}

RSA *
evp2rsa_public_key(EVP_PKEY *evp) {
	return EVP_PKEY_get1_RSA(evp);
}

char *
evp2pem_public_key(EVP_PKEY *evp) {
	RSA* rsa = evp2rsa_public_key(evp);
	if(rsa == NULL)
		return NULL;

	char *pem = rsa2pem_public_key(rsa);
	RSA_free(rsa);
	return pem;
}

static EVP_PKEY *
rsa2evp(RSA *rsa) {
	assert(rsa);

	EVP_PKEY *key_pair;
	key_pair = EVP_PKEY_new();
	assert(key_pair);

	if(!EVP_PKEY_assign_RSA(key_pair, rsa)) {
		EVP_PKEY_free(key_pair);
		key_pair = NULL;
	}

	return key_pair;
}

EVP_PKEY *
pem2evp_public_key(char const *pem_public_key) {
	RSA *rsa = pem2rsa_public_key(pem_public_key);
	if(rsa == NULL)
		return NULL;

	return rsa2evp(rsa);
} 

EVP_PKEY *
pem2evp_key_pair(char const *pem_key_pair) {
	return pem2evp(pem_key_pair, PEM_read_bio_PrivateKey);
} 

char *
pem_generate_key_pair(int rsa_bits) {
	RSA *rsa;
	char *pem = NULL;

	rsa = RSA_generate_key(rsa_bits, RSA_F4, NULL, NULL);
	if(rsa == NULL)
		return NULL;

	pem = rsa2pem_key_pair(rsa);
	RSA_free(rsa);

	return pem;
}

size_t
pem_fingerprint(char const *pem, unsigned char **md) {
	if(pem == NULL)
		return 0;

	size_t md_len;
	size_t pem_len = strlen(pem);
	*md = malloc(EVP_MAX_MD_SIZE);

	int ret;
	ret = EVP_Digest(pem, pem_len, *md, &md_len, EVP_sha512(), NULL);
	
	if(!ret) {
		free(*md);
		*md = NULL;
		return 0;
	}

	return md_len;
}

char *
pem_fingerprint_string(char const *pem) {
	size_t len;
	unsigned char *md;

	len = pem_fingerprint(pem, &md);
	if(len <= 0)
		return NULL;

	size_t i;
	char *str = malloc(2*len+1);
	memset(str, 0, 2*len+1);
	for(i = 0; i < len; ++i)
		sprintf(&str[2*i], "%02x", md[i]);

	free(md);
	return str;
}

X509 *
pem_generate_certificate(char const *pem_key_pair,
                         int days,
                         int serial) {
	assert(pem_key_pair);

	X509 *cert;
	cert = X509_new();
	assert(cert);

	EVP_PKEY *key_pair = pem2evp_key_pair(pem_key_pair);
	if(!key_pair) {
		X509_free(cert);
		cert = NULL;
		goto out;
	}

	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*24*days);
	X509_set_pubkey(cert, key_pair);

	// Its self signed so set the issuer name to be the same as the
	// subject.
	X509_NAME *name = NULL;
	name = X509_get_subject_name(cert);
	X509_set_issuer_name(cert, name);

	if (!X509_sign(cert, key_pair, EVP_sha1())) {
		//SSL_DEBUG(1, "Signing the certificate failed (reason=%s)! (X509_sign()).\n",
		///ERR_reason_error_string(ERR_get_error()));

		X509_free(cert);
		cert = NULL;
		goto out;
	}

out:
	if(key_pair)
		EVP_PKEY_free(key_pair);

	return cert;
}
