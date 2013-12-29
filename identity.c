#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "identity.h"
#include "pem.h"
#include "util/strv.h"

Identity *
identity_new(const char *name,
             const char *pem_key_pair,
             const char * const *search_terms)
{
	Identity *ident = (Identity *) malloc(sizeof(Identity));
	assert(ident != NULL);

	memset(ident, 0, sizeof(Identity));

	if(name != NULL)
		ident->name = strdup(name);
	if(search_terms != NULL)
		ident->search_terms = strvdup(search_terms);
	if(pem_key_pair != NULL) {
		ident->pem_key_pair = pem_parse_key_pair(pem_key_pair);
		if(ident->pem_key_pair == NULL) 
			goto err;
	}

	return ident;

err:
	identity_free(ident);

	return NULL;
}

void
identity_free(Identity *ident) {
	assert(ident);

	if(ident->name != NULL)
		free(ident->name);
	if(ident->pem_key_pair != NULL)
		free(ident->pem_key_pair);
	if(ident->search_terms != NULL)
		strvfree(ident->search_terms);

	free(ident);
	ident = NULL;
}

Identity *
identity_generate_new(const char const *name,
                      int rsa_bits,
                      const char const * const *search_terms)
{
	char *pem = pem_generate_key_pair(rsa_bits);
	Identity *ident = identity_new(name, pem, search_terms);
	free(pem);

	return ident;
}

const char const *
identity_get_pem_key_pair(Identity const *ident) {
	if(ident->pem_key_pair == NULL)
		return NULL;
	else
		return ident->pem_key_pair;
}

char *
identity_fingerprint_string(Identity const *ident) {
	const char const *pem = identity_get_pem_key_pair(ident);
	if(pem == NULL)
		return NULL;

	char *md = pem_fingerprint_string(pem);

	return md;
}

char *
identity_pem_public_key(Identity const *ident) {
	const char const *pem = identity_get_pem_key_pair(ident);
	return pem_public_key(pem);
}	
