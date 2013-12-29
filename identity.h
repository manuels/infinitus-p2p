#ifndef __IDENTITIY_H__
#define __IDENTITIY_H__

struct Identity_ {
	char *name;
	char *pem_key_pair;
	char **search_terms;
};

typedef struct Identity_ Identity;

void *
identity_fingerprint(Identity const *ident);

char *
identity_fingerprint_string(Identity const *ident);

Identity *
identity_new(const char *name,
             const char *pem_key_pair,
             const char * const *search_terms);

void
identity_free(Identity *ident);

Identity *
identity_generate_new(const char const *name,
                      int rsa_bits,
                      const char const * const *search_terms);

char *
identity_pem_public_key(Identity const *ident);

const char const *
identity_get_pem_key_pair(Identity const *ident);

#endif
