#include <string.h>
#include <stdlib.h>
#include <assert.h>

size_t
strvlen(const char * const *strv) {
	if(strv == NULL)
		return 0;

	size_t i = 0;
	char * const *iter = (char * const *) strv;
	while(*iter != NULL) {
		i++;
		iter++;
	}

	return i;
}

char **
strvdup(const char * const *strv) {
	if(strv == NULL)
		return NULL;

	size_t len = strvlen(strv);
	char ** dup = (char **) malloc(sizeof(char *)*(1+len));
	assert(dup != NULL);

	char * const *iter0 = (char * const *) strv;
	char **iter1 = dup;
	while(*iter0 != NULL) {
		*iter1 = strdup(*iter0);
		iter0++;
		iter1++;
	}
	*iter1 = NULL;

	return dup;
}

void
strvfree(char **strv) {
	if(strv == NULL)
		return;

	char **iter = strv;
	while(*iter != NULL) {
		free(*iter);
		iter++;
	}

	free(strv);
}
