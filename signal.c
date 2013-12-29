#include <stdlib.h>
#include <assert.h>

#include "signal.h"

Signal *
signal_new() {
	Signal *sig = (Signal *) malloc(sizeof(Signal));
	assert(sig);

	sig->callbacks = NULL;

	return sig;
}

void
signal_on(Signal *sig, Callback cb, void *user_arg) {
	CallbackList *l = (CallbackList *) malloc(sizeof(CallbackList));
	l->data = cb;
	l->user_arg = user_arg;

	l->next = sig->callbacks;
	sig->callbacks = l;
}

void
signal_emit(Signal *sig, ...) {
	va_list args;
	va_start(args, sig);

	int res;
	CallbackList *iter = sig->callbacks;
	while(iter != NULL) {
		res = iter->data(iter->user_arg, args);
		iter = iter->next;
	}

	va_end(args); 

	sig->emit_counter++;
}

void
signal_free(Signal *sig) {
	CallbackList *iter = sig->callbacks;
	CallbackList *prev;

	while(iter != NULL) {
		prev = iter;
		iter = iter->next;
		free(prev);
	}

	free(sig);
}
