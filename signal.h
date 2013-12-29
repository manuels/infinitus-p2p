#ifndef __SIGNAL_H__
#define __SIGNAL_H__

#include <stdarg.h>

typedef int (*Callback)(void *, va_list);

struct CallbackList_ {
	Callback data;
	void *user_arg;
	struct CallbackList_ *next;
};

typedef struct CallbackList_ CallbackList;

struct Signal_ {
	CallbackList *callbacks;
	int emit_counter;
};

typedef struct Signal_ Signal;

Signal *
signal_new();

#endif
