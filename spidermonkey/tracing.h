#ifndef _TRACING_H_
#define _TRACING_H_

#include <Python.h>
#include "structmember.h"

extern JSTrapStatus js_interrupt_handler(JSContext *cx, JSScript *script, jsbytecode *pc, jsval *rval,void *closure);


#endif /* _TRACING_H_ */
