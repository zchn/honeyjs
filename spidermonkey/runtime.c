/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * Copyright 2009 Paul J. Davis <paul.joseph.davis@gmail.com>
 *
 * This file is part of the python-spidermonkey package released
 * under the MIT license.
 *
 */

#include "spidermonkey.h"


JSTrapStatus js_intterupt_handler(JSContext *cx, JSScript *script, jsbytecode *pc, jsval *rval,void *closure)
{
    JSOp opcode = 0;
    JSStackFrame * fp = NULL;
    jsval r_val = 0;
    jsval l_val = 0;
    
    /* TODO:these should be stored in the context's private data area.
      global top_value_has_sc
    global malvalues
    */
    
    opcode =  JS_GetTrapOpcode(cx, script, pc);
    fp = NULL;
    JS_FrameIterator(cx,&fp);
    r_val = l_val = 0;
    switch(opcode)
    {
    case JSOP_SETNAME:
    case JSOP_SETPROP:
    {
        r_val = fp->regs->sp[-1];
        l_val = get_opcode_arg(cx,script,pc);
        break;
    }
    case JSOP_SETELEM:
    {
        r_val = fp->regs->sp[-1];
        l_val = fp->regs->sp[-3];
        break;
    }
    case JSOP_SETVAR:
    {
        r_val = fp->regs->sp[-1];
        l_val = (jsval)&(fp->vars[GET_VARNO(pc)]); // TODO: FIXIT
        break;
    }
    case JSOP_SETARG:
    {
        r_val = fp->regs->sp[-1];
        l_val = (jsval)&(fp->argv[GET_ARGNO(pc)]); // TODO: FIXIT
        break;
    }
    }
    if(r_val != 0 &&
       JSVAL_IS_STRING(r_val) &&
       JS_GetStringLength(JSVAL_TO_STRING(r_val)) > 30) //TODO: Adjust the threshold
    {
        int r = 0;
        r = check_buffer(r_val);
        if(r >= 0)
        {
            //Shellcode DETECTED!
            PyObject* alert = NULL;
            PyObject* param = NULL;
            jschar *jschars = NULL;
            char *bytes = NULL;
            Context* pycx = NULL;
            int length = 0;
            jschars = JS_GetStringChars(JSVAL_TO_STRING(r_val));
            bytes = (char *)jschars;
            length = JS_GetStringLength(JSVAL_TO_STRING(r_val));
            
            param = Py_BuildValue("is{}s#",
                                  -1,
                                  "Shellcode Detected!",
                                  bytes,
                                  length*sizeof(jschar));
            if(param == NULL) goto error;
            
            alert = PyObject_CallObject((PyObject*)ShellcodeAlertType,param);
            if(alert == NULL) goto error;
            pycx = (Context*) JS_GetContextPrivate(jscx);

            if(PyList_Append(pycx->alertlist,alert) != 0)
            {
                goto error;
            }
            //TODO: FIXME: is it necesary to DECREF alert?
            
            /*         if rt.malvariables.has_key(l_val): */
            /*             alert = rt.malvariables[l_val] */
            /*         else: */
            /*             alert = Alert(0,l_val,"Shellcode Detected",{"hit":0}) */
            /*             rt.malvariables[l_val]=alert */
            /*             rt.alerts.append(alert) */
            /*         alert.misc["hit"]+=1 */

            /*         jschars = JS_GetStringChars(JSVAL_TO_STRING(r_val)) */
            /*         bytes = <char *>jschars */
            /*         length = JS_GetStringLength(JSVAL_TO_STRING(r_val)) */
            /*         s = PyString_FromStringAndSize(bytes, length*2)#sizeof(jschar)) */
            /*         alert.misc["contents"] = s */
            /*         alert.misc["offset"] = r */
            /*         #f = open("shellcodes/"+str(l_val)+".sc","w") */
            /*         #f.write(s) */
            /*         #f.close() */
            /*         #print "DEBUG: !!!SC DETECTED at "+str(l_val)+"="+str(r_val)+"size:"+str(length*2) */
        }
    }
    return JSTRAP_CONTINUE;
error:
    return  JSTRAP_ERROR;
}


Pyobject*
Runtime_new(PyTypeObject* type, PyObject* args, PyObject* kwargs)
{
    Runtime* self = NULL;
    unsigned int stacksize = 0x2000000; // 32 MiB heap size.

    if(!PyArg_ParseTuple(args, "|I", &stacksize)) goto error;

    self = (Runtime*) type->tp_alloc(type, 0);
    if(self == NULL) goto error;

    self->rt = JS_NewRuntime(stacksize);
    if(self->rt == NULL)
    {
        PyErr_SetString(JSError, "Failed to allocate new JSRuntime.");
        goto error;
    }

    self->is_traced = 0;
    
    goto success;

error:
    Py_XDECREF(self);
    self = NULL;

success:
    return (PyObject*) self;
}

int
Runtime_init(Runtime* self, PyObject* args, PyObject* kwargs)
{
    return 0;
}

void
Runtime_dealloc(Runtime* self)
{
    if(self->rt != NULL)
    {
        JS_DestroyRuntime(self->rt);
    }
}

PyObject*
Runtime_new_context(Runtime* self, PyObject* args, PyObject* kwargs)
{
    PyObject* cx = NULL;
    PyObject* tpl = NULL;
    PyObject* global = Py_None;
    PyObject* access = Py_None;
    PyObject* alertlist = Py_None;

    char* keywords[] = {"glbl", "access", "alertlist", NULL};

    if(!PyArg_ParseTupleAndKeywords(
        args, kwargs,
        "|OOO",
        keywords,
        &global,
        &access,
        &alertlist
    )) goto error;

    tpl = Py_BuildValue("OOOO", self, global, access, alertlist);
    if(tpl == NULL) goto error;

    cx = PyObject_CallObject((PyObject*) ContextType, tpl);
    goto success;

error:
    Py_XDECREF(cx);

success:
    Py_XDECREF(tpl);
    return cx;
}

PyObject*
Runtime_switch_tracing(Runtime* self, PyObject* args, PyObject* kwargs)
{
    int status = self->is_traced;

    char* keywords[] = {"status",  NULL};

    if(!PyArg_ParseTupleAndKeywords(
        args, kwargs,
        "|i",
        keywords,
        &status
    )) goto error;

    if ( status != self->is_traced )
    {
        if ( status == 0 )
        {
             JS_ClearInterrupt(JSRuntime *rt, JSTrapHandler *handlerp, void **closurep);
        }
        else
        {
             JS_SetInterrupt(JSRuntime *rt, JSTrapHandler handler, void *closure);
        }
    }
    goto success;

error:
    Py_XDECREF(cx);

success:
    Py_XDECREF(tpl);
    return cx;
}



static PyMemberDef Runtime_members[] = {
    {NULL}
};

static PyMethodDef Runtime_methods[] = {
    {
        "new_context",
        (PyCFunction)Runtime_new_context,
        METH_VARARGS | METH_KEYWORDS,
        "Create a new JavaScript Context."
    },
    {NULL}
};

PyTypeObject _RuntimeType = {
    PyObject_HEAD_INIT(NULL)
    0,                                          /*ob_size*/
    "spidermonkey.Runtime",                     /*tp_name*/
    sizeof(Runtime),                            /*tp_basicsize*/
    0,                                          /*tp_itemsize*/
    (destructor)Runtime_dealloc,                /*tp_dealloc*/
    0,                                          /*tp_print*/
    0,                                          /*tp_getattr*/
    0,                                          /*tp_setattr*/
    0,                                          /*tp_compare*/
    0,                                          /*tp_repr*/
    0,                                          /*tp_as_number*/
    0,                                          /*tp_as_sequence*/
    0,                                          /*tp_as_mapping*/
    0,                                          /*tp_hash*/
    0,                                          /*tp_call*/
    0,                                          /*tp_str*/
    0,                                          /*tp_getattro*/
    0,                                          /*tp_setattro*/
    0,                                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,   /*tp_flags*/
    "JavaScript Runtime",                       /*tp_doc*/
    0,		                                    /*tp_traverse*/
    0,		                                    /*tp_clear*/
    0,		                                    /*tp_richcompare*/
    0,		                                    /*tp_weaklistoffset*/
    0,		                                    /*tp_iter*/
    0,		                                    /*tp_iternext*/
    Runtime_methods,                            /*tp_methods*/
    Runtime_members,                            /*tp_members*/
    0,                                          /*tp_getset*/
    0,                                          /*tp_base*/
    0,                                          /*tp_dict*/
    0,                                          /*tp_descr_get*/
    0,                                          /*tp_descr_set*/
    0,                                          /*tp_dictoffset*/
    (initproc)Runtime_init,                     /*tp_init*/
    0,                                          /*tp_alloc*/
    Runtime_new,                                /*tp_new*/
};

