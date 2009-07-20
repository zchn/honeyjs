/*
 * Copyright 2009 Paul J. Davis <paul.joseph.davis@gmail.com>
 *
 * This file is part of the python-spidermonkey package released
 * under the MIT license.
 *
 */

#include "spidermonkey.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>


void dump(int signo)
{
        char buf[1024];
        char cmd[1024];
        FILE *fh;

        snprintf(buf, sizeof(buf), "/proc/%d/cmdline", getpid());
        if(!(fh = fopen(buf, "r")))
                exit(0);
        if(!fgets(buf, sizeof(buf), fh))
                exit(0);
        fclose(fh);
        if(buf[strlen(buf) - 1] == '\n')
                buf[strlen(buf) - 1] = '\0';
        snprintf(cmd, sizeof(cmd), "gdb %s %d", buf, getpid());
        system(cmd);
        
        exit(0);
}

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif

PyObject* SpidermonkeyModule = NULL;
PyTypeObject* RuntimeType = NULL;
PyTypeObject* ContextType = NULL;
PyTypeObject* ObjectType = NULL;
PyTypeObject* ArrayType = NULL;
PyTypeObject* FunctionType = NULL;
PyTypeObject* IteratorType = NULL;
PyTypeObject* HashCObjType = NULL;
PyObject* JSError = NULL;

PyObject* hcalertModule = NULL;
PyTypeObject* HeapsprayAlertType = NULL;
PyTypeObject* ShellcodeAlertType = NULL;


static PyMethodDef spidermonkey_methods[] = {
    {NULL}
};

PyMODINIT_FUNC
initspidermonkey(void)
{
    PyObject* m;
    PyObject* r;
    PyObject* str;

    //Only for core DEBUG
    signal(SIGSEGV, &dump);

    if(PyType_Ready(&_RuntimeType) < 0) return;
    if(PyType_Ready(&_ContextType) < 0) return;
    if(PyType_Ready(&_ObjectType) < 0) return;

    _ArrayType.tp_base = &_ObjectType;
    if(PyType_Ready(&_ArrayType) < 0) return;

    _FunctionType.tp_base = &_ObjectType;
    if(PyType_Ready(&_FunctionType) < 0) return;

    if(PyType_Ready(&_IteratorType) < 0) return;

    if(PyType_Ready(&_HashCObjType) < 0) return;
    
    m = Py_InitModule3("spidermonkey", spidermonkey_methods,
            "The Python-Spidermonkey bridge.");

    if(m == NULL)
    {
        return;
    }

    RuntimeType = &_RuntimeType;
    Py_INCREF(RuntimeType);
    PyModule_AddObject(m, "Runtime", (PyObject*) RuntimeType);

    ContextType = &_ContextType;
    Py_INCREF(ContextType);
    PyModule_AddObject(m, "Context", (PyObject*) ContextType);

    ObjectType = &_ObjectType;
    Py_INCREF(ObjectType);
    PyModule_AddObject(m, "Object", (PyObject*) ObjectType);

    ArrayType = &_ArrayType;
    Py_INCREF(ArrayType);
    PyModule_AddObject(m, "Array", (PyObject*) ArrayType);

    FunctionType = &_FunctionType;
    Py_INCREF(FunctionType);
    PyModule_AddObject(m, "Function", (PyObject*) FunctionType);

    IteratorType = &_IteratorType;
    Py_INCREF(IteratorType);
    // No module access on purpose.

    HashCObjType = &_HashCObjType;
    Py_INCREF(HashCObjType);
    // Don't add access from the module on purpose.

    JSError = PyErr_NewException("spidermonkey.JSError", NULL, NULL);
    PyModule_AddObject(m, "JSError", JSError);
    
    SpidermonkeyModule = m;

    hcalertModule = PyImport_ImportModule("hcalert");
    if ( hcalertModule == NULL) return;    
    
    str = PyString_FromString("ShellcodeAlert");
    if (str == NULL) return;
    r = PyObject_GetAttr(hcalertModule,str);
    Py_DECREF(str);
    str = NULL;
    //Check if r is a type object
    if( !PyCallable_Check(r) )
    {
        PyErr_SetString(PyExc_TypeError,
                        "hcalert.ShellcodeAlert must be callable");
        //TODO: just Callable? or must type object?
        return;
    }
    ShellcodeAlertType = (PyTypeObject *)r;
    
    str = PyString_FromString("HeapsprayAlert");
    if (str == NULL) return;
    r = PyObject_GetAttr(hcalertModule,str);
    Py_DECREF(str);
    str = NULL;
    //Check if r is a type object
    if( !PyCallable_Check(r) )
    {
        PyErr_SetString(PyExc_TypeError,
                        "hcalert.HeapsprayAlert must be callable");
        //TODO: just Callable? or must type object?
        return;
    }
    HeapsprayAlertType = (PyTypeObject *)r;    
}
