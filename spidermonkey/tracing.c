/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 */
#include "spidermonkey.h"

#include <jsinterp.h>

#include <emu/emu.h>
#include <emu/emu_shellcode.h>

#define FETCH_OPND(n)   (fp->sp[n])

int check_buffer(jsval buffer)
{
    //fprintf(stderr,"DEBUG:Checking buffer\n");
    uint32_t length;
    length = JS_GetStringLength(JSVAL_TO_STRING(buffer));
    if (length > 65535)
    {
        fprintf(stderr,"WARNING: Long string with more than 65535 bytes! return -1 in developing mode\n");
        return -1;
    }
    jschar *bytes;
    bytes = JS_GetStringChars(JSVAL_TO_STRING(buffer));
    struct emu * e;
    e = emu_new();
    
    int result;
    result = emu_shellcode_test(e, (unsigned char *)bytes, length * sizeof(jschar));
    emu_free(e);
    if (result >= 0)
        return result;

    e = emu_new();
    result = emu_shellcode_test(e, (unsigned char *)bytes, length * sizeof(jschar));
    emu_free(e);
    return result;
}


jsval
get_opcode_arg(JSContext *cx, JSScript *script, jsbytecode *pc)
{
    JSOp op;
    const JSCodeSpec *cs;
    ptrdiff_t len;
    uint32 type;
    JSAtom *atom;
    jsval v;

    op = (JSOp)*pc;
    if (op >= JSOP_LIMIT) {
        char numBuf1[12], numBuf2[12];
        JS_snprintf(numBuf1, sizeof numBuf1, "%d", op);
        JS_snprintf(numBuf2, sizeof numBuf2, "%d", JSOP_LIMIT);
        fprintf(stderr,"ERROR in get_opcode_arg: unknown bytecode %s %s\n",numBuf1,numBuf2);
        return 0;
    }
    cs = &js_CodeSpec[op];
    len = (ptrdiff_t) cs->length;
    type = cs->format & JOF_TYPEMASK;

    switch (type) {
      case JOF_CONST:
        atom = GET_ATOM(cx, script, pc);
        v = ATOM_KEY(atom);
        return v;
        break;

      default: {
        char numBuf[12];
        JS_snprintf(numBuf, sizeof numBuf, "%lx", (unsigned long) cs->format);
        fprintf(stderr,"ERROR in get_opcode_arg: Unknown format %s\n",numBuf);
        return 0;
      }
    }
}


JSTrapStatus js_interrupt_handler(JSContext *cx, JSScript *script, jsbytecode *pc, jsval *rval,void *closure)
{
    JSOp opcode = 0;
    JSStackFrame * fp = NULL;
    jsval r_val = 0;
    jsval l_val = 0;
    const JSCodeSpec *cs;
        
    /* TODO:these should be stored in the context's private data area.
       global top_value_has_sc
       global malvalues
    */
    
    opcode = (JSOp)*pc;//JS_GetTrapOpcode(cx, script, pc);//in 1.8.0, use this
    cs = &js_CodeSpec[opcode];
    //fprintf(stderr, "DEBUG:now  %s\n", cs->name);

    fp = NULL;
    JS_FrameIterator(cx,&fp);
    r_val = l_val = 0;
    switch(opcode)
    {
    case JSOP_SETNAME:
    case JSOP_SETPROP:
    {
        r_val = FETCH_OPND(-1);
        l_val = get_opcode_arg(cx,script,pc);
        break;
    }
    case JSOP_SETELEM:
    {
        r_val = FETCH_OPND(-1);
        l_val = FETCH_OPND(-3);
        break;
    }
    case JSOP_SETVAR:
    {
        r_val = FETCH_OPND(-1);
        l_val = (jsval)&(fp->vars[GET_VARNO(pc)]); // TODO: FIXIT
        break;
    }
    case JSOP_SETARG:
    {
        r_val = FETCH_OPND(-1);
        l_val = (jsval)&(fp->argv[GET_ARGNO(pc)]); // TODO: FIXIT
        break;
    }
    default:
        break;
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
            fprintf(stderr,"\nDEBUG: SHELLCODE DETECTED!\n");
            PyObject* alert = NULL;
            PyObject* param = NULL;
            jschar *jschars = NULL;
            char *bytes = NULL;
            Context* pycx = NULL;
            int length = 0;
            jschars = JS_GetStringChars(JSVAL_TO_STRING(r_val));
            bytes = (char *)jschars;
            length = JS_GetStringLength(JSVAL_TO_STRING(r_val));
            
            param = Py_BuildValue("iss#i",
                                  -1,
                                  "Shellcode Detected!",
                                  bytes,
                                  length*sizeof(jschar),
                                  r);
            if(param == NULL) goto error;
            
            alert = PyObject_CallObject((PyObject*)ShellcodeAlertType,param);
            if(alert == NULL) goto error;
            pycx = (Context*) JS_GetContextPrivate(cx);

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


#if 0


#endif
