/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 */
#include "spidermonkey.h"

#include <jsinterp.h>

#include <emu/emu.h>
#include <emu/emu_shellcode.h>
#include <emu/emu_memory.h>
#include <emu/emu_cpu.h>
#include <emu/emu_log.h>
#include <emu/emu_cpu_data.h>
#include <emu/emu_cpu_stack.h>
#include <emu/environment/emu_profile.h>
#include <emu/environment/emu_env.h>
#include <emu/environment/win32/emu_env_w32.h>
#include <emu/environment/win32/emu_env_w32_dll.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>
#include <emu/environment/win32/env_w32_dll_export_kernel32_hooks.h>


int check_buffer(jsval buffer)
{
        
    uint32_t length;
    length = JS_GetStringLength(JSVAL_TO_STRING(buffer));
    if (length > 65535)
    {
        fprintf(stderr,"WARNING: Long string with more than 65535 bytes! return -1 in developing mode");
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
    ptrdiff_t len;//, off, jmplen;
    uint32 type;
    JSAtom *atom;
    uintN index;
    JSObject *obj;
    jsval v;
    //const char *bytes;
    //jsint i;

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
//    fprintf(fp, "  %s", js_CodeName[op]);
    type = JOF_TYPE(cs->format);
    switch (type) {
      /* case JOF_BYTE: */
      /*   if (op == JSOP_TRAP) { */
      /*       op = JS_GetTrapOpcode(cx, script, pc); */
      /*       len = (ptrdiff_t) js_CodeSpec[op].length; */
      /*   } */
      /*   break; */

      /* case JOF_JUMP: */
      /* case JOF_JUMPX: */
      /*   off = GetJumpOffset(pc, pc); */
      /*   fprintf(fp, " %u (%d)", loc + off, off); */
      /*   break; */

      case JOF_ATOM:
      case JOF_OBJECT:
      case JOF_REGEXP:
        index = js_GetIndexFromBytecode(cx, script, pc, 0);
        if (type == JOF_ATOM) {
            JS_GET_SCRIPT_ATOM(script, index, atom);
            v = ATOM_KEY(atom);
        } else {
            if (type == JOF_OBJECT)
                JS_GET_SCRIPT_OBJECT(script, index, obj);
            else
                JS_GET_SCRIPT_REGEXP(script, index, obj);
            v = OBJECT_TO_JSVAL(obj);
        }
        return v;
        break;

      /* case JOF_UINT16: */
      /* case JOF_LOCAL: */
      /*   i = (jsint)GET_UINT16(pc); */
      /*   goto print_int; */

      /* case JOF_2BYTE: */
      /*   fprintf(fp, " %u", (uintN)pc[1]); */
      /*   break; */

      /* case JOF_TABLESWITCH: */
      /* case JOF_TABLESWITCHX: */
      /* { */
      /*   jsbytecode *pc2; */
      /*   jsint i, low, high; */

      /*   jmplen = (type == JOF_TABLESWITCH) ? JUMP_OFFSET_LEN */
      /*                                      : JUMPX_OFFSET_LEN; */
      /*   pc2 = pc; */
      /*   off = GetJumpOffset(pc, pc2); */
      /*   pc2 += jmplen; */
      /*   low = GET_JUMP_OFFSET(pc2); */
      /*   pc2 += JUMP_OFFSET_LEN; */
      /*   high = GET_JUMP_OFFSET(pc2); */
      /*   pc2 += JUMP_OFFSET_LEN; */
      /*   fprintf(fp, " defaultOffset %d low %d high %d", off, low, high); */
      /*   for (i = low; i <= high; i++) { */
      /*       off = GetJumpOffset(pc, pc2); */
      /*       fprintf(fp, "\n\t%d: %d", i, off); */
      /*       pc2 += jmplen; */
      /*   } */
      /*   len = 1 + pc2 - pc; */
      /*   break; */
      /* } */

      /* case JOF_LOOKUPSWITCH: */
      /* case JOF_LOOKUPSWITCHX: */
      /* { */
      /*   jsbytecode *pc2; */
      /*   jsatomid npairs; */

      /*   jmplen = (type == JOF_LOOKUPSWITCH) ? JUMP_OFFSET_LEN */
      /*                                       : JUMPX_OFFSET_LEN; */
      /*   pc2 = pc; */
      /*   off = GetJumpOffset(pc, pc2); */
      /*   pc2 += jmplen; */
      /*   npairs = GET_UINT16(pc2); */
      /*   pc2 += UINT16_LEN; */
      /*   fprintf(fp, " offset %d npairs %u", off, (uintN) npairs); */
      /*   while (npairs) { */
      /*       JS_GET_SCRIPT_ATOM(script, GET_INDEX(pc2), atom); */
      /*       pc2 += INDEX_LEN; */
      /*       off = GetJumpOffset(pc, pc2); */
      /*       pc2 += jmplen; */

      /*       bytes = ToDisassemblySource(cx, ATOM_KEY(atom)); */
      /*       if (!bytes) */
      /*           return 0; */
      /*       fprintf(fp, "\n\t%s: %d", bytes, off); */
      /*       npairs--; */
      /*   } */
      /*   len = 1 + pc2 - pc; */
      /*   break; */
      /* } */

      /* case JOF_QARG: */
      /*   fprintf(fp, " %u", GET_ARGNO(pc)); */
      /*   break; */

      /* case JOF_QVAR: */
      /*   fprintf(fp, " %u", GET_VARNO(pc)); */
      /*   break; */

      /* case JOF_SLOTATOM: */
      /* case JOF_SLOTOBJECT: */
      /*   fprintf(fp, " %u", GET_VARNO(pc)); */
      /*   index = js_GetIndexFromBytecode(cx, script, pc, VARNO_LEN); */
      /*   if (type == JOF_SLOTATOM) { */
      /*       JS_GET_SCRIPT_ATOM(script, index, atom); */
      /*       v = ATOM_KEY(atom); */
      /*   } else { */
      /*       JS_GET_SCRIPT_OBJECT(script, index, obj); */
      /*       v = OBJECT_TO_JSVAL(obj); */
      /*   } */
      /*   bytes = ToDisassemblySource(cx, v); */
      /*   if (!bytes) */
      /*       return 0; */
      /*   fprintf(fp, " %s", bytes); */
      /*   break; */

      /* case JOF_UINT24: */
      /*   JS_ASSERT(op == JSOP_UINT24); */
      /*   i = (jsint)GET_UINT24(pc); */
      /*   goto print_int; */

      /* case JOF_INT8: */
      /*   i = GET_INT8(pc); */
      /*   goto print_int; */

      /* case JOF_INT32: */
      /*   JS_ASSERT(op == JSOP_INT32); */
      /*   i = GET_INT32(pc); */
      /* print_int: */
      /*   fprintf(fp, " %d", i); */
      /*   break; */

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
            
            param = Py_BuildValue("is{}s#",
                                  -1,
                                  "Shellcode Detected!",
                                  bytes,
                                  length*sizeof(jschar));
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

/*=================== surpport for shellcode analysis  =================
 *
 */

uint32_t user_hook_URLDownloadToFile(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	printf("DEBUG: Hook me Captain Cook!\n");
	printf("DEBUG: %s:%i %s\n",__FILE__,__LINE__,__FUNCTION__);

	va_list vl;
	va_start(vl, hook);

	/*void * pCaller    = */(void)va_arg(vl, void *);
	char * szURL      = va_arg(vl, char *);
	char * szFileName = va_arg(vl, char *);
	/*int    dwReserved = */(void)va_arg(vl, int   );
	/*void * lpfnCB     = */(void)va_arg(vl, void *);

	va_end(vl);

        PyObject *list;
        list = hook->hook.win->userdata;
        if(list != NULL && szURL != NULL){
                PyList_Append(list,PyString_FromString(szURL));
        }
        printf("DEBUG: download %s -> %s\n", szURL, szFileName);
	return 0;
}


#define CODE_OFFSET 0x417000


int getpctest(char *opts_scode,uint32_t opts_size)
{
	struct emu *e = emu_new();
        int opts_offset;
        
	if ( (opts_offset = emu_shellcode_test(e, (uint8_t *)opts_scode, opts_size)) >= 0 )
		printf("DEBUG: %s offset = 0x%08x\n","SUCCESS", opts_offset);
	else
		printf("DEBUG: FAILED retvar:%d\n",opts_offset);

	emu_free(e);

	return opts_offset;
}

int run_shellcode(char *opts_scode, uint32_t opts_size, int opts_offset, uint32_t opts_steps, PyObject *urllist)
{
        struct emu *e = emu_new();
        int offset = getpctest(opts_scode,opts_size);
        if(offset >= 0) opts_offset = offset;

	struct emu_cpu *cpu = emu_cpu_get(e);
	struct emu_memory *mem = emu_memory_get(e);

	struct emu_env *env = emu_env_new(e);
	env->profile = emu_profile_new();
	printf("DEBUG: emulating shellcode size %d",opts_size);

	int j;
	for ( j=0;j<8;j++ )
	{
		emu_cpu_reg32_set(cpu,j , 0);
	}



	/* write the code to the offset */
	int static_offset = CODE_OFFSET;
	emu_memory_write_block(mem, static_offset, opts_scode,  opts_size);



	/* set eip to the code */
	emu_cpu_eip_set(emu_cpu_get(e), static_offset + opts_offset);

	emu_memory_write_block(mem, 0x0012fe98, opts_scode,  opts_size);
	emu_cpu_reg32_set(emu_cpu_get(e), esp, 0x0012fe98);




	emu_memory_write_dword(mem, 0xef787c3c,  4711);
	emu_memory_write_dword(mem, 0x0,  4711);
	emu_memory_write_dword(mem, 0x00416f9a,  4711);
	emu_memory_write_dword(mem, 0x0044fcf7, 4711);
	emu_memory_write_dword(mem, 0x00001265, 4711);
	emu_memory_write_dword(mem, 0x00002583, 4711);
	emu_memory_write_dword(mem, 0x00e000de, 4711);
	emu_memory_write_dword(mem, 0x01001265, 4711);
	emu_memory_write_dword(mem, 0x8a000066, 4711);

	/* set the flags */
	emu_cpu_eflags_set(cpu, 0);

	/* IAT for sqlslammer */
	emu_memory_write_dword(mem, 0x42AE1018, 0x7c801D77);
	emu_memory_write_dword(mem, 0x42ae1010, 0x7c80ADA0);
	emu_memory_write_dword(mem, 0x7c80ADA0, 0x51EC8B55);

	if ( env == NULL )
	{
		fprintf(stderr,"%s \n", emu_strerror(e));
		fprintf(stderr,"%s \n", strerror(emu_errno(e)));
		return -1;
	}

	emu_env_w32_load_dll(env->env.win, "urlmon.dll");
        emu_env_w32_export_hook(env, "URLDownloadToFileA", user_hook_URLDownloadToFile, urllist);


        j=0;

	int ret; 
	uint32_t eipsave = 0;
        
	for ( j=0;j<opts_steps;j++ )
	{
                //emu_log_level_set(emu_logging_get(e),EMU_LOG_DEBUG);
                //emu_cpu_debug_print(cpu);
                //emu_log_level_set(emu_logging_get(e),EMU_LOG_NONE);

		if ( cpu->repeat_current_instr == false )
			eipsave = emu_cpu_eip_get(emu_cpu_get(e));

		struct emu_env_hook *hook = NULL;

		ret = 0;

		hook = emu_env_w32_eip_check(env);

		if ( hook != NULL )
		{
                        if ( hook->hook.win->fnhook == NULL )
			{
				fprintf(stderr,"unhooked call to %s\n", hook->hook.win->fnname);
				break;
			}
                        
		}
		else
		{

			ret = emu_cpu_parse(emu_cpu_get(e));
                        
                        emu_log_level_set(emu_logging_get(e),EMU_LOG_DEBUG);
                        logDebug(e, "%s\n", cpu->instr_string);
                        emu_log_level_set(emu_logging_get(e),EMU_LOG_NONE);

			struct emu_env_hook *hook =NULL;

			if ( ret != -1 )
			{
				if ( hook == NULL )
				{
                                        emu_log_level_set(emu_logging_get(e),EMU_LOG_DEBUG);
                                        ret = emu_cpu_step(emu_cpu_get(e));
                                        emu_log_level_set(emu_logging_get(e),EMU_LOG_NONE);
				}
				else
				{
                                        fprintf(2,"DEBUG: Why here?\n");
					/* if ( hook->hook.lin->fnhook  */
					/* 	hook->hook.lin->fnhook(env, hook); */
					/* else */
					/* 	break; */
				}
			}

			if ( ret == -1 )
			{
				//printf("cpu error %s\n", emu_strerror(e));
				break;
			}
		}
	}

	printf("stepcount %i\n",j);

	emu_profile_debug(env->profile);//Print profile
        emu_free(e);
	return 0;
}

#endif
