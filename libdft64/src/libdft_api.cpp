/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <string>
#include "libdft_api.h"
#include "branch_pred.h"
#include "debug.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "syscall_hook.h"
#include "taint_info.h"

using std::string;

/* threads context counter */
static size_t tctx_ct = 0;
/* threads context */
thread_ctx_t *threads_ctx = NULL;

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* ins descriptors */
ins_desc_t ins_desc[XED_ICLASS_LAST];

/* target region finding */
int taint_logging;
int first_target_call;
ADDRINT ret_addr;
ADDRINT ret_sp;

/* taint instruction info */
extern FuncNode *root_node;
extern FuncNode *cur_node;
extern int seq_num;

extern map<uint64_t, uint64_t> bbl_list;

/*
 * thread start callback (analysis function)
 *
 * allocate space for the syscall context and VCPUs (i.e., thread context)
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @flags:	OS specific flags for the new thread
 * @v:		callback value
 */
static void thread_alloc(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v) {
  /* store the old threads context */
  thread_ctx_t *tctx_prev = threads_ctx;

  /*
   * we need more thread contexts; optimized branch (not so frequent);
   *
   * NOTE: in case the tid is greater than tctx_ct + THREAD_CTX_BLK we
   * need to loop in order to allocate enough thread contexts
   */
  while (unlikely(tid >= tctx_ct)) {
    /* reallocate space; optimized branch */
    if (unlikely((threads_ctx = (thread_ctx_t *)realloc(
                      threads_ctx, (tctx_ct + THREAD_CTX_BLK) *
                                       sizeof(thread_ctx_t))) == NULL)) {
      /* failed; this is fatal we need to terminate */

      /* cleanup */
      free(tctx_prev);

      /* error message */
      fprintf(stderr, "%s:%u", __func__, __LINE__);

      /* die */
      libdft_die();
    }

    /* success; patch the counter */
    tctx_ct += THREAD_CTX_BLK;
  }
}

// thread_free?

/*
 * syscall enter notification (analysis function)
 *
 * save the system call context and invoke any pre-syscall callback
 * functions that have been registered
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
static void sysenter_save(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std,
                          VOID *v) {
  /* get the syscall number */
  size_t syscall_nr = PIN_GetSyscallNumber(ctx, std);
  // LOGD("[syscall] %ld\n", syscall_nr);
  /* unknown syscall; optimized branch */
  if (unlikely(syscall_nr >= SYSCALL_MAX)) {
    fprintf(stderr, "%s:%u: unknown syscall(num=%lu)", __func__, __LINE__,
            syscall_nr);
    /* syscall number is set to -1; hint for the sysexit_save() */
    threads_ctx[tid].syscall_ctx.nr = -1;
    /* no context save and no pre-syscall callback invocation */
    return;
  }

  /* pass the system call number to sysexit_save() */
  threads_ctx[tid].syscall_ctx.nr = syscall_nr;

  /*
   * check if we need to save the arguments for that syscall
   *
   * we save only when we have a callback registered or the syscall
   * returns a value in the arguments
   */
  if (syscall_desc[syscall_nr].save_args |
      syscall_desc[syscall_nr].retval_args) {
    /*
     * dump only the appropriate number of arguments
     * or yet another lame way to avoid a loop (vpk)
     */
    switch (syscall_desc[syscall_nr].nargs) {
    /* 6 */
    case SYSCALL_ARG5 + 1:
      threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG5] =
          PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG5);
      /* 5 */
    case SYSCALL_ARG4 + 1:
      threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG4] =
          PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG4);
      /* 4 */
    case SYSCALL_ARG3 + 1:
      threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG3] =
          PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG3);
      /* 3 */
    case SYSCALL_ARG2 + 1:
      threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG2] =
          PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG2);
      /* 2 */
    case SYSCALL_ARG1 + 1:
      threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG1] =
          PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG1);
      /* 1 */
    case SYSCALL_ARG0 + 1:
      threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG0] =
          PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG0);
      /* default */
    default:
      /* nothing to do */
      break;
    }

    /*
     * dump the architectural state of the processor;
     * saved as "auxiliary" data
     */
    threads_ctx[tid].syscall_ctx.aux = ctx;

    /* call the pre-syscall callback (if any); optimized branch */
    if (unlikely(syscall_desc[syscall_nr].pre != NULL))
      syscall_desc[syscall_nr].pre(tid, &threads_ctx[tid].syscall_ctx);
  }
}

/*
 * syscall exit notification (analysis function)
 *
 * save the system call context and invoke any post-syscall callback
 * functions that have been registered
 *
 * NOTE: it performs tag cleanup for the syscalls that have side-effects in
 * their arguments
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
static void sysexit_save(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std,
                         VOID *v) {
  /* iterator */
  size_t i;

  /* get the syscall number */
  int syscall_nr = threads_ctx[tid].syscall_ctx.nr;

  /* unknown syscall; optimized branch */
  if (unlikely(syscall_nr < 0)) {
    fprintf(stderr, "%s:%u: unknown syscall(num=%d)", __func__, __LINE__,
            syscall_nr);
    /* no context save and no pre-syscall callback invocation */
    return;
  }

  /*
   * return value of a syscall is store in EAX, usually it is not a pointer
   * So need to clean the tag of EAX, if it is, the post function should
   * retag EAX
   */

  /*
   * check if we need to save the arguments for that syscall
   *
   * we save only when we have a callback registered or the syscall
   * returns a value in the arguments
   */
  if (syscall_desc[syscall_nr].save_args |
      syscall_desc[syscall_nr].retval_args) {
    /* dump only the appropriate number of arguments */
    threads_ctx[tid].syscall_ctx.ret = PIN_GetSyscallReturn(ctx, std);

    /*
     * dump the architectural state of the processor;
     * saved as "auxiliary" data
     */
    threads_ctx[tid].syscall_ctx.aux = ctx;

    /* thread_ctx[tid].syscall_ctx.errno =
       PIN_GetSyscallErrno(ctx, std); */

    /* call the post-syscall callback (if any) */
    if (syscall_desc[syscall_nr].post != NULL) {
      syscall_desc[syscall_nr].post(tid, &threads_ctx[tid].syscall_ctx);
    } else {
      /* default post-syscall handling */

      /*
       * the syscall failed; typically 0 and positive
       * return values indicate success
       */
      if (threads_ctx[tid].syscall_ctx.ret < 0)
        /* no need to do anything */
        return;

      /* traverse the arguments map */
      for (i = 0; i < syscall_desc[syscall_nr].nargs; i++)
        /* analyze each argument */
        if (unlikely(syscall_desc[syscall_nr].map_args[i] > 0))
          /* sanity check -- probably non needed */
          if (likely((void *)threads_ctx[tid].syscall_ctx.arg[i] != NULL))
            /*
             * argument i is changed by the system call;
             * the length of the change is given by
             * map_args[i]
             */
            tagmap_clrn(threads_ctx[tid].syscall_ctx.arg[i],
                        syscall_desc[syscall_nr].map_args[i]);
    }
  }
}

/*
 * trace inspection (instrumentation function)
 *
 * traverse the basic blocks (BBLs) on the trace and
 * inspect every instruction for instrumenting it
 * accordingly
 *
 * @trace:      instructions trace; given by PIN
 */
static void hook_call_ins(ADDRINT applicationIP, ADDRINT sp, ADDRINT target) {
  string caller_name;
  string callee_name;
  FuncNode *new_node;

  if (root_node == NULL || cur_node == NULL) {
    return;
  }

  caller_name = RTN_FindNameByAddress(applicationIP).c_str();
  callee_name = RTN_FindNameByAddress(target).c_str();

  if (cur_node->func_name.compare(".plt.sec") == 0) {
    FuncNode *caller_node = cur_node->caller;
    new_node = new FuncNode;

    new_node->caller = caller_node;
    new_node->func_name = caller_name;
    new_node->score = 0;
    new_node->seq_num = seq_num++;
    new_node->depth = caller_node->depth + 1;
    new_node->taint_inst_used = 0;
    new_node->modified_tag_used = 0;
    new_node->origianl_tag_used = 0;

    caller_node->callee.pop_back();
    caller_node->callee.push_back(new_node);
    
    delete cur_node;
    cur_node = new_node;
  } else if (cur_node->func_name.compare(caller_name) != 0) {
    // For Debug
    //cout << "=========wrong call===========" << endl;
    //cout << "cur_node : " << cur_node->func_name << endl;
    //cout << "caller : " << caller_name << endl;
    //cout << "callee : " << callee_name << endl;
    //printf("cur node & caller are mismatch\n");

    new_node = new FuncNode;
    new_node->caller = cur_node;
    new_node->func_name = caller_name;
    new_node->score = 0;
    new_node->seq_num = seq_num++;
    new_node->depth = new_node->caller->depth + 1;
    new_node->taint_inst_used = 0;
    new_node->modified_tag_used = 0;
    new_node->origianl_tag_used = 0;
    
    cur_node->callee.push_back(new_node);
    cur_node = new_node;
  }

  new_node = new FuncNode;
  //new_node = (FuncNode *)malloc(sizeof(FuncNode));

  new_node->caller = cur_node;
  new_node->func_name = callee_name;
  new_node->stack_base = 0;
  new_node->score = 0;
  new_node->seq_num = seq_num++;
  new_node->depth = new_node->caller->depth + 1;
  new_node->taint_inst_used = 0;
  new_node->modified_tag_used = 0;
  new_node->origianl_tag_used = 0;

  //cout << "==============call============" << endl;
  //cout << "cur_node : " << cur_node->func_name << endl;
  //cout << "new_node : " << new_node->func_name << endl;

  cur_node->callee.push_back(new_node);
  cur_node = new_node;
}

static void hook_ret_ins(ADDRINT applicationIP, ADDRINT sp, ADDRINT target) {
  //cout << "===========ret=============" << endl;
  string caller_name;
  string callee_name;
  FuncNode *tmp_node;

  if (root_node == NULL || cur_node == NULL) {
    return;
  }

  callee_name = RTN_FindNameByAddress(applicationIP).c_str();
  caller_name = RTN_FindNameByAddress(target).c_str();

  //cout << "callee name : " << callee_name << endl;
  //cout << "caller name : " << caller_name << endl;
 
  if (cur_node->func_name.compare(callee_name) != 0) {
    // For Debug
    //printf("cur node & callee are mismatch\n");
    //return;
  }

  tmp_node = cur_node;
  while (tmp_node != NULL) {
    if (tmp_node->func_name.compare(caller_name) == 0) {
      //cout << "same in return" << endl;
      cur_node = tmp_node;
      //cout << "cur_node : " << cur_node->func_name << endl;
      return;
    }
    tmp_node = tmp_node->caller;
  }

  // Cannot reach here
  printf("error at hook ret call\n");
}

static void hook_main_call(ADDRINT applicationIP, ADDRINT sp) {
  string func_name = RTN_FindNameByAddress(applicationIP).c_str();
  FuncNode *new_node;

  //cout << "hook main call : " << func_name << endl;

  if (root_node != NULL) {
    //cout << "root node is not null" << endl;
    return;
  }
  if (func_name.compare("main") != 0) {
    //cout << "not main" << endl;
    return;
  }
  cout << "Found main" << endl;

  new_node = new FuncNode;
  //new_node = (FuncNode *)malloc(sizeof(FuncNode));

  new_node->caller = NULL;
  new_node->func_name = func_name;
  new_node->stack_base = sp;
  new_node->score = 0;
  new_node->seq_num = seq_num++;
  new_node->depth = 0;
  new_node->taint_inst_used = 0;
  new_node->modified_tag_used = 0;
  new_node->origianl_tag_used = 0;

  root_node = new_node;
  cur_node = new_node;
}

extern map<string, int> func_called;
static void hook_target_call(ADDRINT applicationIP, ADDRINT sp) {
  string func_name = RTN_FindNameByAddress(applicationIP).c_str();

  func_called[func_name] = 1;
  
  if (applicationIP == ret_addr && sp == ret_sp && taint_logging == 1) {
    taint_logging = 0;
  }
  
  if (func_name.compare(target2find) != 0) {
    return;
  }

  if (first_target_call == 0) {
    cout << "Found target" << endl;
    first_target_call = 1;
    taint_logging = 1;
    ret_addr = *((uint64_t *)(sp - 0));
    ret_sp = (sp + 8);
    log_before_taint_mem_list();
  }
}

static void trace_inspect(TRACE trace, VOID *v) {
  /* iterators */
  BBL bbl;
  INS ins;
  xed_iclass_enum_t ins_indx;

  /* traverse all the BBLs in the trace */
  for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {    
    uint64_t bbl_start = INS_Address(BBL_InsHead(bbl));
    uint64_t bbl_end = INS_Address(BBL_InsTail(bbl));
    bbl_list[bbl_start] = bbl_end;
    
    /* traverse all the instructions in the BBL */
    INS_InsertCall(BBL_InsHead(bbl), IPOINT_BEFORE, (AFUNPTR)hook_target_call, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_REG_VALUE, REG_RSP, IARG_END);
    INS_InsertCall(BBL_InsHead(bbl), IPOINT_BEFORE, (AFUNPTR)hook_main_call, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_REG_VALUE, REG_RSP, IARG_END);

    for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      if (INS_IsCall(ins) && !INS_IsDirectControlFlow(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(hook_call_ins), IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_REG_VALUE, REG_RSP, IARG_BRANCH_TARGET_ADDR, IARG_END);
      } else if (INS_IsDirectControlFlow(ins)) {
        RTN sourceRtn = TRACE_Rtn(trace);
        RTN destRtn   = RTN_FindByAddress(INS_DirectControlFlowTargetAddress(ins));
        if (INS_IsCall(ins) || sourceRtn != destRtn) {
          INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(hook_call_ins), IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_REG_VALUE, REG_RSP, IARG_BRANCH_TARGET_ADDR, IARG_END);
        }
      } else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(hook_ret_ins), IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_REG_VALUE, REG_RSP, IARG_BRANCH_TARGET_ADDR, IARG_END);
      }
      /*
       * use XED to decode the instruction and
       * extract its opcode
       */
      ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

      /*
       * invoke the pre-ins insrumentation callback;
       * optimized branch
       */
      if (unlikely(ins_desc[ins_indx].pre != NULL))
        ins_desc[ins_indx].pre(ins);

      /* analyze the instruction */
      /*
      if (is_tainted())
        LOGD("[ins] %s\n", INS_Disassemble(ins).c_str());
      */
      ins_inspect(ins);
      /*
       * invoke the post-ins insrumentation callback;
       * optimized branch
       */
      if (unlikely(ins_desc[ins_indx].post != NULL))
        ins_desc[ins_indx].post(ins);
    }
  }
}

/*
 * initialize thread contexts
 *
 * allocate space for the thread contexts and
 * register a thread start callback
 *
 * returns: 0 on success, 1 on error
 */
static inline int thread_ctx_init(void) {
  /* allocate space for the thread contexts; optimized branch
   *
   * NOTE: allocation is performed in blocks of THREAD_CTX_BLK
   */
  threads_ctx = new thread_ctx_t[THREAD_CTX_BLK]();

  if (unlikely(threads_ctx == NULL)) {
    fprintf(stderr, "%s:%u", __func__, __LINE__);
    /* failed */
    libdft_die();
    return 1;
  }

  /* initialize the context counter */
  tctx_ct = THREAD_CTX_BLK;

  /*
   * thread start hook;
   * keep track of the threads and allocate space for the per-thread
   * logistics (i.e., syscall context, VCPU, etc)
   */
  PIN_AddThreadStartFunction(thread_alloc, NULL);

  /* success */
  return 0;
}

/*
 * initialization of the core tagging engine;
 * it must be called before using everything else
 *
 * @argc:	argc passed in main
 * @argv:	argv passed in main
 *
 * returns: 0 on success, 1 on error
 */
int libdft_init() {

  // std::ios::sync_with_stdio(false);

  /* initialize symbol processing */
  PIN_InitSymbolsAlt(IFUNC_SYMBOLS);

  /* initialize thread contexts; optimized branch */
  if (unlikely(thread_ctx_init()))
    /* thread contexts failed */
    return 1;

  /*
   * syscall hooks; store the context of every syscall
   * and invoke registered callbacks (if any)
   */

  /* register sysenter_save() to be called before every syscall */
  PIN_AddSyscallEntryFunction(sysenter_save, NULL);

  /* register sysexit_save() to be called after every syscall */
  PIN_AddSyscallExitFunction(sysexit_save, NULL);

  /* initialize the ins descriptors */
  (void)memset(ins_desc, 0, sizeof(ins_desc));

  /* register trace_ins() to be called for every trace */
  TRACE_AddInstrumentFunction(trace_inspect, NULL);

  /* success */
  return 0;
}

/*
 * stop the execution of the application inside the
 * tag-aware VM; the execution of the application
 * is not interrupted
 *
 * NOTE: it also performs the appropriate cleanup
 */
void libdft_die(void) {
  /*
   * deallocate the resources needed for the tagmap
   * and threads context
   */
  //	delete[] threads_ctx;
  free(threads_ctx);
  /*
   * detach PIN from the application;
   * the application will continue to execute natively
   */
  PIN_Detach();
}

/*
 * add a new pre-ins callback into an instruction descriptor
 *
 * @desc:       the ins descriptor
 * @pre:        function pointer to the pre-ins handler
 *
 * returns:     0 on success, 1 on error
 */
int ins_set_pre(ins_desc_t *desc, void (*pre)(INS)) {
  /* sanity checks */
  if (unlikely((desc == NULL) | (pre == NULL)))
    /* return with failure */
    return 1;

  /* update the pre-ins callback */
  desc->pre = pre;

  /* success */
  return 0;
}

/*
 * add a new post-ins callback into an instruction descriptor
 *
 * @desc:       the ins descriptor
 * @pre:        function pointer to the post-ins handler
 *
 * returns:     0 on success, 1 on error
 */
int ins_set_post(ins_desc_t *desc, void (*post)(INS)) {
  /* sanity checks */
  if (unlikely((desc == NULL) | (post == NULL)))
    /* return with failure */
    return 1;

  /* update the post-ins callback */
  desc->post = post;

  /* success */
  return 0;
}

/*
 * remove the pre-ins callback from an instruction descriptor
 *
 * @desc:       the ins descriptor
 *
 * returns:     0 on success, 1 on error
 */
int ins_clr_pre(ins_desc_t *desc) {
  /* sanity check */
  if (unlikely(desc == NULL))
    /* return with failure */
    return 1;

  /* clear the pre-ins callback */
  desc->pre = NULL;

  /* return with success */
  return 0;
}

/*
 * remove the post-ins callback from an instruction descriptor
 *
 * @desc:       the ins descriptor
 *
 * returns:     0 on success, 1 on error
 */
int ins_clr_post(syscall_desc_t *desc) {
  /* sanity check */
  if (unlikely(desc == NULL))
    /* return with failure */
    return 1;

  /* clear the post-ins callback */
  desc->post = NULL;

  /* return with success */
  return 0;
}