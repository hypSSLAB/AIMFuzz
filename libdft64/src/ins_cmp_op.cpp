#include "ins_xfer_op.h"
#include "ins_clear_op.h"
#include "ins_helper.h"
#include "taint_info.h"
#include "ins_cmp_op.h"

extern std::map<ADDRINT, std::string> disassembleMap;
extern thread_ctx_t *threads_ctx;

#define MNI_CALL(fn)                                                                  \
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fn,                                     \
                  IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,                            \
                  IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_END);

#define RNI_CALL(fn, dst)                                                             \
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fn,                                     \
                  IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,                            \
                  IARG_UINT32, REG_INDX(dst), IARG_INST_PTR,                          \
                  IARG_CONST_CONTEXT, IARG_END);

#define MNR_CALL(fn, src)                                                             \
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fn,                                     \
                  IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,                            \
                  IARG_MEMORYREAD_EA,IARG_UINT32, REG_INDX(src),                      \
                  IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END);

#define RNM_CALL(fn, dst)                                                             \
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fn,                                     \
                  IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,                            \
                  IARG_UINT32, REG_INDX(dst), IARG_MEMORYREAD_EA,                    \
                  IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END);

#define RNR_CALL(fn, dst, src)                                                        \
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fn,                                     \
                  IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,                            \
                  IARG_UINT32, REG_INDX(dst), IARG_UINT32, REG_INDX(src),             \
                  IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END);



/*
 *  CMP mem imm
 */
void PIN_FAST_ANALYSIS_CALL mni_cmp_op8(THREADID tid, ADDRINT dst, ADDRINT applicationIP) {
  int flag = 0;
  if (!tag_is_empty(MTAG(dst))) {
    flag = 1;
    insert_taint_mem_info(COMP_M, dst, *((char *)dst), MTAG(dst), RTN_FindNameByAddress(applicationIP).c_str());
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL mni_cmp_op16(THREADID tid, ADDRINT dst, ADDRINT applicationIP) {
  int i;
  int flag = 0;

  for (i = 0; i < 2; i++) {
    if (!tag_is_empty(MTAG(dst+i))) {
      flag = 1;
      insert_taint_mem_info(COMP_M, dst+i, *((char *)dst+i), MTAG(dst+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL mni_cmp_op32(THREADID tid, ADDRINT dst, ADDRINT applicationIP) {
  int i;
  int flag = 0;

  for (i = 0; i < 4; i++) {
    if (!tag_is_empty(MTAG(dst+i))) {
      flag = 1;
      insert_taint_mem_info(COMP_M, dst+i, *((char *)dst+i), MTAG(dst+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL mni_cmp_op64(THREADID tid, ADDRINT dst, ADDRINT applicationIP) {
  int i;
  int flag = 0;

  for (i = 0; i < 8; i++) {
    if (!tag_is_empty(MTAG(dst+i))) {
      flag = 1;
      insert_taint_mem_info(COMP_M, dst+i, *((char *)dst+i), MTAG(dst+i), RTN_FindNameByAddress(applicationIP).c_str()); 
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

/*
 *  CMP reg imm
 */
void PIN_FAST_ANALYSIS_CALL rni_cmp_op8(THREADID tid, uint32_t dst, ADDRINT applicationIP, CONTEXT *ctxt) {
  int flag = 0;
  ADDRINT reg_val;
  tag_t src_tag = RTAG[dst][0];

  PIN_GetContextRegval(ctxt, REG(dst), reinterpret_cast<UINT8 *>(&reg_val));

  if (!tag_is_empty(src_tag)) {
    flag = 1;
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL rni_cmp_op16(THREADID tid, uint32_t dst, ADDRINT applicationIP, CONTEXT *ctxt) {
  int i;
  int flag = 0;
  tag_t *src_tags = RTAG[dst];

  for (i = 0; i < 2; i++) {
    if (!tag_is_empty(src_tags[i])) {
      flag = 1;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL rni_cmp_op32(THREADID tid, uint32_t dst, ADDRINT applicationIP, CONTEXT *ctxt) {
  int i;
  int flag = 0;
  tag_t *src_tags = RTAG[dst];

  for (i = 0; i < 4; i++) {
    if (!tag_is_empty(src_tags[i])) {
      flag = 1;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL rni_cmp_op64(THREADID tid, uint32_t dst, ADDRINT applicationIP, CONTEXT *ctxt) {
  int i;
  int flag = 0;
  tag_t *src_tags = RTAG[dst];

  for (i = 0; i < 8; i++) {
    if (!tag_is_empty(src_tags[i])) {
      flag = 1;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

/*
 *  CMP mem reg
 */
void PIN_FAST_ANALYSIS_CALL mnr_cmp_op8(THREADID tid, ADDRINT dst, uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag = RTAG[src][0];

  if (!tag_is_empty(src_tag)) {
    flag = 1;
  }

  if (!tag_is_empty(MTAG(dst))) {
    flag = 1;
    insert_taint_mem_info(COMP_M, dst, *((char *)dst), MTAG(dst), RTN_FindNameByAddress(applicationIP).c_str());
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL mnr_cmp_op16(THREADID tid, ADDRINT dst, uint32_t src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  tag_t *src_tags = RTAG[src];

  for (i = 0; i < 2; i++) {
    if (!tag_is_empty(src_tags[i])) {
      flag = 1;
    }
  }

  for (i = 0; i < 2; i++) {
    if (!tag_is_empty(MTAG(dst+i))) {
      flag = 1;
      insert_taint_mem_info(COMP_M, dst+i, *((char *)dst+i), MTAG(dst+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL mnr_cmp_op32(THREADID tid, ADDRINT dst, uint32_t src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  tag_t *src_tags = RTAG[src];

  for (i = 0; i < 4; i++) {
    if (!tag_is_empty(src_tags[i])) {
      flag = 1;
    }
  }

  for (i = 0; i < 4; i++) {
    if (!tag_is_empty(MTAG(dst+i))) {
      flag = 1;
      insert_taint_mem_info(COMP_M, dst+i, *((char *)dst+i), MTAG(dst+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL mnr_cmp_op64(THREADID tid, ADDRINT dst, uint32_t src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  tag_t *src_tags = RTAG[src];

  for (i = 0; i < 8; i++) {
    if (!tag_is_empty(src_tags[i])) {
      flag = 1;
    }
  }

  for (i = 0; i < 8; i++) {
    if (!tag_is_empty(MTAG(dst+i))) {
      flag = 1;
      insert_taint_mem_info(COMP_M, dst+i, *((char *)dst+i), MTAG(dst+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}


/*
 *  CMP reg mem
 */
void PIN_FAST_ANALYSIS_CALL rnm_cmp_op8(THREADID tid, uint32_t dst, ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t dst_tag = RTAG[dst][0];

  if (!tag_is_empty(dst_tag)) {
    flag = 1;
  }

  if (!tag_is_empty(MTAG(src))) {
    flag = 1;
    insert_taint_mem_info(COMP_M, src, *((char *)src), MTAG(src), RTN_FindNameByAddress(applicationIP).c_str());
  }
  
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL rnm_cmp_op16(THREADID tid, uint32_t dst, ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];

  for (i = 0; i < 2; i++) {
    if (!tag_is_empty(dst_tags[i])) {
      flag = 1;
    }
  }

  for (i = 0; i < 2; i++) {
    if (!tag_is_empty(MTAG(src+i))) {
      flag = 1;
      insert_taint_mem_info(COMP_M, src+i, *((char *)(src+i)), MTAG(src+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL rnm_cmp_op32(THREADID tid, uint32_t dst, ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];

  for (i = 0; i < 4; i++) {
    if (!tag_is_empty(dst_tags[i])) {
      flag = 1;
    }
  }

  for (i = 0; i < 4; i++) {
    if (!tag_is_empty(MTAG(src+i))) {
      flag = 1;
      insert_taint_mem_info(COMP_M, src+i, *((char *)(src+i)), MTAG(src+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL rnm_cmp_op64(THREADID tid, uint32_t dst, ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];

  for (i = 0; i < 8; i++) {
    if (!tag_is_empty(dst_tags[i])) {
      flag = 1;
    }
  }

  for (i = 0; i < 8; i++) {
    if (!tag_is_empty(MTAG(src+i))) {
      flag = 1;
      insert_taint_mem_info(COMP_M, src+i, *((char *)(src+i)), MTAG(src+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

/*
 *  CMP reg reg
 */
void PIN_FAST_ANALYSIS_CALL rnr_cmp_op8(THREADID tid, uint32_t dst, uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t dst_tag = RTAG[dst][0];
  tag_t src_tag = RTAG[src][0];

  if (!tag_is_empty(dst_tag)) {
    flag = 1;
  }

  if (!tag_is_empty(src_tag)) {
    flag = 1;
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL rnr_cmp_op16(THREADID tid, uint32_t dst, uint32_t src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];
  tag_t *src_tags = RTAG[src];

  for (i = 0; i < 2; i++) {
    if (!tag_is_empty(dst_tags[i])) {
      flag = 1;
    }
  }

  for (i = 0; i < 2; i++) {
    if (!tag_is_empty(src_tags[i])) {
      flag = 1;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL rnr_cmp_op32(THREADID tid, uint32_t dst, uint32_t src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];
  tag_t *src_tags = RTAG[src];

  for (i = 0; i < 4; i++) {
    if (!tag_is_empty(dst_tags[i])) {
      flag = 1;
    }
  }

  for (i = 0; i < 4; i++) {
    if (!tag_is_empty(src_tags[i])) {
      flag = 1;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL rnr_cmp_op64(THREADID tid, uint32_t dst, uint32_t src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];
  tag_t *src_tags = RTAG[src];

  for (i = 0; i < 8; i++) {
    if (!tag_is_empty(dst_tags[i])) {
      flag = 1;
    }
  }

  for (i = 0; i < 8; i++) {
    if (!tag_is_empty(src_tags[i])) {
      flag = 1;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

VOID cmp_dasm(char *s) { 
  //LOGD("================================================\n");
  //LOGD("[ins] %s\n", s);  
}

void ins_cmp_op(INS ins) {
  /*
    CMP   AL      imm8
    CMP   AX      imm16
    CMP   EAX     imm32
    CMP   RAX     imm32

    CMP   r/m8    imm8
    CMP   r/m16   imm16
    CMP   r/m32   imm32
    CMP   r/m64   imm32

    CMP   r/m16   imm8
    CMP   r/m32   imm8
    CMP   r/m64   imm8
    
    CMP   r/m8    r8
    CMP   r/m16   r16
    CMP   r/m32   r32
    CMP   r/m64    r64
    CMP   r8      r/m8
    CMP   r16     r/m16
    CMP   r/32    r/m32
    CMP   r/64    r/m64
  */

  char *cstr;
  cstr = new char[INS_Disassemble(ins).size() + 1];
  strcpy(cstr, INS_Disassemble(ins).c_str());
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)cmp_dasm, IARG_PTR, cstr, IARG_END);  

  if (INS_OperandIsImmediate(ins, OP_1)) {
    if (INS_OperandIsMemory(ins, OP_0) && INS_IsMemoryRead(ins)) {
      // CMP mem imm    
      if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_BYTE_LEN)) {
        MNI_CALL(mni_cmp_op8);
      } else if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_WORD_LEN)) {
        MNI_CALL(mni_cmp_op16);
      } else if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_LONG_LEN)) {
        MNI_CALL(mni_cmp_op32);
      } else if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_64BIT_LEN)) {
        MNI_CALL(mni_cmp_op64);
      } else {
        LOGD("CMP mem imm : error in mem size");
      }
    } else {
      // CMP reg imm
      REG reg_dst = INS_OperandReg(ins, OP_0);
      
      if (REG_is_gr64(reg_dst)) {
        RNI_CALL(rni_cmp_op64, reg_dst);
      } else if (REG_is_gr32(reg_dst)) {
        RNI_CALL(rni_cmp_op32, reg_dst);
      } else if (REG_is_gr16(reg_dst)) {
        RNI_CALL(rni_cmp_op16, reg_dst);
      } else if (REG_is_gr8(reg_dst)) {
        RNI_CALL(rni_cmp_op8, reg_dst);
      } else {
        LOGD("CMP reg imm : error in reg size");
      }
    }
  } else {
    if (INS_OperandIsMemory(ins, OP_0)) {
      // CMP mem reg
      REG reg_src = INS_OperandReg(ins, OP_1);
      
      if (REG_is_gr64(reg_src)) {
        MNR_CALL(mnr_cmp_op64, reg_src);
      } else if (REG_is_gr32(reg_src)) {
        MNR_CALL(mnr_cmp_op32, reg_src);
      } else if (REG_is_gr16(reg_src)) {
        MNR_CALL(mnr_cmp_op16, reg_src);
      } else if (REG_is_gr8(reg_src)) {
        MNR_CALL(mnr_cmp_op8, reg_src);
      } else {
        LOGD("CMP mem reg : error in reg size");
      }
    } else if (INS_OperandIsMemory(ins, OP_1)) {
      // CMP reg mem
      REG reg_dst = INS_OperandReg(ins, OP_0);

      if (REG_is_gr64(reg_dst)) {
        RNM_CALL(rnm_cmp_op64, reg_dst);
      } else if (REG_is_gr32(reg_dst)) {
        RNM_CALL(rnm_cmp_op32, reg_dst);
      } else if (REG_is_gr16(reg_dst)) {
        RNM_CALL(rnm_cmp_op16, reg_dst);
      } else if (REG_is_gr8(reg_dst)) {
        RNM_CALL(rnm_cmp_op8, reg_dst);
      } else {
        LOGD("CMP reg mem : error in reg size");
      }
    } else {
      // CMP reg reg
      REG reg_dst = INS_OperandReg(ins, OP_0);
      REG reg_src = INS_OperandReg(ins, OP_1);

      if (REG_is_gr64(reg_dst)) {
        RNR_CALL(rnr_cmp_op64, reg_dst, reg_src);
      } else if (REG_is_gr32(reg_dst)) {
        RNR_CALL(rnr_cmp_op32, reg_dst, reg_src);
      } else if (REG_is_gr16(reg_dst)) {
        RNR_CALL(rnr_cmp_op16, reg_dst, reg_src);
      } else if (REG_is_gr8(reg_dst)) {
        RNR_CALL(rnr_cmp_op8, reg_dst, reg_src);
      } else {
        LOGD("CMP reg reg : error in reg size");
      }
    }
  }
}