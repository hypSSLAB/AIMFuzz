#include "ins_unitary_op.h"
#include "ins_helper.h"
#include "taint_info.h"

/* threads context */
extern thread_ctx_t *threads_ctx;
extern int pollution_mode;

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opb_u(THREADID tid,
                                                     uint32_t src, ADDRINT applicationIP) {
  tag_t src_tag = RTAG[src][1];
  if (src_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
  
  if (pollution_mode) {
    RTAG[DFT_REG_RAX][0] = -1 * src_tag;
    RTAG[DFT_REG_RAX][1] = -1 * src_tag;
  } else {
    RTAG[DFT_REG_RAX][0] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RAX][1] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opb_l(THREADID tid,
                                                     uint32_t src, ADDRINT applicationIP) {
  tag_t src_tag = RTAG[src][0];
  if (src_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
  
  if (pollution_mode) {
    RTAG[DFT_REG_RAX][0] = -1 * src_tag;
    RTAG[DFT_REG_RAX][1] = -1 * src_tag;
  } else {
    RTAG[DFT_REG_RAX][0] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RAX][1] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opw(THREADID tid, uint32_t src, ADDRINT applicationIP) {
  tag_t src_tag1 = RTAG[src][0];
  tag_t src_tag2 = RTAG[src][1];
  
  if (src_tag1 != 0 || src_tag2 != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
  
  if (pollution_mode) {
    RTAG[DFT_REG_RDX][0] = -1;
    RTAG[DFT_REG_RDX][1] = -1;

    RTAG[DFT_REG_RAX][0] = -1;
    RTAG[DFT_REG_RAX][1] = -1;
  } else {
    RTAG[DFT_REG_RDX][0] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RDX][1] = tag_traits<tag_t>::cleared_val;

    RTAG[DFT_REG_RAX][0] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RAX][1] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opq(THREADID tid, uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag[] = R64TAG(src);
  
  for (size_t i = 0; i < 8; i++) {
    if (src_tag[i] != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      RTAG[DFT_REG_RDX][i] = -1 * src_tag[i];
      RTAG[DFT_REG_RAX][i] = -1 * src_tag[i];
    } else {
      RTAG[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
      RTAG[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opl(THREADID tid, uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag[] = R32TAG(src);
  
  for (size_t i = 0; i < 4; i++) {
    if (src_tag[i] != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      RTAG[DFT_REG_RDX][i] = -1 * src_tag[i];
      RTAG[DFT_REG_RAX][i] = -1 * src_tag[i];
    } else {
      RTAG[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
      RTAG[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opb(THREADID tid, ADDRINT src, ADDRINT applicationIP) {
  tag_t src_tag = MTAG(src);
  if (src_tag != 0) {
    insert_taint_mem_info(ARITH_M2R, src, *((char *)src), src_tag, RTN_FindNameByAddress(applicationIP).c_str());
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  if (pollution_mode) {
    RTAG[DFT_REG_RAX][0] = -1 * src_tag;
    RTAG[DFT_REG_RAX][1] = -1 * src_tag;
  } else {
    RTAG[DFT_REG_RAX][0] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RAX][1] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opw(THREADID tid, ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag[] = M16TAG(src);
  
  for (size_t i = 0; i < 2; i++) {
    if (src_tag[i] != 0) {
      flag = 1;
      insert_taint_mem_info(ARITH_M2R, src+i, *((char *)src+i), src_tag[i], RTN_FindNameByAddress(applicationIP).c_str());
    }
    if (pollution_mode) {
      RTAG[DFT_REG_RDX][i] = -1 * src_tag[i];
      RTAG[DFT_REG_RAX][i] = -1 * src_tag[i];
    } else {
      RTAG[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
      RTAG[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opq(THREADID tid, ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag[] = M64TAG(src);
  
  for (size_t i = 0; i < 8; i++) {
    if (src_tag[i] != 0) {
      flag = 1;
      insert_taint_mem_info(ARITH_M2R, src+i, *((char *)src+i), src_tag[i], RTN_FindNameByAddress(applicationIP).c_str());
    }
    if (pollution_mode) {
      RTAG[DFT_REG_RDX][i] = -1 * src_tag[i];
      RTAG[DFT_REG_RAX][i] = -1 * src_tag[i];
    } else {
      RTAG[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
      RTAG[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opl(THREADID tid, ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag[] = M32TAG(src);
  
  for (size_t i = 0; i < 4; i++) {
    if (src_tag[i] != 0) {
      flag = 1;
      insert_taint_mem_info(ARITH_M2R, src+i, *((char *)src+i), src_tag[i], RTN_FindNameByAddress(applicationIP).c_str());
    }
    if (pollution_mode) {
      RTAG[DFT_REG_RDX][i] = -1 * src_tag[i];
      RTAG[DFT_REG_RAX][i] = -1 * src_tag[i];
    } else {
      RTAG[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
      RTAG[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void ins_unitary_op(INS ins) {
  //return;
  //printf("int unitary op\n");
  if (INS_OperandIsMemory(ins, OP_0))
    switch (INS_MemoryWriteSize(ins)) {
    case BIT2BYTE(MEM_64BIT_LEN):
      M_CALL_R(m2r_unitary_opq);
      break;
    case BIT2BYTE(MEM_LONG_LEN):
      M_CALL_R(m2r_unitary_opl);
      break;
    case BIT2BYTE(MEM_WORD_LEN):
      M_CALL_R(m2r_unitary_opw);
      break;
    case BIT2BYTE(MEM_BYTE_LEN):
    default:
      M_CALL_R(m2r_unitary_opb);
      break;
    }
  else {
    REG reg_src = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_src))
      R_CALL(r2r_unitary_opq, reg_src);
    else if (REG_is_gr32(reg_src))
      R_CALL(r2r_unitary_opl, reg_src);
    else if (REG_is_gr16(reg_src))
      R_CALL(r2r_unitary_opw, reg_src);
    else if (REG_is_Upper8(reg_src))
      R_CALL(r2r_unitary_opb_u, reg_src);
    else
      R_CALL(r2r_unitary_opb_l, reg_src);
  }
}