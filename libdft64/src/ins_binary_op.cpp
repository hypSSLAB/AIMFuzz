#include "ins_binary_op.h"
#include "ins_helper.h"
#include "taint_info.h"

/* threads context */

extern thread_ctx_t *threads_ctx;
extern std::map<ADDRINT, std::string> disassembleMap;
extern int pollution_mode;

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_ul(THREADID tid, uint32_t dst,
                                                     uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][1];

  if (src_tag != 0 || dst_tag != 0) {
    flag = 1;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  //RTAG[dst][1] = tag_combine(dst_tag, src_tag);
  if (pollution_mode) {
    RTAG[dst][1] = -1 * src_tag;
  } else {
    RTAG[dst][1] = 0;
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_lu(THREADID tid, uint32_t dst,
                                                     uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][0];

  if (src_tag != 0 || dst_tag != 0) {
    flag = 1;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  //RTAG[dst][0] = tag_combine(dst_tag, src_tag);
  if (pollution_mode) {
    RTAG[dst][0] = -1 * src_tag;
  } else {
    RTAG[dst][0] = 0;
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][1];

  if (src_tag != 0 || dst_tag != 0) {
    flag = 1;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  //RTAG[dst][1] = tag_combine(dst_tag, src_tag);
  if (pollution_mode) {
    RTAG[dst][1] = -1 * src_tag;
  } else {
    RTAG[dst][1] = 0;
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][0];

  if (src_tag != 0 || dst_tag != 0) {
    flag = 1;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  //RTAG[dst][0] = tag_combine(dst_tag, src_tag);
  if (pollution_mode) {
    RTAG[dst][0] = -1 & src_tag;
  } else {
    RTAG[dst][0] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opw(THREADID tid, uint32_t dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++) {
    if (src_tags[i] != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      dst_tags[i] = -1 * src_tags[i];
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opl(THREADID tid, uint32_t dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++) {
    if (src_tags[i] != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      dst_tags[i] = -1 * src_tags[i];
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }                                                
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opq(THREADID tid, uint32_t dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++) {
    if (src_tags[i] != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      dst_tags[i] = -1 * src_tags[i];
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opx(THREADID tid, uint32_t dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++) {
    if (src_tags[i] != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      dst_tags[i] = -1 * src_tags[i];
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opy(THREADID tid, uint32_t dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++) {
    if (src_tags[i] != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      dst_tags[i] = -1 * src_tags[i];
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][1];

  if (src_tag != 0 || dst_tag != 0) {
    flag = 1;
  }

  if (src_tag != 0) {
    insert_taint_mem_info(ARITH_M2R, src, *((char *)src), src_tag, RTN_FindNameByAddress(applicationIP).c_str());
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  //RTAG[dst][1] = tag_combine(src_tag, dst_tag);
  if (pollution_mode) {
    RTAG[dst][1] = -1 * src_tag;
  } else {
    RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][0];

  if (src_tag != 0 || dst_tag != 0) {
    flag = 1;
  }

  if (src_tag != 0) {
    insert_taint_mem_info(ARITH_M2R, src, *((char *)src), src_tag, RTN_FindNameByAddress(applicationIP).c_str());
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  //RTAG[dst][0] = tag_combine(src_tag, dst_tag);
  if (pollution_mode) {
    RTAG[dst][0] = -1 * src_tag;
  } else {
    RTAG[dst][0] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opw(THREADID tid, uint32_t dst,
                                                  ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++) {
    if (MTAG(src+i) != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (MTAG(src+i) != 0) {
      insert_taint_mem_info(ARITH_M2R, src+i, *((char *)src+i), MTAG(src+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
    if (pollution_mode) {
      dst_tags[i] = -1 * MTAG(src+i);
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }                                         

}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opl(THREADID tid, uint32_t dst,
                                                  ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++) {
    if (MTAG(src+i) != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (MTAG(src+i) != 0) {
      insert_taint_mem_info(ARITH_M2R, src+i, *((char *)src+i), MTAG(src+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
    if (pollution_mode) {
      dst_tags[i] = -1 * MTAG(src+i);
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }  
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opq(THREADID tid, uint32_t dst,
                                                  ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++) {
    if (MTAG(src+i) != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (MTAG(src+i) != 0) {
      insert_taint_mem_info(ARITH_M2R, src+i, *((char *)src+i), MTAG(src+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
    if (pollution_mode) {
       dst_tags[i] = -1 * MTAG(src+i);
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  } 
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opx(THREADID tid, uint32_t dst,
                                                  ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++) {
    if (MTAG(src+i) != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (MTAG(src+i) != 0) {
      insert_taint_mem_info(ARITH_M2R, src+i, *((char *)src+i), MTAG(src+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
    if (pollution_mode) {
      dst_tags[i] = -1 * MTAG(src+i);
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  } 
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opy(THREADID tid, uint32_t dst,
                                                  ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++) {
    if (MTAG(src+i) != 0 || dst_tags[i] != 0) {
      flag = 1;
    }
    if (MTAG(src+i) != 0) {
      insert_taint_mem_info(ARITH_M2R, src+i, *((char *)src+i), MTAG(src+i), RTN_FindNameByAddress(applicationIP).c_str());
    }
    if (pollution_mode) {
      dst_tags[i] = -1 * MTAG(src+i);
    } else {
      dst_tags[i] = tag_traits<tag_t>::cleared_val;
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  } 
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_u(THREADID tid, ADDRINT dst,
                                                    uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = MTAG(dst);

  if (src_tag != 0 || dst_tag != 0) {
    flag = 1;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  if (pollution_mode) {
    tagmap_setb(dst, -1 * src_tag);
  } else {
    tagmap_setb(dst, 0);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_l(THREADID tid, ADDRINT dst,
                                                    uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = MTAG(dst);

  if (src_tag != 0 || dst_tag != 0) {
    flag = 1;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  if (pollution_mode) {
    tagmap_setb(dst, -1 * src_tag);
  } else {
    tagmap_setb(dst, 0);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opw(THREADID tid, ADDRINT dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 2; i++) {
    if (src_tags[i] != 0 || MTAG(dst+i) != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      tagmap_setb(dst + i, -1 * src_tags[i]);
    } else {
      tagmap_setb(dst + i, tag_traits<tag_t>::cleared_val);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opl(THREADID tid, ADDRINT dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++) {
    if (src_tags[i] != 0 || MTAG(dst+i) != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      tagmap_setb(dst + i, -1 * src_tags[i]);
    } else {
      tagmap_setb(dst + i, tag_traits<tag_t>::cleared_val);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opq(THREADID tid, ADDRINT dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++) {
    if (src_tags[i] != 0 || MTAG(dst+i) != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      tagmap_setb(dst + i, -1 * src_tags[i]);
    } else {
      tagmap_setb(dst + i, tag_traits<tag_t>::cleared_val);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opx(THREADID tid, ADDRINT dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 16; i++) {
    if (src_tags[i] != 0 || MTAG(dst+i) != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      tagmap_setb(dst + i, -1 * src_tags[i]);
    } else {
      tagmap_setb(dst + i, tag_traits<tag_t>::cleared_val);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opy(THREADID tid, ADDRINT dst,
                                                  uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 32; i++) {
    if (src_tags[i] != 0 || MTAG(dst+i) != 0) {
      flag = 1;
    }
    if (pollution_mode) {
      tagmap_setb(dst + i, -1 * src_tags[i]);

    } else {
     tagmap_setb(dst + i, tag_traits<tag_t>::cleared_val);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}


// Check tainted
void ins_binary_op(INS ins) {
  //return;
  //printf("ins binary op\n");
  if (INS_OperandIsImmediate(ins, OP_1))
    return;
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_binary_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_binary_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL(r2r_binary_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL(r2r_binary_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))
        R2R_CALL(r2r_binary_opb_l, reg_dst, reg_src);
      else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
        R2R_CALL(r2r_binary_opb_u, reg_dst, reg_src);
      else if (REG_is_Lower8(reg_dst))
        R2R_CALL(r2r_binary_opb_lu, reg_dst, reg_src);
      else
        R2R_CALL(r2r_binary_opb_ul, reg_dst, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_binary_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_binary_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL(m2r_binary_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_binary_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_binary_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_binary_opb_l, reg_dst);
    }
  } else {
    //printf("r2m instruction\n");
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_binary_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_binary_opw, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL(r2m_binary_opx, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL(r2m_binary_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(r2m_binary_opb_u, reg_src);
    } else {
      R2M_CALL(r2m_binary_opb_l, reg_src);
    }
  }
}