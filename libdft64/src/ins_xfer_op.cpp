#include "ins_xfer_op.h"
#include "ins_clear_op.h"
#include "ins_helper.h"
#include "taint_info.h"

/* threads context */
extern thread_ctx_t *threads_ctx;
extern std::map<int, char> tagVal;
extern std::map<ADDRINT, std::string> disassembleMap;

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_ul(THREADID tid, uint32_t dst,
                                            uint32_t src, ADDRINT applicationIP, 
                                            CONTEXT *ctxt, REG src_reg) {                                            
  int flag = 0;
  char src_val;

  tag_t src_tag = RTAG[src][0];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);  

  if (src_tag == 0) {
    RTAG[dst][1] = 0;
  } else if (src_val == tagVal[int(src_tag)]) {
    flag = 1;
    RTAG[dst][1] = src_tag;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_lu(THREADID tid, uint32_t dst,
                                            uint32_t src, ADDRINT applicationIP,
                                            CONTEXT *ctxt, REG src_reg) {
  int flag = 0;
  char src_val;
  
  tag_t src_tag = RTAG[src][1];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);  

  if (src_tag == 0) {
    RTAG[dst][0] = 0;
  } else if (src_val == tagVal[int(src_tag)]) {
    flag = 1;
    RTAG[dst][0] = src_tag;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           uint32_t src, ADDRINT applicationIP,
                                           CONTEXT *ctxt, REG src_reg) {
  int flag = 0;
  char src_val;
  
  tag_t src_tag = RTAG[src][1];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);  

  if (src_tag == 0) {
    RTAG[dst][1] = 0;
  } else if (src_val == tagVal[int(src_tag)]) {
    flag = 1;
    RTAG[dst][1] = src_tag;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           uint32_t src, ADDRINT applicationIP,
                                           CONTEXT *ctxt, REG src_reg) {
  int flag = 0;
  char src_val;
  
  tag_t src_tag = RTAG[src][0];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);  

  if (src_tag == 0) {
    RTAG[dst][0] = 0;
  } else if (src_val == tagVal[int(src_tag)]) {
    flag = 1;
    RTAG[dst][0] = src_tag;
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opw(THREADID tid, uint32_t dst,
                                         uint32_t src, ADDRINT applicationIP,
                                         CONTEXT *ctxt, REG src_reg) {
  ////LOGD("================r2r_xfer_opw================\n");
  int flag = 0;
  char src_val[2];

  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);  

  for (size_t i = 0; i < 2; i++) {
    if (RTAG[src][i] == 0) {
      RTAG[dst][i] = 0;
    } else if (src_val[i] == tagVal[int(RTAG[src][i])]) {
      flag = 1;
      RTAG[dst][i] = RTAG[src][i];
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opl(THREADID tid, uint32_t dst,
                                         uint32_t src, ADDRINT applicationIP,
                                         CONTEXT *ctxt, REG src_reg) {
  ////LOGD("================r2r_xfer_opl================\n");
  int flag = 0;
  char src_val[4];

  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);  

  for (size_t i = 0; i < 4; i++) {
    if (RTAG[src][i] == 0) {
      RTAG[dst][i] = 0;
    } else if (src_val[i] == tagVal[int(RTAG[src][i])]) {
      flag = 1;
      RTAG[dst][i] = RTAG[src][i];
    }
  }
  
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opq(THREADID tid, uint32_t dst,
                                         uint32_t src, ADDRINT applicationIP, 
                                         CONTEXT *ctxt, REG src_reg) {
  int flag = 0;
  char src_val[8];

  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);  

  for (size_t i = 0; i < 8; i++) {
    if (RTAG[src][i] == 0) {
      RTAG[dst][i] = 0;
    } else if (src_val[i] == tagVal[int(RTAG[src][i])]) {
      flag = 1;
      RTAG[dst][i] = RTAG[src][i];
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx(THREADID tid, uint32_t dst,
                                         uint32_t src, ADDRINT applicationIP,
                                         CONTEXT *ctxt, REG src_reg) {
  int flag = 0;
  char src_val[16];

  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);  

  for (size_t i = 0; i < 16; i++) {
    if (RTAG[src][i] == 0) {
      RTAG[dst][i] = 0;
    } else if (src_val[i] == tagVal[int(RTAG[src][i])]) {
      flag = 1;
      RTAG[dst][i] = RTAG[src][i];
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opy(THREADID tid, uint32_t dst,
                                         uint32_t src, ADDRINT applicationIP,
                                         CONTEXT *ctxt, REG src_reg) {
  int flag = 0;
  char src_val[32];

  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);  

  for (size_t i = 0; i < 32; i++) {
    if (RTAG[src][i] == 0) {
      RTAG[dst][i] = 0;
    } else if (src_val[i] == tagVal[int(RTAG[src][i])]) {
      flag = 1;
      RTAG[dst][i] = RTAG[src][i];
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           ADDRINT src, ADDRINT applicationIP, CONTEXT *ctxt) {
  int flag = 0;
  tag_t src_tag = MTAG(src);

  if (src_tag == 0) {
    RTAG[dst][1] = 0;
  } else if ((*((char *)src)) == tagVal[int(src_tag)]) {
    flag = 1;
    RTAG[dst][1] = src_tag;
  }

  if (flag) {
    const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();
    insert_taint_mem_info(XFER_M2R, src, *((char *)src), src_tag, name_tmp);
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           ADDRINT src, ADDRINT applicationIP, CONTEXT *ctxt) {
  int flag = 0;
  tag_t src_tag = MTAG(src);

  if (src_tag == 0) {
    RTAG[dst][0] = 0;
  } else if ((*((char *)src)) == tagVal[int(src_tag)]) {
    flag = 1;
    RTAG[dst][0] = src_tag;
  }

  if (flag) {
    const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();
    insert_taint_mem_info(XFER_M2R, src, *((char *)src), src_tag, name_tmp);
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw(THREADID tid, uint32_t dst,
                                         ADDRINT src, ADDRINT applicationIP, CONTEXT *ctxt) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for (i = 0; i < 2; i++) {
    if (MTAG(src+i) == 0) {
      RTAG[dst][i] = 0;
    } else if ((*((char *)(src+i))) == tagVal[int(MTAG(src+i))]) {
      flag = 1;
      RTAG[dst][i] = MTAG(src + i);
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
    }
  }
  if (flag) { 
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);  
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl(THREADID tid, uint32_t dst,
                                         ADDRINT src, ADDRINT applicationIP, CONTEXT *ctxt) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for (i = 0; i < 4; i++) {
    if (MTAG(src+i) == 0) {
      RTAG[dst][i] = 0;
    } else if ((*((char *)(src+i))) == tagVal[int(MTAG(src+i))]) {
      flag = 1;
      RTAG[dst][i] = MTAG(src + i);
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq(THREADID tid, uint32_t dst,
                                         ADDRINT src, ADDRINT applicationIP, CONTEXT *ctxt) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for (i = 0; i < 8; i++) {
    if (MTAG(src+i) == 0) {
      RTAG[dst][i] = 0;
    } else if ((*((char *)(src+i))) == tagVal[int(MTAG(src+i))]) {
      flag = 1;
      RTAG[dst][i] = MTAG(src + i);
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opx(THREADID tid, uint32_t dst,
                                         ADDRINT src, ADDRINT applicationIP, CONTEXT *ctxt) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for (i = 0; i < 16; i++) {
    if (MTAG(src+i) == 0) {
      RTAG[dst][i] = 0;
    } else if ((*((char *)(src+i))) == tagVal[int(MTAG(src+i))]) {
      flag = 1;
      RTAG[dst][i] = MTAG(src + i);
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opy(THREADID tid, uint32_t dst,
                                         ADDRINT src, ADDRINT applicationIP, CONTEXT *ctxt) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for (i = 0; i < 32; i++) {
    if (MTAG(src+i) == 0) {
      RTAG[dst][i] = 0;
    } else if ((*((char *)(src+i))) == tagVal[int(MTAG(src+i))]) {
      flag = 1;
      RTAG[dst][i] = MTAG(src + i);
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_u(THREADID tid, ADDRINT dst,
                                           uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int flag = 0;
  char src_val;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();
  
  tag_t src_tag = RTAG[src][1];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  if (src_tag != 0) {
    tagmap_setb(dst, 0);
  } else if (src_val == tagVal[int(src_tag)]) {
    flag = 1;
    tagmap_setb(dst, src_tag);
    insert_taint_mem_info(XFER_R2M, dst, src_val, src_tag, name_tmp);
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_l(THREADID tid, ADDRINT dst,
                                           uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int flag = 0;
  char src_val;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();
  
  tag_t src_tag = RTAG[src][0];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  if (src_tag != 0) {
    tagmap_setb(dst, 0);
  } else if (src_val == tagVal[int(src_tag)]) {
    flag = 1;
    tagmap_setb(dst, src_tag);
    insert_taint_mem_info(XFER_R2M, dst, src_val, src_tag, name_tmp);
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw(THREADID tid, ADDRINT dst,
                                         uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int i;
  int flag = 0;
  char src_val[2];
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t *src_tags = RTAG[src];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  for(i = 0; i < 2; i++) {
    if (src_tags[i] == 0) {
      tagmap_setb(dst+i, 0);
    } else if (src_val[i] == tagVal[int(src_tags[i])]) {
      flag = 1;
      tagmap_setb(dst+i, src_tags[i]);
      insert_taint_mem_info(XFER_R2M, dst+i, src_val[i], src_tags[i], name_tmp);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl(THREADID tid, ADDRINT dst,
                                         uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int i;
  int flag = 0;
  char src_val[4];
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t *src_tags = RTAG[src];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  for(i = 0; i < 4; i++) {
    if (src_tags[i] == 0) {
      tagmap_setb(dst+i, 0);
    } else if (src_val[i] == tagVal[int(src_tags[i])]) {
      flag = 1;
      tagmap_setb(dst+i, src_tags[i]);
      insert_taint_mem_info(XFER_R2M, dst+i, src_val[i], src_tags[i], name_tmp);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq(THREADID tid, ADDRINT dst,
                                         uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int i;
  int flag = 0;
  char src_val[8];
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t *src_tags = RTAG[src];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  for(i = 0; i < 8; i++) {
    if (src_tags[i] == 0) {
      tagmap_setb(dst+i, 0);
    } else if (src_val[i] == tagVal[int(src_tags[i])]) {
      flag = 1;
      tagmap_setb(dst+i, src_tags[i]);
      insert_taint_mem_info(XFER_R2M, dst+i, src_val[i], src_tags[i], name_tmp);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opx(THREADID tid, ADDRINT dst,
                                         uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int i;
  int flag = 0;
  char src_val[16];
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t *src_tags = RTAG[src];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  for(i = 0; i < 16; i++) {
    if (src_tags[i] == 0) {
      tagmap_setb(dst+i, 0);
    } else if (src_val[i] == tagVal[int(src_tags[i])]) {
      flag = 1;
      tagmap_setb(dst+i, src_tags[i]);
      insert_taint_mem_info(XFER_R2M, dst+i, src_val[i], src_tags[i], name_tmp);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opy(THREADID tid, ADDRINT dst,
                                         uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int i;
  int flag = 0;
  char src_val[32];
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t *src_tags = RTAG[src];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  for(i = 0; i < 32; i++) {
    if (src_tags[i] == 0) {
      tagmap_setb(dst+i, 0);
    } else if (src_val[i] == tagVal[int(src_tags[i])]) {
      flag = 1;
      tagmap_setb(dst+i, src_tags[i]);
      insert_taint_mem_info(XFER_R2M, dst+i, src_val[i], src_tags[i], name_tmp);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opb(ADDRINT dst, ADDRINT src, ADDRINT applicationIP) {
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t src_tag = MTAG(src);

  if (src_tag == 0) {
    tagmap_setb(dst, 0);
  } else if ((*(char *)src) == tagVal[int(src_tag)]) {
    flag = 1;
    tagmap_setb(dst, src_tag);
    insert_taint_mem_info(XFER_M2R, src, *((char *)src), MTAG(src), name_tmp);
    insert_taint_mem_info(XFER_R2M, dst, *((char *)src), MTAG(src), name_tmp);
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opw(ADDRINT dst, ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for(i = 0; i < 2; i++) {
    if (MTAG(src+i) == 0) {
      tagmap_setb(dst + i, 0);
    } else if ((*(char *)(src+i)) == tagVal[int(MTAG(src+i))]) {
      flag = 1;
      tagmap_setb(dst+i, MTAG(src+i));
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
      insert_taint_mem_info(XFER_R2M, dst+i, *((char *)src+i), MTAG(src+i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opl(ADDRINT dst, ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for(i = 0; i < 4; i++) {
    if (MTAG(src+i) == 0) {
      tagmap_setb(dst + i, 0);
    } else if ((*(char *)(src+i)) == tagVal[int(MTAG(src+i))]) {
      flag = 1;
      tagmap_setb(dst+i, MTAG(src+i));
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
      insert_taint_mem_info(XFER_R2M, dst+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opq(ADDRINT dst, ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for(i = 0; i < 8; i++) {
    if (MTAG(src+i) == 0) {
      tagmap_setb(dst + i, 0);
    } else if ((*(char *)(src+i)) == tagVal[int(MTAG(src+i))]) {
      flag = 1;
      tagmap_setb(dst+i, MTAG(src+i));
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
      insert_taint_mem_info(XFER_R2M, dst+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_h(THREADID tid, uint32_t dst,
                                           ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for(i = 0; i < 8; i++) {
    if (MTAG(src+i) == 0) {
      RTAG[dst][i + 8] = 0;
    } else if ((*(char *)(src+i)) == tagVal[int(MTAG(src+i))]) {
      flag = 1;
      RTAG[dst][i + 8] = MTAG(src + i);
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), MTAG(src+i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_h(THREADID tid, ADDRINT dst,
                                           uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int i;
  int flag = 0;
  char src_val[16];
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t *src_tags = RTAG[src];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  for(i = 0; i < 8; i++) {
    if (src_tags[i+8] == 0) {
      tagmap_setb(dst + i, 0);
    } else if (src_val[i+8] == tagVal[int(src_tags[i+8])]) {
      flag = 1;
      tagmap_setb(dst + i, src_tags[i + 8]);
      insert_taint_mem_info(XFER_R2M, dst+i, src_val[i+8], src_tags[i+8], name_tmp);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opbn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags, ADDRINT applicationIP) {
  tag_t src_tag = RTAG[DFT_REG_RAX][0];
  int flag = 0;

  if(src_tag != 0) {
    flag = 1;
  }
  
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < count; i++) {
      tagmap_setb(dst + i, src_tag);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < count; i++) {
      size_t dst_addr = dst - count + 1 + i;
      tagmap_setb(dst_addr, src_tag);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opwn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags, ADDRINT applicationIP) {
  //printf("r2m_xfer_opwn\n");
  tag_t src_tag[] = R16TAG(DFT_REG_RAX);
  int flag = 0;

  for (size_t i = 0; i < (count << 1); i++) {
    if (src_tag[i % 2] != 0) {
      flag = 1;
    }  
  }

  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 1); i++) {
      tagmap_setb(dst + i, src_tag[i % 2]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 1); i++) {
      size_t dst_addr = dst - (count << 1) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 2]);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opln(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags, ADDRINT applicationIP) {
  //printf("r2m_xfer_opln\n");
  tag_t src_tag[] = R32TAG(DFT_REG_RAX);
  int flag = 0;
  
  for (size_t i = 0; i < (count << 2); i++) {
    if (src_tag[i % 4] != 0) {
      flag = 1;
    }
  }

  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 2); i++) {
      tagmap_setb(dst + i, src_tag[i % 4]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 2); i++) {
      size_t dst_addr = dst - (count << 2) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 4]);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opqn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags, ADDRINT applicationIP) {
  //printf("r2m_xfer_opqn\n");
  tag_t src_tag[] = R64TAG(DFT_REG_RAX);
  int flag = 0;

  for (size_t i = 0; i < (count << 3); i++) {
    if (src_tag[i % 8] != 0) {
      flag = 1;
    }
  }
  
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 3); i++) {
      tagmap_setb(dst + i, src_tag[i % 8]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 3); i++) {
      size_t dst_addr = dst - (count << 3) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 8]);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL rep_predicate(BOOL first_iteration) {
  ////printf("rep_predicate\n");
  /* return the flag; typically this is true only once */
  return first_iteration;
}

static void PIN_FAST_ANALYSIS_CALL _lea_opw(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  ////printf("_lea_opw\n");
  for (size_t i = 0; i < 2; i++)
    //RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
    RTAG[dst][i] = 0;
}

static void PIN_FAST_ANALYSIS_CALL _lea_opl(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  ////printf("_lea_opl\n");
  for (size_t i = 0; i < 4; i++)
    //RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
    RTAG[dst][i] = 0;
}

static void PIN_FAST_ANALYSIS_CALL _lea_opq(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  ////printf("_lea_opq\n");
  for (size_t i = 0; i < 8; i++)
    //RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
    RTAG[dst][i] = 0;
}

void ins_xfer_op(INS ins) {
  REG reg_dst, reg_src;

  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src)) {
        R2R_CALL_XFER(r2r_xfer_opb_l, reg_dst, reg_src);
      } else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src)) {
        R2R_CALL_XFER(r2r_xfer_opb_u, reg_dst, reg_src);
      } else if (REG_is_Lower8(reg_dst)) {
        R2R_CALL_XFER(r2r_xfer_opb_lu, reg_dst, reg_src);
      } else {
        R2R_CALL_XFER(r2r_xfer_opb_ul, reg_dst, reg_src);
      }
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL(m2r_xfer_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_xfer_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_xfer_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opb_l, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL_XFER(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL_XFER(r2m_xfer_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL_XFER(r2m_xfer_opw, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL_XFER(r2m_xfer_opx, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL_XFER(r2m_xfer_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL_XFER(r2m_xfer_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL_XFER(r2m_xfer_opb_u, reg_src);
    } else {
      R2M_CALL_XFER(r2m_xfer_opb_l, reg_src);
    }
  }
}

void ins_xfer_op_predicated(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opl, reg_dst, reg_src);
    } else {
      R2R_CALL_XFER(r2r_xfer_opw, reg_dst, reg_src);
    }
  } else {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    }
  }
}

void ins_push_op(INS ins) {
  ////printf("ins_push_op\n");
  REG reg_src;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_src = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL_XFER(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL_XFER(r2m_xfer_opl, reg_src);
    } else {
      R2M_CALL_XFER(r2m_xfer_opw, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL(m2m_xfer_opl);
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  } else {
    INT32 n = INS_OperandWidth(ins, OP_0) / 8;
    M_CLEAR_N(n);
  }
}

void ins_pop_op(INS ins) {
  ////printf("ins_pop_op\n");
  REG reg_dst;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL(m2m_xfer_opl);
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  }
}

void ins_stos_ins(INS ins, AFUNPTR fn) {
  ////printf("ins_stos_ins\n");
  INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)rep_predicate,
                             IARG_FAST_ANALYSIS_CALL, IARG_FIRST_REP_ITERATION,
                             IARG_END);
  INS_InsertThenPredicatedCall(
      ins, IPOINT_BEFORE, fn, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
      IARG_MEMORYWRITE_EA, IARG_REG_VALUE, INS_RepCountRegister(ins),
      IARG_REG_VALUE, INS_OperandReg(ins, OP_4), IARG_INST_PTR, IARG_END);
}

void ins_stosb(INS ins) {
  ////printf("ins_stosb\n");
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opbn);
  } else {
    R2M_CALL_XFER(r2m_xfer_opb_l, REG_AL);
  }
}

void ins_stosw(INS ins) {
  ////printf("ins_stosw\n");
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opwn);
  } else {
    R2M_CALL_XFER(r2m_xfer_opw, REG_AX);
  }
}

void ins_stosd(INS ins) {
  ////printf("ins_stosd\n");
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opln);
  } else {
    R2M_CALL_XFER(r2m_xfer_opw, REG_EAX);
  }
}

void ins_stosq(INS ins) {
  ////printf("ins_stosq\n");
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opqn);
  } else {
    R2M_CALL_XFER(r2m_xfer_opw, REG_RAX);
  }
}

void ins_movlp(INS ins) {
  ////printf("ins movlp\n");
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL_XFER(r2m_xfer_opq, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL(m2r_xfer_opq, reg_dst);
  }
}

void ins_movhp(INS ins) {
  ////printf("ins movhp\n");
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL_XFER(r2m_xfer_opq_h, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL(m2r_xfer_opq_h, reg_dst);
  }
}

void ins_lea(INS ins) {
  ////printf("ins_lea\n");
  REG reg_base = INS_MemoryBaseReg(ins);
  REG reg_indx = INS_MemoryIndexReg(ins);
  REG reg_dst = INS_OperandReg(ins, OP_0);
  if (reg_base == REG_INVALID() && reg_indx == REG_INVALID()) {
    ins_clear_op(ins);
  }
  if (reg_base != REG_INVALID() && reg_indx == REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opq, reg_dst, reg_base);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opl, reg_dst, reg_base);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opw, reg_dst, reg_base);
    }
  }
  if (reg_base == REG_INVALID() && reg_indx != REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opq, reg_dst, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opl, reg_dst, reg_indx);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL_XFER(r2r_xfer_opw, reg_dst, reg_indx);
    }
  }
  if (reg_base != REG_INVALID() && reg_indx != REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      RR2R_CALL(_lea_opq, reg_dst, reg_base, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      RR2R_CALL(_lea_opl, reg_dst, reg_base, reg_indx);
    } else if (REG_is_gr16(reg_dst)) {
      RR2R_CALL(_lea_opw, reg_dst, reg_base, reg_indx);
    }
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for(i = 0; i < 2; i++) {
    if(MTAG(src + (1 - i)) == 0) {
      RTAG[dst][i] = 0;
    } else if ((*(char *)(src+1-i)) == tagVal[int(MTAG(src+1-i))]) {
      flag = 1;
      RTAG[dst][i] = MTAG(src + (1 - i));
      insert_taint_mem_info(XFER_M2R, src+1-i, *((char *)(src+1-i)), MTAG(src+1-i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for(i = 0; i < 4; i++) {
    if(MTAG(src + (3 - i)) == 0) {
      RTAG[dst][i] = 0;
    } else if ((*(char *)(src+3-i)) == tagVal[int(MTAG(src+3-i))]) {
      flag = 1;
      RTAG[dst][i] = MTAG(src + (3 - i));
      insert_taint_mem_info(XFER_M2R, src+3-i, *((char *)(src+3-i)), MTAG(src+3-i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src, ADDRINT applicationIP) {
  int i;
  int flag = 0;
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  for(i = 0; i < 8; i++) {
    if(MTAG(src + (7 - i)) == 0) {
      RTAG[dst][i] = 0;
    } else if ((*(char *)(src+7-i)) == tagVal[int(MTAG(src+7-i))]) {
      flag = 1;
      RTAG[dst][i] = MTAG(src + (7 - i));
      insert_taint_mem_info(XFER_M2R, src+7-i, *((char *)(src+7-i)), MTAG(src+7-i), name_tmp);
    }
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int i;
  int flag = 0;
  char src_val[2];
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t *src_tags = RTAG[src];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  for (i = 0; i < 2; i++) {
    if (src_tags[i] == 0) {
      tagmap_setb(dst + (1 - i), 0);
    } else if (src_val[i] == tagVal[int(src_tags[i])]) {
      flag = 1;
      insert_taint_mem_info(XFER_R2M, dst+1-i, src_val[i], src_tags[i], name_tmp);
      tagmap_setb(dst + (1 - i), src_tags[i]);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) {
  int i;
  int flag = 0;
  char src_val[4];
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t *src_tags = RTAG[src];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  for (i = 0; i < 4; i++) {
    if (src_tags[i] == 0) {
      tagmap_setb(dst + (3 - i), 0);
    } else if (src_val[i] == tagVal[int(src_tags[i])]) {
      flag = 1;
      insert_taint_mem_info(XFER_R2M, dst+3-i, src_val[i], src_tags[i], name_tmp);
      tagmap_setb(dst + (3 - i), src_tags[i]);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt, REG src_reg) { 
  int i;
  int flag = 0;
  char src_val[8];
  const char *name_tmp = RTN_FindNameByAddress(applicationIP).c_str();

  tag_t *src_tags = RTAG[src];
  PIN_GetContextRegval(ctxt, src_reg, (UINT8 *)&src_val);

  for (i = 0; i < 8; i++) {
    if (src_tags[i] == 0) {
      tagmap_setb(dst + (7 - i), 0);
    } else if (src_val[i] == tagVal[int(src_tags[i])]) {
      flag = 1;
      insert_taint_mem_info(XFER_R2M, dst+7-i, src_val[i], src_tags[i], name_tmp);
      tagmap_setb(dst + (7 - i), src_tags[i]);
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void ins_movbe_op(INS ins) {
  ////printf("ins movbe op\n");
  if (INS_OperandIsMemory(ins, OP_1)) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq_rev, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl_rev, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw_rev, reg_dst);
    }
  } else {
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq_rev, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl_rev, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw_rev, reg_src);
    }
  }
}