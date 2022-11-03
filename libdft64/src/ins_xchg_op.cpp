#include "ins_xchg_op.h"
#include "ins_helper.h"
#include "ins_xfer_op.h"
#include "taint_info.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

/*
 * Compare and Exchange
 *
 * INS dest, src
 * 
 * if dest == rax
 *    dest = src
 * else
 *    rax = dest 
 */

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opq_fast(THREADID tid,
                                                            uint32_t rax_val,
                                                            uint32_t dst,
                                                            uint32_t dst_val, ADDRINT applicationIP) {
  /* save the tag value of dst in the scratch register */
  tag_t save_tags[] = R64TAG(DFT_REG_RAX);
  int flag = 0;
  
  for (size_t i = 0; i < 8; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  /* update */
  tag_t dst_tags[] = R64TAG(dst);

  for (size_t i = 0; i < 8; i++) {
    if (dst_tags[i] != 0) {
      flag = 1;
    }
    RTAG[DFT_REG_RAX][i] = dst_tags[i];
  }

  if ((dst_val != rax_val) && flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  /* compare the dst and src values */
  return (rax_val == dst_val);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opq_slow(THREADID tid,
                                                         uint32_t dst,
                                                         uint32_t src, ADDRINT applicationIP) {
  /* restore the tag value from the scratch register */
  int flag = 0;
  tag_t saved_tags[] = {RTAG[DFT_REG_HELPER1][0], RTAG[DFT_REG_HELPER1][1],
                        RTAG[DFT_REG_HELPER1][2], RTAG[DFT_REG_HELPER1][3],
                        RTAG[DFT_REG_HELPER1][4], RTAG[DFT_REG_HELPER1][5],
                        RTAG[DFT_REG_HELPER1][6], RTAG[DFT_REG_HELPER1][7]};
  for (size_t i = 0; i < 8; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = {RTAG[src][0], RTAG[src][1], RTAG[src][2], RTAG[src][3],
                      RTAG[src][4], RTAG[src][5], RTAG[src][6], RTAG[src][7]};
  for (size_t i = 0; i < 8; i++) {
    if (src_tags[i] != 0) {
      flag = 1;
    }
    RTAG[dst][i] = src_tags[i];
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opl_fast(THREADID tid,
                                                            uint32_t rax_val,
                                                            uint32_t dst,
                                                            uint32_t dst_val, ADDRINT applicationIP) {
  /* save the tag value of dst in the scratch register */
  int flag = 0;
  tag_t save_tags[] = R32TAG(DFT_REG_RAX);
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  /* update */
  tag_t dst_tags[] = R32TAG(dst);

  for (size_t i = 0; i < 4; i++) {
    if (dst_tags[i] != 0) {
      flag = 1;
    }
    RTAG[DFT_REG_RAX][i] = dst_tags[i];
  }
  if ((dst_val != rax_val) && flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  /* compare the dst and src values */
  return (rax_val == dst_val);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opl_slow(THREADID tid,
                                                         uint32_t dst,
                                                         uint32_t src, ADDRINT applicationIP) {
  /* restore the tag value from the scratch register */
  int flag = 0;
  tag_t saved_tags[] = {RTAG[DFT_REG_HELPER1][0], RTAG[DFT_REG_HELPER1][1],
                        RTAG[DFT_REG_HELPER1][2], RTAG[DFT_REG_HELPER1][3]};
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = {RTAG[src][0], RTAG[src][1], RTAG[src][2], RTAG[src][3]};
  for (size_t i = 0; i < 4; i++) {
    if (src_tags[i] != 0) {
      flag = 1;
    }
    RTAG[dst][i] = src_tags[i];
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opw_fast(THREADID tid,
                                                            uint16_t rax_val,
                                                            uint32_t dst,
                                                            uint16_t dst_val, ADDRINT applicationIP) {
  /* save the tag value of dst in the scratch register */
  int flag = 0;
  tag_t save_tags[] = R32TAG(DFT_REG_RAX);
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  tag_t dst_tags[] = R16TAG(dst);
  RTAG[DFT_REG_RAX][0] = dst_tags[0];
  RTAG[DFT_REG_RAX][1] = dst_tags[1];

  for (size_t i = 0; i < 2; i++) {
    if (dst_tags[i] != 0) {
      flag = 1;
    }
    RTAG[DFT_REG_RAX][i] = dst_tags[i];
  }
  if ((dst_val != rax_val) && flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
  /* compare the dst and src values */
  return (rax_val == dst_val);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opw_slow(THREADID tid,
                                                         uint32_t dst,
                                                         uint32_t src, ADDRINT applicationIP) {
  /* restore the tag value from the scratch register */
  int flag = 0;
  tag_t saved_tags[] = {RTAG[DFT_REG_HELPER1][0], RTAG[DFT_REG_HELPER1][1],
                        RTAG[DFT_REG_HELPER1][2], RTAG[DFT_REG_HELPER1][3]};
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = {RTAG[src][0], RTAG[src][1]};

  for (size_t i = 0; i < 2; i++) {
    if (src_tags[i] != 0) {
      flag = 1;
    }
    RTAG[dst][i] = src_tags[i];
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);  
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_m2r_opq_fast(THREADID tid,
                                                            uint32_t rax_val,
                                                            ADDRINT dst, ADDRINT applicationIP) {
  /* save the tag value of dst in the scratch register */
  int flag = 0;
  tag_t save_tags[] = {RTAG[DFT_REG_RAX][0], RTAG[DFT_REG_RAX][1],
                       RTAG[DFT_REG_RAX][2], RTAG[DFT_REG_RAX][3],
                       RTAG[DFT_REG_RAX][4], RTAG[DFT_REG_RAX][5],
                       RTAG[DFT_REG_RAX][6], RTAG[DFT_REG_RAX][7]};
  for (size_t i = 0; i < 8; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  tag_t dst_tags[] = {tagmap_getb(dst),     tagmap_getb(dst + 1),
                      tagmap_getb(dst + 2), tagmap_getb(dst + 3),
                      tagmap_getb(dst + 4), tagmap_getb(dst + 5),
                      tagmap_getb(dst + 6), tagmap_getb(dst + 7)};
  for (size_t i = 0; i < 8; i++) {
    if (dst_tags[i] != 0 && (rax_val == *(uint32_t *)dst)) {
      flag = 1;
      insert_taint_mem_info(XFER_M2R, dst+i, *((char *)(dst+i)), dst_tags[i], RTN_FindNameByAddress(applicationIP).c_str());
    }
    RTAG[DFT_REG_RAX][i] = dst_tags[i];
  }

  if ((rax_val == *(uint32_t *)dst) && flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  return (rax_val == *(uint32_t *)dst);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2m_opq_slow(THREADID tid,
                                                         ADDRINT dst,
                                                         uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t saved_tags[] = R64TAG(DFT_REG_HELPER1);
  for (size_t i = 0; i < 8; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = R64TAG(src);
  for (size_t i = 0; i < 8; i++) {
    if (src_tags[i] != 0) {
      flag = 1;
      insert_taint_mem_info(XFER_R2M, dst+i, 0, 0, RTN_FindNameByAddress(applicationIP).c_str());
    }
    tagmap_setb(dst + i, src_tags[i]);
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_m2r_opl_fast(THREADID tid,
                                                            uint32_t rax_val,
                                                            ADDRINT dst, ADDRINT applicationIP) {
  /* save the tag value of dst in the scratch register */
  int flag = 0;
  tag_t save_tags[] = {RTAG[DFT_REG_RAX][0], RTAG[DFT_REG_RAX][1],
                       RTAG[DFT_REG_RAX][2], RTAG[DFT_REG_RAX][3]};
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  tag_t dst_tags[] = {tagmap_getb(dst), tagmap_getb(dst + 1),
                      tagmap_getb(dst + 2), tagmap_getb(dst + 3)};

  for (size_t i = 0; i < 4; i++) {
    if (dst_tags[i] != 0 && (rax_val == *(uint32_t *)dst)) {
      flag = 1;
      insert_taint_mem_info(XFER_M2R, dst+i, *((char *)(dst+i)), dst_tags[i], RTN_FindNameByAddress(applicationIP).c_str());
    }
    RTAG[DFT_REG_RAX][i] = dst_tags[i];
  }

  if ((rax_val == *(uint32_t *)dst) && flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  return (rax_val == *(uint32_t *)dst);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2m_opl_slow(THREADID tid,
                                                         ADDRINT dst,
                                                         uint32_t src, ADDRINT applicationIP) {
  int flag = 0;
  tag_t saved_tags[] = R32TAG(DFT_REG_HELPER1);
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = R32TAG(src);
  for (size_t i = 0; i < 4; i++) {
    if (src_tags[i] != 0) {
      flag = 1;
      insert_taint_mem_info(XFER_R2M, dst+i, 0, 0, RTN_FindNameByAddress(applicationIP).c_str());
    }
    tagmap_setb(dst + i, src_tags[i]);
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_m2r_opw_fast(THREADID tid,
                                                            uint16_t rax_val,
                                                            ADDRINT dst, ADDRINT applicationIP) {
  /* save the tag value of dst in the scratch register */
  int flag = 0;
  tag_t save_tags[] = {RTAG[DFT_REG_RAX][0], RTAG[DFT_REG_RAX][1],
                       RTAG[DFT_REG_RAX][2], RTAG[DFT_REG_RAX][3]};

  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  tag_t dst_tags[] = {tagmap_getb(dst), tagmap_getb(dst + 1)};
  for (size_t i = 0; i < 2; i++) {
    if (dst_tags[i] != 0 && (rax_val == *(uint32_t *)dst)) {
      flag = 1;
      insert_taint_mem_info(XFER_M2R, dst+i, *((char *)(dst+i)), dst_tags[i], RTN_FindNameByAddress(applicationIP).c_str());
    }
    RTAG[DFT_REG_RAX][i] = dst_tags[i];
  }

  if ((rax_val == *(uint32_t *)dst) && flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  /* compare the dst and src values; the original values the tag bits */
  return (rax_val == *(uint32_t *)dst);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2m_opw_slow(THREADID tid,
                                                         ADDRINT dst,
                                                         uint32_t src, ADDRINT applicationIP) {
  /* restore the tag value from the scratch register */
  int flag = 0;
  tag_t saved_tags[] = {RTAG[DFT_REG_HELPER1][0], RTAG[DFT_REG_HELPER1][1],
                        RTAG[DFT_REG_HELPER1][2], RTAG[DFT_REG_HELPER1][3]};

  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = {RTAG[src][0], RTAG[src][1]};
  for (size_t i = 0; i < 2; i++) {
    if (src_tags[i] != 0) {
      flag = 1;
      insert_taint_mem_info(XFER_R2M, dst+i, 0, 0, RTN_FindNameByAddress(applicationIP).c_str());
    }
    tagmap_setb(dst + i, src_tags[i]);
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opb_ul(THREADID tid, uint32_t dst,
                                                    uint32_t src, ADDRINT applicationIP) {
  /* temporary tag value */
  tag_t dst_tag = RTAG[dst][1];
  tag_t src_tag = RTAG[src][0];

  if (src_tag != 0 || dst_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  /* swap */
  RTAG[dst][1] = src_tag;
  RTAG[src][0] = dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opb_lu(THREADID tid, uint32_t dst,
                                                    uint32_t src, ADDRINT applicationIP) {
  /* temporary tag value */
  tag_t dst_tag = RTAG[dst][0];
  tag_t src_tag = RTAG[src][1];

  if (src_tag != 0 || dst_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  /* swap */
  RTAG[dst][0] = src_tag;
  RTAG[src][1] = dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opb_u(THREADID tid, uint32_t dst,
                                                   uint32_t src, ADDRINT applicationIP) {
  /* temporary tag value */
  tag_t dst_tag = RTAG[dst][1];
  tag_t src_tag = RTAG[src][1];

  if (src_tag != 0 || dst_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  /* swap */
  RTAG[dst][1] = src_tag;
  RTAG[src][1] = dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opb_l(THREADID tid, uint32_t dst,
                                                   uint32_t src, ADDRINT applicationIP) {
  tag_t dst_tag = RTAG[dst][0];
  tag_t src_tag = RTAG[src][0];

  if (src_tag != 0 || dst_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  /* swap */
  RTAG[dst][0] = src_tag;
  RTAG[src][0] = dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opw(THREADID tid, uint32_t dst,
                                                 uint32_t src, ADDRINT applicationIP) {
  tag_t dst_tag[] = R16TAG(dst);
  tag_t src_tag[] = R16TAG(src);
  int flag = 0;
  
  for (size_t i = 0; i < 2; i++) {
    if (src_tag != 0 || dst_tag != 0) {
      flag = 1;
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  /* swap */
  RTAG[dst][0] = src_tag[0];
  RTAG[dst][1] = src_tag[1];
  RTAG[src][0] = dst_tag[0];
  RTAG[src][1] = dst_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opl(THREADID tid, uint32_t dst,
                                                 uint32_t src, ADDRINT applicationIP) {
  tag_t dst_tag[] = R32TAG(dst);
  tag_t src_tag[] = R32TAG(src);
  int flag = 0;

  for (size_t i = 0; i < 4; i++) {
    if (src_tag[i] != 0 || dst_tag[i] != 0) {
      flag = 1;
    }
    
    RTAG[dst][i] = src_tag[i];
    RTAG[src][i] = dst_tag[i];
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opq(THREADID tid, uint32_t dst,
                                                 uint32_t src, ADDRINT applicationIP) {
  tag_t dst_tag[] = R64TAG(dst);
  tag_t src_tag[] = R64TAG(src);
  int flag = 0;

  for (size_t i = 0; i < 8; i++) {
    if (src_tag[i] != 0 || dst_tag[i] != 0) {
      flag = 1;
    }
    
    RTAG[dst][i] = src_tag[i];
    RTAG[src][i] = dst_tag[i];
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opb_u(THREADID tid, uint32_t dst,
                                                   ADDRINT src, ADDRINT applicationIP) {
  /* temporary tag value */
  tag_t dst_tag = RTAG[dst][1];
  tag_t src_tag = M8TAG(src);

  if (src_tag != 0 || dst_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  if (src_tag != 0) {
    insert_taint_mem_info(XFER_M2R, src, *((char *)src), src_tag, RTN_FindNameByAddress(applicationIP).c_str());
  }

  /* swap */
  RTAG[dst][1] = src_tag;
  tagmap_setb(src, dst_tag);
}
static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opb_l(THREADID tid, uint32_t dst,
                                                   ADDRINT src, ADDRINT applicationIP) {
  /* temporary tag value */
  tag_t dst_tag = RTAG[dst][0];
  tag_t src_tag = M8TAG(src);

  if (src_tag != 0 || dst_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  if (src_tag != 0) {
    insert_taint_mem_info(XFER_M2R, src, *((char *)src), src_tag, RTN_FindNameByAddress(applicationIP).c_str());
  }

  /* swap */
  RTAG[dst][0] = src_tag;
  tagmap_setb(src, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opw(THREADID tid, uint32_t dst,
                                                 ADDRINT src, ADDRINT applicationIP) {
  /* temporary tag value */
  tag_t dst_tag[] = R16TAG(dst);
  tag_t src_tag[] = M16TAG(src);
  int flag = 0;

  for (size_t i = 0; i < 2; i++) {
    if (src_tag[i] != 0 || dst_tag[i] != 0) {
      flag = 1;
    }
    if (src_tag[i] != 0) {
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), src_tag[i], RTN_FindNameByAddress(applicationIP).c_str());
    }
    /* swap */
    RTAG[dst][i] = src_tag[i];
    tagmap_setb(src + i, dst_tag[i]);
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opq(THREADID tid, uint32_t dst,
                                                 ADDRINT src, ADDRINT applicationIP) {
  /* temporary tag value */
  tag_t dst_tag[] = R64TAG(dst);
  tag_t src_tag[] = M64TAG(src);
  int flag = 0;

  for (size_t i = 0; i < 8; i++) {
    if (src_tag[i] != 0 || dst_tag[i] != 0) {
      flag = 1;
    }
    if (src_tag[i] != 0) {
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), src_tag[i], RTN_FindNameByAddress(applicationIP).c_str());
    }
    /* swap */
    RTAG[dst][i] = src_tag[i];
    tagmap_setb(src + i, dst_tag[i]);
  }
  
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opl(THREADID tid, uint32_t dst,
                                                 ADDRINT src, ADDRINT applicationIP) {
  /* temporary tag value */
  tag_t dst_tag[] = R64TAG(dst);
  tag_t src_tag[] = M64TAG(src);
  int flag = 0;

  for (size_t i = 0; i < 4; i++) {
    if (src_tag[i] != 0 || dst_tag[i] != 0) {
      flag = 1;
    }
    if (src_tag[i] != 0) {
      insert_taint_mem_info(XFER_M2R, src+i, *((char *)(src+i)), src_tag[i], RTN_FindNameByAddress(applicationIP).c_str());
    }
    /* swap */
    RTAG[dst][i] = src_tag[i];
    tagmap_setb(src + i, dst_tag[i]);
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

/*
 * Exchange and Add
 *
 * INS dest src
 * 
 * temp = src + dest
 * src = dest
 * dest = temp 
 */

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opb_ul(THREADID tid, uint32_t dst,
                                                    uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t dst_tag = RTAG[dst][1];
  tag_t src_tag = RTAG[src][0];

  if (dst_tag != 0 || src_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  RTAG[dst][1] = 0;
  RTAG[src][0] = dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opb_lu(THREADID tid, uint32_t dst,
                                                    uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t dst_tag = RTAG[dst][0];
  tag_t src_tag = RTAG[src][1];

  if (dst_tag != 0 || src_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  RTAG[dst][0] = 0;
  RTAG[src][1] = dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opb_u(THREADID tid, uint32_t dst,
                                                   uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t dst_tag = RTAG[dst][1];
  tag_t src_tag = RTAG[src][1];

  if (dst_tag != 0 || src_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  RTAG[dst][1] = 0;
  RTAG[src][1] = dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opb_l(THREADID tid, uint32_t dst,
                                                   uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t dst_tag = RTAG[dst][0];
  tag_t src_tag = RTAG[src][0];

  if (dst_tag != 0 || src_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  RTAG[dst][0] = 0;
  RTAG[src][0] = dst_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opw(THREADID tid, uint32_t dst,
                                                 uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t dst_tag[] = {RTAG[dst][0], RTAG[dst][1]};
  tag_t src_tag[] = {RTAG[src][0], RTAG[src][1]};
  int i;
  int flag = 0;

  for (i = 0; i < 2; i++) {
    if (dst_tag[i] != 0 || src_tag[i] != 0) {
      flag = 1;
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  RTAG[dst][0] = 0;
  RTAG[dst][1] = 0;
  RTAG[src][0] = dst_tag[0];
  RTAG[src][1] = dst_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opl(THREADID tid, uint32_t dst,
                                                 uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t dst_tag[] = R32TAG(dst);
  tag_t src_tag[] = R32TAG(src);
  int flag = 0;
  
  for (size_t i = 0; i < 4; i++) {
    if (dst_tag[i] != 0 || src_tag[i] != 0) {
      flag = 1;
    }

    RTAG[dst][i] = 0;
    RTAG[src][i] = dst_tag[i];
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opq(THREADID tid, uint32_t dst,
                                                 uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t dst_tag[] = R64TAG(dst);
  tag_t src_tag[] = R64TAG(src);
  int flag = 0;
  
  for (size_t i = 0; i < 8; i++) {
    if (dst_tag[i] != 0 || src_tag[i] != 0) {
      flag = 1;
    }
    
    RTAG[dst][i] = 0;
    RTAG[src][i] = dst_tag[i];
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opb_u(THREADID tid, ADDRINT dst,
                                                   uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = tagmap_getb(dst);

  if (dst_tag != 0 || src_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  RTAG[src][1] = dst_tag;
  tagmap_setb(dst, 0);
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opb_l(THREADID tid, ADDRINT dst,
                                                   uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = tagmap_getb(dst);

  if (dst_tag != 0 || src_tag != 0) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  RTAG[src][0] = dst_tag;
  tagmap_setb(dst, 0);
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opw(THREADID tid, ADDRINT dst,
                                                 uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t src_tag[] = R16TAG(src);
  tag_t dst_tag[] = M16TAG(dst);
  int flag = 0;

  for (size_t i = 0; i < 2; i++) {
    if (dst_tag[i] != 0 || src_tag[i] != 0) {
      flag = 1;
    }
  }

  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }

  RTAG[src][0] = dst_tag[0];
  RTAG[src][1] = dst_tag[1];

  tagmap_setb(dst, 0);
  tagmap_setb(dst + 1, 0);
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opl(THREADID tid, ADDRINT dst,
                                                 uint32_t src, ADDRINT applicationIP, CONTEXT *ctxt) {
  tag_t src_tag[] = R32TAG(src);
  tag_t dst_tag[] = M32TAG(dst);
  int flag = 0;

  for (size_t i = 0; i < 4; i++) {
    if (dst_tag[i] != 0 || src_tag[i] != 0) {
      flag = 1;
    }
    
    tagmap_setb(dst + i, 0);
    RTAG[src][i] = dst_tag[i];
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opq(THREADID tid, ADDRINT dst,
                                                 uint32_t src, ADDRINT applicationIP) {
  tag_t src_tag[] = R64TAG(src);
  tag_t dst_tag[] = M64TAG(dst);
  int flag = 0;

  for (size_t i = 0; i < 8; i++) {
    if (src_tag[i] != 0 || dst_tag[i] != 0) {
      flag = 1;
    }
    
    tagmap_setb(dst + i, 0);
    RTAG[src][i] = dst_tag[i];
  }
  if (flag) {
    insert_taint_inst(RTN_FindNameByAddress(applicationIP).c_str(), applicationIP);
  }
}

void ins_cmpxchg_op(INS ins) {
  //printf("ins cmpxchg op\n");
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opq_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_UINT32, REG_INDX(reg_dst), IARG_REG_VALUE,
                       reg_dst, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opq_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                         REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                         IARG_INST_PTR, IARG_END);
    } else if (REG_is_gr32(reg_dst)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opl_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_UINT32, REG_INDX(reg_dst), IARG_REG_VALUE,
                       reg_dst, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opl_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                         REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                         IARG_INST_PTR, IARG_END);
    } else if (REG_is_gr16(reg_dst)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opw_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_AX, IARG_UINT32, REG_INDX(reg_dst), IARG_REG_VALUE,
                       reg_dst, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opw_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                         REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                         IARG_INST_PTR, IARG_END);
    } else {
      xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
      LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) +
          ")\n");
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_m2r_opq_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2m_opq_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                         IARG_MEMORYWRITE_EA, IARG_UINT32, REG_INDX(reg_src),
                         IARG_INST_PTR, IARG_END);
    } else if (REG_is_gr32(reg_src)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_m2r_opl_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2m_opl_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                         IARG_MEMORYWRITE_EA, IARG_UINT32, REG_INDX(reg_src),
                         IARG_INST_PTR, IARG_END);
    } else if (REG_is_gr16(reg_src)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_m2r_opw_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_AX, IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2m_opw_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                         IARG_MEMORYWRITE_EA, IARG_UINT32, REG_INDX(reg_src),
                         IARG_INST_PTR, IARG_END);
    } else {
      xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
      LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) +
          ")\n");
    }
  }
}

void ins_xchg_op(INS ins) {
  //printf("ins xchg op\n");
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) 
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opq,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_INST_PTR, IARG_END);
    else if (REG_is_gr32(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opl,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_INST_PTR, IARG_END);
    else if (REG_is_gr16(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opw,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                     IARG_INST_PTR, IARG_END);
    else if (REG_is_gr8(reg_dst)) {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opb_l,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_INST_PTR, IARG_END);
      else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opb_u,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_INST_PTR, IARG_END);
      else if (REG_is_Lower8(reg_dst))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opb_lu,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_INST_PTR, IARG_END);
      else
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opb_ul,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_INST_PTR, IARG_END);
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opq,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_END);
    else if (REG_is_gr32(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opl,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_END);
    else if (REG_is_gr16(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opw,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_END);
    else if (REG_is_Upper8(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opb_u,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_END);
    else
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opb_l,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_END);
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opq,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_INST_PTR, IARG_END);
    else if (REG_is_gr32(reg_src))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opl,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_INST_PTR, IARG_END);
    else if (REG_is_gr16(reg_src))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opw,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_INST_PTR, IARG_END);
    else if (REG_is_Upper8(reg_src))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opb_u,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_INST_PTR, IARG_END);
    else
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opb_l,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_INST_PTR, IARG_END);
  }
}

void ins_xadd_op(INS ins) {
  //printf("ins xadd op\n");
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(_xadd_r2r_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(_xadd_r2r_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(_xadd_r2r_opw, reg_dst, reg_src);
    } else if (REG_is_gr8(reg_dst)) {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))
        R2R_CALL(_xadd_r2r_opb_l, reg_dst, reg_src);
      else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
        R2R_CALL(_xadd_r2r_opb_u, reg_dst, reg_src);
      else if (REG_is_Lower8(reg_dst))
        R2R_CALL(_xadd_r2r_opb_lu, reg_dst, reg_src);
      else
        R2R_CALL(_xadd_r2r_opb_ul, reg_dst, reg_src);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(_xadd_r2m_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(_xadd_r2m_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(_xadd_r2m_opw, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(_xadd_r2m_opb_u, reg_src);
    } else {
      R2M_CALL(_xadd_r2m_opb_l, reg_src);
    }
  }
}