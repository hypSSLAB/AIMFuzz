#include "bdd_tag.h"
#include "debug.h"
#include "tag_traits.h"
#include "pin.H"
#include "tagmap.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <math.h>

#include <cmath>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stack>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>

using namespace std;

#define XFER_M2R        0
#define XFER_R2M        1
#define XFER_M2M        2
#define XFER_R2R        4

#define ARITH_M2R       100
#define ARITH_R2M       101
#define ARITH_M2M       102
#define ARITH_R2R       103

#define COMP_M          200

#define TARGET_FINDING          0
#define TAINT_REGION_FINDING    1

typedef struct FuncNode {
    FuncNode *caller;
    vector<FuncNode *> callee;
    string func_name;
    ADDRINT stack_base;
    double my_score;
    double score;
    int seq_num;
    map<uint64_t, map<uint64_t, uint64_t>> taint_inst;
    //map<uint64_t, uint64_t> taint_inst;
    int depth;
    int taint_inst_used;
    uint64_t origianl_tag_used;
    uint64_t modified_tag_used;
} FuncNode;

typedef struct ScoreNode {
    string func_name;
    int seq_num;
    double my_score;
    int depth;
} ScoreNode;
 
extern string target2find;
extern int TAINT_MODE;
extern int taint_logging;
extern int seq_num;

void insert_taint_mem_info(int ins_type, ADDRINT addr, char value, tag_t tag, string func_name);

void insert_taint_inst(string func_name, uint64_t addr);
void print_taint_info();

void insert_tagVal(tag_t tag, char val);
void print_tagVal();

tag_t is_tainted(ADDRINT addr, size_t size); 
void print_tagged_memory(int pollute);

void log_before_taint_mem_list();
void print_func_taint_mem_info();