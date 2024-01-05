#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_hook.h"
#include "taint_info.h"
#include <iostream>

using namespace std;

VOID TestGetHandler(void *p, unsigned int n) {
  n=4;
  printf("n : %d\n", n);
  uint64_t v = *((uint64_t *)p);
  tag_t t = tagmap_getn((ADDRINT)p, n);
  printf("[PIN][GET] addr: %p, v: %lu, lb: %d, taint: %s\n", p, v, t,
         tag_sprint(t).c_str());
}

VOID TestGetValHandler(THREADID tid, uint64_t v) {
  tag_t t = tagmap_getn_reg(tid, X64_ARG0_REG, 8);
  printf("[PIN][GETVAL] v: %lu, lb: %d, taint: %s\n", v, t,
         tag_sprint(t).c_str());
}

// p = memory address or register
// v = data size
VOID TestSetHandler(void *p, unsigned int v) {
  tag_t t = tag_alloc<tag_t>(v);
  tagmap_setb((ADDRINT)p, t);
  printf("[PIN][SET] addr: %p, lb: %d, taint: %d\n", p, t, v);
}

VOID EntryPoint(VOID *v) {

  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
    RTN test_get_rtn = RTN_FindByName(img, "__libdft_get_taint");
    if (RTN_Valid(test_get_rtn)) {
      RTN_Open(test_get_rtn);
      RTN_InsertCall(test_get_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
      RTN_Close(test_get_rtn);
    }

    RTN test_set_rtn = RTN_FindByName(img, "__libdft_set_taint");
    if (RTN_Valid(test_set_rtn)) {
      RTN_Open(test_set_rtn);
      RTN_InsertCall(test_set_rtn, IPOINT_BEFORE, (AFUNPTR)TestSetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
      RTN_Close(test_set_rtn);
    }

    RTN test_getval_rtn = RTN_FindByName(img, "__libdft_getval_taint");
    if (RTN_Valid(test_getval_rtn)) {
      RTN_Open(test_getval_rtn);

      RTN_InsertCall(test_getval_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetValHandler,
                     IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_END);
      RTN_Close(test_getval_rtn);
    }
  }
}

VOID fini_function(INT32 code, VOID* v)
{
  std::cout << "fini function" << std::endl;

  if (TAINT_MODE == TARGET_FINDING) {
    print_taint_info();
  } else if (TAINT_MODE == TAINT_REGION_FINDING) {
    print_tagVal();
    print_func_taint_mem_info();
  }
}

int ins_flag = 0;
int monitor_taint_flag = 0;

static BOOL OnCommand(THREADID, CONTEXT* ctxt, const std::string& _cmd, std::string* reply, VOID*)
{
  vector<string> parsed_cmd;
  string token;
  string delimiter = " ";
  string cmd = _cmd;

  size_t pos = 0;
  while((pos = cmd.find(delimiter)) != string::npos) {
    token = cmd.substr(0, pos);
    parsed_cmd.push_back(token);
    cmd.erase(0, pos + delimiter.length());
  }
  parsed_cmd.push_back(cmd);

  if (parsed_cmd[0].compare("tag") == 0 && parsed_cmd.size() > 1) {
    if (parsed_cmd[1].compare("all") == 0) {
      int pollute = 0;
      if (parsed_cmd.size() > 2 && parsed_cmd[2].compare("pollute") == 0) {
        pollute = 1;
      }

      print_tagged_memory(pollute);
      return TRUE;
    } else if (parsed_cmd.size() > 2) {
      ADDRINT addr = strtol(parsed_cmd[1].c_str(), 0, 16);
      size_t range = strtol(parsed_cmd[2].c_str(), 0, 16);
      is_tainted(addr, range);
      return TRUE;
    } 
  }
  if (parsed_cmd[0].compare("opcode") == 0) {
    ins_flag = 1;
    return TRUE;
  }
  if (parsed_cmd[0].compare("taint") == 0) {
    if (monitor_taint_flag) {
      cout << "deactivate monitoring" << endl;
    } else {
      cout << "activate monitoring" << endl;
    }
    monitor_taint_flag = !monitor_taint_flag;
    return TRUE;
  }

  return FALSE;
}

int pollution_mode;

extern double callee_weight;
extern int taint_weight;

int main(int argc, char *argv[]) {
  int i;

  std::cout << "start track.cpp" << std::endl;
  PIN_InitSymbols();

  char *temp_callee_str;
  char *temp_taint_str;
  double temp_callee;
  int temp_taint;

  if ((temp_callee_str=getenv("CALLEE_WEIGHT"))) {
    sscanf(temp_callee_str, "%lf", &temp_callee);
    cout << "callee_weight : " << temp_callee << endl;
    callee_weight = temp_callee;
  }
  if ((temp_taint_str=getenv("TAINT_WEIGHT"))) {
    sscanf(temp_taint_str, "%d", &temp_taint);
    cout << "taint_weight : " << temp_taint << endl;
    taint_weight = temp_taint;
  }

  for (i = 0; i < argc; i++) {
    if (string(argv[i]).compare("-w") == 0) {
      cout << "Activate Pollution Mode" << endl;
      pollution_mode = 1;

      for (int j = i; j < argc-1; j++) {
        argv[j] = argv[j+1];
      }
      argc--;

      break;
    }
  }


  for (i = 0; i < argc; i++) {
    if (string(argv[i]).compare("-P") == 0) {
      cout << "Activate Pollution Mode" << endl;
      pollution_mode = 1;

      for (int j = i; j < argc-1; j++) {
        argv[j] = argv[j+1];
      }
      argc--;

      break;
    }
  }

  for (i = 0; i < argc; i++) {
    if (string(argv[i]).compare("-t") == 0) {
      target2find = string(argv[i+2]);
      break;
    }
  }

  if (target2find.compare("--") != 0) {
    cout << "func name : " << target2find << endl;
    cout << "find tainted region" << endl;

    TAINT_MODE = TAINT_REGION_FINDING;

    for (int j = i+3; j < argc; j++) {
      argv[j-1] = argv[j];  
    }
    argc--;
  } else {
    cout << "find target function" << endl;
    TAINT_MODE = TARGET_FINDING;
  }

  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr
        << "Sth error in PIN_Init. Plz use the right command line options."
        << std::endl;
    return -1;
  }

  if (unlikely(libdft_init() != 0)) {
    std::cerr << "Sth error libdft_init." << std::endl;
    return -1;
  }

  PIN_AddDebugInterpreter(OnCommand, 0);

  PIN_AddApplicationStartFunction(EntryPoint, 0);
  hook_file_syscall();

  PIN_AddFiniFunction(fini_function, 0);
  PIN_StartProgram();
}
