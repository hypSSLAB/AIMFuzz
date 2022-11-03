/*
 * Copyright (C) 2019, Alex Bennée <alex.bennee@linaro.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

__attribute__ ((visibility("default"))) int commmon_flag = 1;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

void *qemu_get_cpu(int index);

uint64_t base_code_addr;
uint64_t persistent_addr;
uint64_t main_addr;
uint64_t ret_addr;
uint64_t caller_sp;
int is_target_logging;
int is_before_logging;
int is_logging_done;
int is_pie;

static GMutex exec_lock;
static GHashTable *exec_block;

static GHashTable *before_hash;
static GHashTable *target_hash;
//static GSList *before_list;
//static GSList *target_list;
GSList *intersect_list;

// translation block information
typedef struct {
    uint64_t start_addr;
    unsigned long insns;
} ExecInfo;

typedef struct {
    uint64_t addr;
} AddrInfo;

// get guest's rip register
static uint64_t get_cpu_register_rip(unsigned int cpu_index)
{
    uint8_t *cpu = qemu_get_cpu(cpu_index);

    // sizeof(CPUState) + sizeof(CPUNegativeOffsetState) + sizeof(regs)
    return *(uint64_t *)(cpu + 33512 + 8 + 128);
}

// get guest's rsp register (stack pointer)
static uint64_t get_cpu_register_rsp(unsigned int cpu_index) 
{
    uint8_t *cpu = qemu_get_cpu(cpu_index);

    // sizeof(CPUState) + sizeof(CPUNegativeOffsetState) + 4 * 8
    return *(uint64_t *)(cpu + 33512 + 8 + 32);
}


static gint list_comp(gconstpointer list1, gconstpointer list2) {
    AddrInfo *addr1 = (AddrInfo *)list1;
    AddrInfo *addr2 = (AddrInfo *)list2;
    
    return addr1->addr > addr2->addr;
}

void hash_free(gpointer key, gpointer value, gpointer user_data) {
    AddrInfo *del_info = (AddrInfo *)value;
    free(del_info);
}

void hash_iterator(gpointer key, gpointer value, gpointer user_data) {
    AddrInfo *tmp_info = (AddrInfo *)g_hash_table_lookup(user_data, (gconstpointer) key);
    if (tmp_info) {
        AddrInfo *new_addr = (AddrInfo *)malloc(sizeof(AddrInfo));
        new_addr->addr = tmp_info->addr;
        intersect_list = g_slist_prepend(intersect_list, new_addr);
    }
}

static void get_intersect_list() {
    GSList *target_iter;
    GSList *before_iter;
    uint64_t target_addr;
    uint64_t before_addr;
    uint64_t prev_addr;
    int before_size, target_size;

    before_size = g_hash_table_size(before_hash);
    target_size = g_hash_table_size(target_hash);
    fprintf(stderr, "before : %d\n", before_size);
    fprintf(stderr, "target : %d\n", target_size);
    fflush(stderr);

    if (before_size < 0 || target_size < 0) {
        fprintf(stderr, "overflow!\n");
        return;
    }

    fprintf(stderr, "iterating hash table...\n");
    fflush(stderr);
    if (before_size < target_size) {
        g_hash_table_foreach(before_hash, (GHFunc)hash_iterator, target_hash);

    } else {
        g_hash_table_foreach(target_hash, (GHFunc)hash_iterator, before_hash);
    }
    
    fprintf(stderr, "freeing hash table...\n");
    fflush(stderr);
    g_hash_table_foreach(before_hash, (GHFunc)hash_free, NULL);
    g_hash_table_foreach(target_hash, (GHFunc)hash_free, NULL);
    g_hash_table_destroy(before_hash);
    g_hash_table_destroy(target_hash);

    fprintf(stderr, "sorting intersection...\n");
    fprintf(stderr, "intersect size : %d\n", g_slist_length(intersect_list));
    fflush(stderr);
    intersect_list = g_slist_sort(intersect_list, (GCompareFunc)list_comp);

    //target_list = g_slist_sort(target_list, (GCompareFunc)list_comp);
    //before_list = g_slist_sort(before_list, (GCompareFunc)list_comp);

    //target_iter = target_list;
    //before_iter = before_list;
    /*
    while (1) {        
        if (!target_iter || !before_iter) {
            break;
        }
        target_addr = ((AddrInfo *)(target_iter->data))->addr;
        before_addr = ((AddrInfo *)(before_iter->data))->addr;
        
        if (target_addr == before_addr) {
            if (prev_addr != target_addr) {
                AddrInfo *new_addr = (AddrInfo *)malloc(sizeof(AddrInfo));
                new_addr->addr = target_addr;
                prev_addr = target_addr;
                intersect_list = g_slist_prepend(intersect_list, new_addr);
            }
            target_iter = target_iter->next;
            before_iter = before_iter->next;
        } else if (target_addr < before_addr) {
            target_iter = target_iter->next;
        } else {
            before_iter = before_iter->next;
        }        
    }
    */

    /*
    // free
    g_slist_foreach(before_list, (GFunc)g_free, NULL);
    g_slist_foreach(target_list, (GFunc)g_free, NULL);
    g_slist_free(before_list);
    g_slist_free(target_list);

    intersect_list = g_slist_sort(intersect_list, (GCompareFunc)list_comp);
    fprintf(stderr, "intersect : %d\n", g_slist_length(intersect_list));
    */
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{    
    // cannot reach here
    fprintf(stderr, "plugin exit...\n");
}

static void plugin_init(void)
{
    exec_block = g_hash_table_new(NULL, g_direct_equal);
    before_hash = g_hash_table_new(NULL, g_direct_equal);
    target_hash = g_hash_table_new(NULL, g_direct_equal);
}

static void vcpu_haddr(unsigned int cpu_index, qemu_plugin_meminfo_t meminfo,
                       uint64_t vaddr, void *udata)
{
    if (is_logging_done) {
        return;
    }
    //fprintf(stderr, "vcpu haddr\n");

    uint32_t mem_size = 1 << qemu_plugin_mem_size_shift(meminfo);
    int i;

    for (int i = 0; i < mem_size; i++) {
        if (is_target_logging) {         
            AddrInfo *tmp_info = (AddrInfo *) g_hash_table_lookup(target_hash, (gconstpointer) vaddr+i);
            if (!tmp_info) {
                AddrInfo *new_addr = (AddrInfo *)malloc(sizeof(AddrInfo));
                new_addr->addr = vaddr+i;
                g_hash_table_insert(target_hash, (gpointer)new_addr->addr, (gpointer)new_addr);
            }
            //target_list = g_slist_prepend(target_list, new_addr);
        } else if (is_before_logging) {   
            AddrInfo *tmp_info = (AddrInfo *) g_hash_table_lookup(before_hash, (gconstpointer) vaddr+i);
            if (!tmp_info) {
                AddrInfo *new_addr = (AddrInfo *)malloc(sizeof(AddrInfo));
                new_addr->addr = vaddr+i;
                g_hash_table_insert(before_hash, (gpointer)new_addr->addr, (gpointer)new_addr);
            }
            //before_list = g_slist_prepend(before_list, new_addr);
        }
    }
}

static void vcpu_tb_exec_before(unsigned int vcpu_index, void *userdata) 
{
    ExecInfo *info;
    uint64_t hash = (uint64_t) userdata;
    uint64_t pc;
    uint64_t sp;

    if (is_logging_done) {
        return;
    }

    if (!base_code_addr && is_pie) {
        return;
    } 

    g_mutex_lock(&exec_lock);
    info = (ExecInfo *) g_hash_table_lookup(exec_block, (gconstpointer) hash);
    // should always succeed
    g_assert(info);
    
    pc = info->start_addr;
    sp = get_cpu_register_rsp(vcpu_index);
    if (pc == main_addr) {
        // start before logging
        fprintf(stderr, "reach main, start before logging\n");
        is_before_logging = 1;
    } else if (pc == persistent_addr && !is_target_logging && is_before_logging) {        
        // initially reaches persistent addr (target function)        
        fprintf(stderr, "reach persistent addr, start target logging & stop before logging\n");
        ret_addr = *(uint64_t *)(sp);
        caller_sp = sp + 8;    
        // start target logging
        is_target_logging = 1;
        // disable before logging
        is_before_logging = 0;
    } else if (pc == ret_addr && sp == caller_sp && is_target_logging) {
        // end target logging
        fprintf(stderr, "end of logging\n");
        is_target_logging = 0;
        is_logging_done = 1;
        get_intersect_list();
    }

    g_mutex_unlock(&exec_lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    if (is_logging_done) {
        return;
    }
    
    ExecInfo *info;
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t n = qemu_plugin_tb_n_insns(tb);
    uint64_t hash = pc ^ n;
    size_t i;

    g_mutex_lock(&exec_lock);
    info = (ExecInfo *)g_hash_table_lookup(exec_block, (gconstpointer) hash);
    if (!info) {
        info = g_new0(ExecInfo, 1);
        info->start_addr = pc;
        info->insns = n;
        g_hash_table_insert(exec_block, (gpointer) hash, (gpointer) info);
    }
    g_mutex_unlock(&exec_lock);

    // instrument memory logging routine for every instruction
    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_haddr,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, NULL);
    }

    // instrument logging manager routine for every tb
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec_before, QEMU_PLUGIN_CB_R_REGS, (void *)hash);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv) 
{
    FILE *map_fp;
    char map_buf[4096];

    if (argc != 2) {
        fprintf(stderr, "ERROR Wrong Format : QEMU_PLUGIN=\"PLUGIN_PATH,arg=TARGET_ADDR,arg=MAIN_ADDR\"\n");
        return -1;
    }

    // get target, main offset
    persistent_addr = (uint64_t)strtol(argv[0], NULL, 16);    
    main_addr = (uint64_t)strtol(argv[1], NULL, 16);    
    base_code_addr = 0;
    is_pie = 1;
    fprintf(stderr, "main offset : %p\n", (void *)main_addr);
    fprintf(stderr, "persistent offset : %p\n", (void *)persistent_addr);
    
    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
