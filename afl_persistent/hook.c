#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <getopt.h>
#include <glib.h>
#include <dlfcn.h>

#include "/root/ATFF/AFLs/AFLpersistent/AFLplusplus/qemu_mode/qemuafl/qemuafl/api.h"

typedef struct MemoryInfo {
	uint64_t addr_begin;
	uint64_t addr_end;
	int r, w, x;
	struct MemoryInfo *next;
	struct MemoryInfo *prev;
} MemoryInfo;

MemoryInfo *headInfo;
MemoryInfo *tailInfo;

typedef struct {
    uint64_t addr;
} AddrInfo;

GSList **intersect_list_p; 
GSList *intersect_list;

GArray *tag_val;
int tag_val_len;

GArray *taint_tag_list;
GArray *taint_region_list;

int is_tag_list_matched[10000];
int is_region_found;
int input_size;

// persistent mode shared library is reloaded on every afl-qemu crash
// but persistent_init only called in afl-init stage
// so to distinguish afl-init & afl-qemu crash, first_load is needed

int is_addr_writable(uint64_t addr) {
	MemoryInfo *iter_node = headInfo;
	while (iter_node != NULL) {
		uint64_t addr_begin = iter_node->addr_begin;
		uint64_t addr_end = iter_node->addr_end;
		if (addr >= addr_begin && addr < addr_end) {
			return iter_node->w;
		}
		iter_node = iter_node->next;
	}	
	return 0;
}

void match_tag(GSList *intersect_iter_match, int tag_list_index) {
	uint64_t prev_addr, cur_addr, base_addr;
	int i = 0;
	GArray *taint_iter = g_array_index(taint_tag_list, GArray *, tag_list_index);

	prev_addr = 0;
	base_addr = ((AddrInfo *)intersect_iter_match->data)->addr; 
	// fprintf(stderr, "start matching... idx : %d, addr : %p\n", tag_list_index, (void *)base_addr);

	for (; intersect_iter_match; intersect_iter_match = intersect_iter_match->next) {
		int taint_tag;
		char cur_val, taint_val;

		if (i == taint_iter->len) {
			break;
		}

		cur_addr = ((AddrInfo *)intersect_iter_match->data)->addr; 
		
		if (cur_addr != prev_addr+1 && prev_addr) {
			// fprintf(stderr, "addr mismatch, %d\n", i);
			return;	
		}
		
		cur_val = *((char *)cur_addr);
		taint_tag = g_array_index(taint_iter, int, i);
		taint_val = g_array_index(tag_val, char, taint_tag);

		if (cur_val != taint_val) {
			// fprintf(stderr, "val mismatch, cur : %x, taint : %x, %d\n", cur_val&0xff, taint_val&0xff, i);
			return;
		}

		if (i == 7) {
			// fprintf(stderr, "currently matched!! -> tag idx : %d\n", tag_list_index);
		}

		prev_addr = cur_addr;
		i++;
	}

	if (i != taint_iter->len) {
		return;
	}

	// fprintf(stderr, "matched! : %p\n", (void *)base_addr);
	// fprintf(stderr, "tag index : %d, size : %d\n", tag_list_index, taint_iter->len);
	is_tag_list_matched[tag_list_index] = 1;

	cur_addr = base_addr;
	for (i = 0; i < taint_iter->len; i++) {
		int taint_tag = g_array_index(taint_iter, int, i);
		GArray *taint_region = g_array_index(taint_region_list, GArray *, taint_tag);

		g_array_append_val(taint_region, cur_addr);

		cur_addr++; 	
	}
}

int find_taint_region_list() {
	char *env_str;
	int overhead_test = 0;
	GSList *intersect_iter;

	fprintf(stderr, "find taint region list\n");
	if ((env_str = getenv("OVERHEAD_TEST"))) {
		fprintf(stderr, "overhead test\n");
		overhead_test = 1;
	}

    for (intersect_iter = *intersect_list_p; intersect_iter; intersect_iter = intersect_iter->next) {
        uint64_t intersect_addr = ((AddrInfo *)intersect_iter->data)->addr;
		char intersect_val = *((char *)intersect_addr);

		// if (!is_addr_writable(intersect_addr)) {
		// 	continue;
		// }

		for (int i = 0; i < taint_tag_list->len; i++) {
			GArray *taint_iter = g_array_index(taint_tag_list, GArray *, i);
			int taint_tag;
			int taint_val;
			int non_zero_count = 0;

			// ignore 1byte case
			if (taint_iter->len < 10) {
				//fprintf(stderr, "ignore 1 byte case\n");
				continue;
			}

			// ignore 0 byte sequence
			for (int j = 0; j < taint_iter->len; j++) {
				int tmp_tag = g_array_index(taint_iter, int , j);
				char taint_val = g_array_index(tag_val, char, tmp_tag);
				if (tag_val != 0) {
					non_zero_count++;
				}
			}
			if (non_zero_count < 5) {
				//fprintf(stderr, "ignore 0 byte sequence\n");
				continue;
			}

			taint_tag = g_array_index(taint_iter, int , 0);
			taint_val = g_array_index(tag_val, char, taint_tag);

			if (taint_val == intersect_val) {
				// fprintf(stderr, "=============start matching... : %d\n", i);
				// fprintf(stderr, "base : %p, val : %x, taint_val : %x\n", (void *)intersect_addr, intersect_val, taint_val);
				match_tag(intersect_iter, i);
			}			
		}
	}
	for (int i = 0; i < taint_tag_list->len; i++) {
		if (!is_tag_list_matched[i]) {
			GArray *taint_iter = g_array_index(taint_tag_list, GArray *, i);
			int taint_tag = g_array_index(taint_iter, int, 0);
			fprintf(stderr, "failed to find tag_list[%d], size : %d, starts from %d\n", i, taint_iter->len, taint_tag);
		} else {
			GArray *taint_iter = g_array_index(taint_tag_list, GArray *, i);
			int taint_tag = g_array_index(taint_iter, int, 0);
			fprintf(stderr, "succeed to find tag_list[%d], size : %d, starts from %d\n", i, taint_iter->len, taint_tag);
		}
	}

	if (overhead_test) {
		abort();
	}

	return 0;
}

static int tag_val_init() {
	FILE *pFile = NULL;
	char read_buf[1024];
	size_t count = 0;
	int ch;
	pFile = fopen("./tag_value", "r");

	if (pFile == NULL) {
		fprintf(stderr, "ERROR : tag_value file not exists\n");
		fclose(pFile);
		return -1;
	} 
	
	do {
		ch = fgetc(pFile);
		if (ch == '\n') count++;
	} while (ch != EOF);
	fseek(pFile, 0, SEEK_SET);
	
	input_size = count;
	tag_val = g_array_new(FALSE, FALSE, sizeof(char));
	while (fgets(read_buf, sizeof(read_buf), pFile)) {
		char *ptr;
		char val = 0;

		g_array_append_val(tag_val, val);

		strtok(read_buf, ",");	
		ptr = strtok(NULL, ",");
		val = (char)(strtol(ptr, NULL, 16));
		g_array_append_val(tag_val, val);
	}
	tag_val_len = tag_val->len;

	fclose(pFile);

	return 0;
}

static int taint_tag_list_init() {
	FILE *pFile = NULL;
	char *read_buf;
	size_t buf_size;

	pFile = fopen("./taint_tag", "r");
	if (pFile == NULL) {
		fprintf(stderr, "ERROR : taint_tag file not exists\n");
		fclose(pFile);
		return -1;
	} 
	
	taint_tag_list = g_array_new(FALSE, FALSE, sizeof(GArray *));
	buf_size = sizeof(char) * (tag_val->len) * (10);
	read_buf = (char *)malloc(buf_size);
	while (fgets(read_buf, buf_size, pFile)) {
		GArray *tmp_taint_tag = g_array_new(FALSE, FALSE, sizeof(int));
		char *ptr;
		int tmp_tag;

		ptr = strtok(read_buf, " ");
		while(ptr != NULL) {			
			tmp_tag = strtol(ptr, NULL, 10);
			g_array_append_val(tmp_taint_tag, tmp_tag);
			ptr = strtok(NULL, " ");
		}
		if (!tmp_taint_tag->len) {
			fprintf(stderr, "ERROR : no tag\n");
			free(read_buf);
			return -1;
		}

		g_array_append_val(taint_tag_list, tmp_taint_tag);
	}

	free(read_buf);
	fclose(pFile);

	return 0;
}

static int plugin_init() {
	// Load tcg-plugin library
    void *tcg_lib = dlopen(getenv("TCG_PLUGIN_PATH"), RTLD_NOW);
    if (!tcg_lib) {
      fprintf(stderr, "ERROR Invalid PLUGIN_PATH=%s\n", getenv("TCG_PLUGIN_PATH"));
      return -1;
    }

	uint64_t *base_code_addr = dlsym(tcg_lib, "base_code_addr");
	if (!base_code_addr) {
		fprintf(stderr, "Failed to load base_code_addr: %s\n", dlerror());
		return -1;
	}

	uint64_t *persistent_offset = dlsym(tcg_lib, "persistent_addr");
	if (!persistent_offset) {
		fprintf(stderr, "Failed to load persistent_addr: %s\n", dlerror());
		return -1;
	}

	uint64_t *main_offset = dlsym(tcg_lib, "main_addr");
	if (!main_offset) {
		fprintf(stderr, "Failed to load main_addr: %s\n", dlerror());
		return -1;
	}

	uint64_t *ret_offset = dlsym(tcg_lib, "ret_addr");
	if (!ret_offset) {
		fprintf(stderr, "Failed to load ret_addr: %s\n", dlerror());
		return -1;
	}

	intersect_list_p = dlsym(tcg_lib, "intersect_list");
	if (!intersect_list_p) {
		fprintf(stderr, "Failed to load intersect_list_p: %s\n", dlerror());
		return -1;
	}

	int *is_pie = dlsym(tcg_lib, "is_pie");
	if (!is_pie) {
		fprintf(stderr, "Failed to load is_pie: %s\n", dlerror());
		return -1;
	}

	// get base address
	char *target_binary_path;
	if (!(target_binary_path = getenv("TARGET_BINARY_PATH"))) {
        fprintf(stderr, "ERROR Please set target binary path\n");
        return -1;
    }

	// setup memory info
	FILE *map_fp = fopen("/proc/self/maps", "r");
	char map_buf[4096];
    if (!map_fp) {
        fprintf(stderr, "ERROR Failed to open /proc/self/maps\n");
        return -1;
    }
    while (fgets(map_buf, sizeof(map_buf), map_fp)) {
		uint64_t addr_begin, addr_end;
		int r, w, x;
		char tmp_buf[4096];
		char *ptr;
		MemoryInfo *new_node = (MemoryInfo *)malloc(sizeof(MemoryInfo));

		r = w = x = 0;
		strcpy(tmp_buf, map_buf);

		ptr = strtok(tmp_buf, "-");
		addr_begin = strtol(ptr, NULL, 16);

		ptr = strtok(NULL, " ");
		addr_end = strtol(ptr, NULL, 16);

		ptr = strtok(NULL, " ");
		if (ptr[0] == 'r') r = 1;
		if (ptr[1] == 'w') w = 1;
		if (ptr[2] == 'x') x = 1;	

		new_node->addr_begin = addr_begin;
		new_node->addr_end = addr_end;
		new_node->r = r;
		new_node->w = w;
		new_node->x = x;
		new_node->next = NULL;
		new_node->prev = NULL;
		if (headInfo == NULL) {
			headInfo = new_node;
			tailInfo = new_node;
		} else {
			tailInfo->next = new_node;
			new_node->prev = tailInfo;
			tailInfo = new_node;
		}
		if (strstr(map_buf, target_binary_path)) {
			// char *ptr;
			// uint64_t tmp_addr;

			// ptr = strtok(map_buf, "-");
			// tmp_addr = strtol(ptr, NULL, 16);
			*base_code_addr = addr_begin;
        }
    }    

	if (!(*base_code_addr)) {
		fprintf(stderr, "Failed to find base address\n");
		return -1;
	} else {
		fprintf(stderr, "Base address : %p\n", (void *)(*base_code_addr));
	}
	
	// for non-PIE executable
	// PIE executable's text is located on the heap area(0x7fff...) by QASAN
	// So we can distinguish them by text section address
	if ((*base_code_addr) < 0x7fff8000ULL) {
		fprintf(stderr, "non-PIE executable detected!\n");
		*base_code_addr = 0;
		*is_pie = 0;
	}

	// set tcg-plugin's main & persistent addr & ret addr
	char env_persistent_addr[1024]; 	
	char env_ret_addr[1024];
	
	*persistent_offset = (*base_code_addr) + (*persistent_offset);	
	*main_offset = (*base_code_addr) + (*main_offset);	
	*ret_offset = (*base_code_addr) + (*ret_offset);

	// set AFL_QEMU_PERSISTENT_ADDR & AFL_QEMU_PERSISTENT_RET
	// AFL calls afl_persistent_hook_init first 
	// and then set persistent_addr from AFL_QEMU_PERSISTENT_ADDR
	sprintf(env_persistent_addr, "AFL_QEMU_PERSISTENT_ADDR=0x%lx", *persistent_offset);
	putenv(env_persistent_addr);

	sprintf(env_ret_addr, "AFL_QEMU_PERSISTENT_RET=0x%lx", *ret_offset);
	putenv(env_ret_addr);

	return 0;
}

void afl_persistent_hook(struct x86_64_regs *regs, uint64_t guest_base, uint8_t *input_buf, uint32_t input_buf_len) {
	// fprintf(stderr, "===============hook=================\n");

	// check whether first run or not
	if (!is_region_found) {
		FILE *fp = fopen("./.hook_state", "r");
		char hook_state_buffer[4096];
		if (!fgets(hook_state_buffer, sizeof(hook_state_buffer), fp)) {
			fprintf(stderr, "failed to open hook state\n");
			fclose(fp);
			abort();
		}
		fclose(fp);

		// we can distinguish by hook_state's content
		if (strcmp(hook_state_buffer, "init") != 0) {
			// restore hook state
			fprintf(stderr, "restore hook state\n");

			fprintf(stderr, "is_region_found\n");
			is_region_found = 1;

			// we don't need intersect_list_p anymore. so just assign dummy value
			fprintf(stderr, "intersect_list_p\n");
			intersect_list_p = (struct _GSList **)malloc(sizeof(struct _GSList *));
			*intersect_list_p = (struct _GSList *)0x1000;

			// restore taint info
			fprintf(stderr, "taint region\n");
			FILE *fp = fopen("./.hook_state", "r");
			if (!fp) {
				fprintf(stderr, "failed to open .hook_state\n");
				fclose(fp);
				abort();
			}

			fprintf(stderr, "restore tag-value\n");
			// restore tag-value length first
			fscanf(fp, "%d\n", &tag_val_len);

			fprintf(stderr, "create new taint_region list\n");
			// create a new taint_region list
			taint_region_list = g_array_new(FALSE, FALSE, sizeof(GArray *));
			for (int i = 0; i < tag_val_len; i++) {
				GArray *taint_region = g_array_new(FALSE, FALSE, sizeof(uint64_t));
				g_array_append_val(taint_region_list, taint_region);
			}

			fprintf(stderr, "restore taint_region list\n");
			// restore taint_region_list
			for (int i = 1; i < taint_region_list->len; i+=2) {
				GArray *taint_region = g_array_index(taint_region_list, GArray *, i);
				char addr_buf[4096];
				char *ptr;
				uint64_t addr;

				fgets(addr_buf, sizeof(addr_buf), fp);
				if (addr_buf[0] == '\n') continue;

				ptr = strtok(addr_buf, " ");
				if (!ptr) continue;

				addr = (strtol(ptr, NULL, 10));
				g_array_append_val(taint_region, addr);
				while ((ptr = strtok(NULL, " "))) {
					addr = (strtol(ptr, NULL, 10));
					g_array_append_val(taint_region, addr);
				}
			}
			fprintf(stderr, "end of restore\n");
			fclose(fp);

			// // testing whether hook state saving is done well
			// fprintf(stderr, "test hook state\n");
			// FILE *fp_test = fopen("./.hook_state_test", "w+");
			// fprintf(fp_test, "%d\n", tag_val_len);

			// for (int i = 1; i < taint_region_list->len; i+=2) {
			// 	GArray *taint_region = g_array_index(taint_region_list, GArray *, i);
			// 	for (int j = 0; j < taint_region->len; j++) {
			// 		uint64_t addr2mutate = g_array_index(taint_region, uint64_t, j);
					
			// 		if (j == (taint_region->len-1)) {
			// 			fprintf(fp_test, "%ld", addr2mutate);
			// 		} else {	
			// 			fprintf(fp_test, "%ld ", addr2mutate);
			// 		}
			// 	}
			// 	fprintf(fp_test, "\n");
			// }
			// fclose(fp_test);		
		}
	}

	if (!(*intersect_list_p)) {
		fprintf(stderr, "now logging...\n");
		return;
	}

	if (is_region_found) {
		// mutate
		// fprintf(stderr, "mutate : %d\n", getpid());
		uint64_t count = 0;
		for (int i = 0; i < input_buf_len; i++) {
		// for (int i = 0; i < 1000000; i++) {
			if ((i*2+1) > tag_val_len) {
				break;
			}
			
			GArray *taint_region = g_array_index(taint_region_list, GArray *, i*2+1);
			for (int j = 0; j < taint_region->len; j++) {
				char *addr2mutate = (char *)g_array_index(taint_region, uint64_t, j);
			
				// if (!is_addr_writable((uint64_t)addr2mutate)) {
				// 	fprintf(stderr, "not writable in mutation\n");
				// 	continue;
				// }

				*addr2mutate = input_buf[i];
				count++;
			}
		}
		// fprintf(stderr, "end of mutate : %ld\n", count);
	} else {
		// find tainted region
		fprintf(stderr, "find tainted region!\n");
		fprintf(stderr, "input size : %d\n", tag_val->len/2);
		fprintf(stderr, "tag list size : %d\n", taint_tag_list->len);
		taint_region_list = g_array_new(FALSE, FALSE, sizeof(GArray *));
		for (int i = 0; i < tag_val->len; i++) {
			GArray *taint_region = g_array_new(FALSE, FALSE, sizeof(uint64_t));
			g_array_append_val(taint_region_list, taint_region);
		}

		find_taint_region_list();

		// test taint_region is writable
		for (int i = 1; i < taint_region_list->len; i+=2) {
			GArray *taint_region = g_array_index(taint_region_list, GArray *, i);
			//fprintf(stderr, "[%d] : ", i);
			for (int j = 0; j < taint_region->len; j++) {
				char *addr2mutate = (char *)g_array_index(taint_region, uint64_t, j);
				char *page_addr = (char *)(((uint64_t)addr2mutate) & ~(0xfff));

				mprotect(page_addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

				char before_mutate = *addr2mutate;
				*addr2mutate = 'a';				
				*addr2mutate = before_mutate;

				is_region_found = 1;
			}
			//fprintf(stderr, "\n");
		} 

		if (!is_region_found) {
			fprintf(stderr, "failed to find region!!\n");
			abort();
		}

		// save hook state
		fprintf(stderr, "save hook state\n");
		FILE *fp = fopen("./.hook_state", "w+");
		fprintf(fp, "%d\n", tag_val_len);

		for (int i = 1; i < taint_region_list->len; i+=2) {
			GArray *taint_region = g_array_index(taint_region_list, GArray *, i);
			for (int j = 0; j < taint_region->len; j++) {
				uint64_t addr2mutate = g_array_index(taint_region, uint64_t, j);
				
				if (j == (taint_region->len-1)) {
					fprintf(fp, "%ld", addr2mutate);
				} else {
					fprintf(fp, "%ld ", addr2mutate);
				}
			}
			fprintf(fp, "\n");
		}
		fclose(fp);

		fprintf(stderr, "finding tainted region done\n");
	}

	//fprintf(stderr, "===============end hook=================\n");
	
	return;
}

int afl_persistent_hook_init(void) {
	fprintf(stderr, "============hook init===============\n");

	FILE *fp = fopen("./.region_state", "r+");
    char region_buffer[4096];
	if (fgets(region_buffer, sizeof(region_buffer), fp)) {
		if (strcmp(region_buffer, "done") == 0) {
			is_region_found = 0;
			return 1;
		}
	}

	fprintf(stderr, "plugin_init\n");
	if (plugin_init()) {
		fprintf(stderr, "ERROR Failed to init tcg-plugin\n");
		return -1;
	}

	fprintf(stderr, "tag_val_init\n");
	if (tag_val_init()) {
		fprintf(stderr, "ERROR : Failed to init tag-value\n");
		return -1;
	}

	fprintf(stderr, "taint_tag_list_init\n");
	if (taint_tag_list_init()) {
		fprintf(stderr, "ERROR : Failed to init taint_tag_list\n");
		return -1;
	}

	// create initial hook state file
	fp = fopen("./.hook_state", "w+");
	fprintf(fp, "init");
	fclose(fp);

	fprintf(stderr, "this is afl-init stage\n");

	fprintf(stderr, "=================End Hook================\n");

	return 1;
}
