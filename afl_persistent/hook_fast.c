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
#include <time.h>
#include <errno.h>

#include "/root/ATFF/AFLs/AFLpersistent/AFLplusplus/qemu_mode/qemuafl/qemuafl/api.h"

// guest memory pages
struct guest_region {
  uint64_t begin;
  uint64_t end;
};

struct guest_region guest_snapshot[1000];
size_t guest_snapshot_len;

typedef struct {
    uint64_t addr;
} AddrInfo;

GArray *tag_val;
int tag_val_len;

GArray *taint_tag_list;
GArray *taint_region_list;

int is_tag_list_matched[1000];
int is_region_found;
int input_size;

void match_tag(struct guest_region *snapshot_p, uint64_t base_addr, int tag_list_index) {
	uint64_t prev_addr, cur_addr;
	uint64_t i = 0;
	GArray *taint_iter = g_array_index(taint_tag_list, GArray *, tag_list_index);

	prev_addr = 0;
	// fprintf(stderr, "start matching... idx : %d, addr : %p\n", tag_list_index, (void *)base_addr);

	for (uint64_t target_addr = base_addr; target_addr < snapshot_p->end; target_addr++) {
		int taint_tag;
		char cur_val, taint_val;

		if (i == taint_iter->len) {
			break;
		}

		cur_addr = target_addr;
		
		if (cur_addr != prev_addr+1 && prev_addr) {
			fprintf(stderr, "addr mismatch\n");
			return;	
		}
		
		cur_val = *((char *)cur_addr);
		taint_tag = g_array_index(taint_iter, int, i);
		taint_val = g_array_index(tag_val, char, taint_tag);

		if (cur_val != taint_val) {
			// fprintf(stderr, "val mismatch, cur : %x, taint : %x\n", cur_val&0xff, taint_val&0xff);
			// fprintf(stderr, "i : %ld\n", i);
			return;
		}
 
		prev_addr = cur_addr;
		i++;
	}

	if (i != taint_iter->len) {
		return;
	}

	is_tag_list_matched[tag_list_index] = 1;

	fprintf(stderr, "matched! : %p\n", (void *)base_addr);
	fprintf(stderr, "tag index : %d, size : %d\n", tag_list_index, taint_iter->len);
	cur_addr = base_addr;
	for (i = 0; i < taint_iter->len; i++) {
		int taint_tag = g_array_index(taint_iter, int, i);
		GArray *taint_region = g_array_index(taint_region_list, GArray *, taint_tag);

		g_array_append_val(taint_region, cur_addr);

		cur_addr++; 	
	}
}

int find_taint_region_list() {
	// load guest address space
	char addr_buf[4096];
	FILE *fp = fopen("./guest_memory_map", "r");
	if (!fp) {
		fprintf(stderr, "failed to load guest memory map\n");
		abort();
	}

	guest_snapshot_len = 0;
	while (fgets(addr_buf, sizeof(addr_buf), fp)) {
		uint64_t begin, end;

		sscanf(addr_buf, "%lx-%lx\n", &begin, &end);
		
		guest_snapshot[guest_snapshot_len].begin = begin;
		guest_snapshot[guest_snapshot_len].end = end;

		guest_snapshot_len++;
	}
	fclose(fp);

	// load input file region when mmap
	fp = fopen("/proc/self/maps", "r");
	if (!fp) {
		fprintf(stderr, "failed to load guest memory map\n");
		abort();
	}

	while (fgets(addr_buf, sizeof(addr_buf), fp)) {
		uint64_t begin, end, size;

		if (strstr(addr_buf, ".cur_input") != NULL) {
			sscanf(addr_buf, "%lx-%lx\n", &begin, &end);
			size = end - begin;
			guest_snapshot[guest_snapshot_len].begin = begin;
			guest_snapshot[guest_snapshot_len].end = end;
			guest_snapshot_len++;

			char *tmp_region = (char *)malloc(size);
			memcpy ((void *)tmp_region, (void *)begin, size);
			
			if (munmap((void *)begin, size)) {
				fprintf(stderr, "failed to unmap : %d\n", errno);
				abort();
			}

			if (mmap((void *)begin, size, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == (void *)-1) {
				fprintf(stderr, "failed to mmap : %d\n", errno);
				abort();
			}
			memcpy ((void *)begin, (void *)tmp_region, size);
			free (tmp_region);

			break;
		}
	}
	fclose(fp);

	for (int snapshot_idx = 0; snapshot_idx < guest_snapshot_len; snapshot_idx++) {
		uint64_t begin = guest_snapshot[snapshot_idx].begin;
		uint64_t end = guest_snapshot[snapshot_idx].end;
		struct timespec time_start, time_end;
		uint64_t elapsed_time;
		clock_gettime(CLOCK_REALTIME_COARSE, &time_start);

		fprintf(stderr, "scanning %lx-%lx (size : %ld)...", begin, end, end-begin);
		for (uint64_t target_addr = begin; target_addr < end; target_addr++) {
			char target_val = *((char *)target_addr);
			if (target_val == 0) continue;
			for (int i = 0; i < taint_tag_list->len; i++) {
				GArray *taint_iter = g_array_index(taint_tag_list, GArray *, i);
				int taint_tag;
				int taint_val;
				int non_zero_count = 0;

				// ignore short len case
				if (taint_iter->len < 5) {
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

				if (taint_val == target_val) {
					fprintf(stderr, "=============start matching... : %d, %d\n", i, taint_val);
					match_tag(&guest_snapshot[snapshot_idx], target_addr, i);
				}			
			}
		}
		clock_gettime(CLOCK_REALTIME_COARSE, &time_end);
		elapsed_time = (time_end.tv_sec - time_start.tv_sec);
		fprintf(stderr, "done in %lds\n", elapsed_time);
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

void afl_persistent_hook(struct x86_64_regs *regs, uint64_t guest_base, uint8_t *input_buf, uint32_t input_buf_len) {
	fprintf(stderr, "===============hook=================\n");
	if (is_region_found) {
		
		// // for debug
		// for (int i = 0; i < input_buf_len; i++) {

		// 	if ((i*2+1) > tag_val_len) {
		// 		break;
		// 	}
			
		// 	GArray *taint_region = g_array_index(taint_region_list, GArray *, i*2+1);

		// 	for (int j = 0; j < taint_region->len; j++) {
		// 		char *addr2mutate = (char *)g_array_index(taint_region, uint64_t, j);	

		// 		char taint_val = g_array_index(tag_val, char, i*2+1);
		// 		if (taint_val != (*addr2mutate)) {
		// 			FILE *mis_fp = fopen("./mismatch\n", "w");
		// 			fprintf(mis_fp, "value mismatch, %p : %x, %x\n", addr2mutate, (*addr2mutate)&0xff, taint_val&0xff);
		// 			fclose(mis_fp);
		// 			abort();
		// 		}	
		// 	}
		// }
		// //////////////////// must be removed

		for (int i = 0; i < input_buf_len; i++) {
			int flag = 0;

			if ((i*2+1) > tag_val_len) {
				break;
			}
			
			GArray *taint_region = g_array_index(taint_region_list, GArray *, i*2+1);
			for (int j = 0; j < taint_region->len; j++) {
				char *addr2mutate = (char *)g_array_index(taint_region, uint64_t, j);	
				*addr2mutate = input_buf[i];
			}
		}
	} else {
		// // load hook state
		// FILE *fp = fopen("./.hook_state", "r");
		// char hook_state_buffer[4096];
		// if (!fgets(hook_state_buffer, sizeof(hook_state_buffer), fp)) {
		// 	fprintf(stderr, "failed to open hook state\n");
		// 	fclose(fp);
		// 	abort();
		// }
		// fclose(fp);

		// // we can distinguish by hook_state's content
		// if (strcmp(hook_state_buffer, "init") != 0) {
		// 	// find tainted region
		// 	// fprintf(stderr, "tag_val_init\n");
		// 	// if (tag_val_init()) {
		// 	// 	fprintf(stderr, "ERROR : Failed to init tag-value\n");
		// 	// 	abort();
		// 	// }

		// 	// restore hook state
		// 	fprintf(stderr, "restore hook state\n");

		// 	fprintf(stderr, "is_region_found\n");
		// 	is_region_found = 1;

		// 	// restore taint info
		// 	fprintf(stderr, "taint region\n");
		// 	fp = fopen("./.hook_state", "r");
		// 	if (!fp) {
		// 		fprintf(stderr, "failed to open .hook_state\n");
		// 		fclose(fp);
		// 		abort();
		// 	}

		// 	fprintf(stderr, "restore tag-value\n");
		// 	// restore tag-value length first
		// 	char tag_val_len_buf[100];
		// 	fgets(tag_val_len_buf, sizeof(tag_val_len_buf), fp);
		// 	tag_val_len_buf[strlen(tag_val_len_buf)-1] = '\0';
		// 	tag_val_len = strtol(tag_val_len_buf, NULL, 10);

		// 	fprintf(stderr, "create new taint_region list\n");
		// 	// create a new taint_region list
		// 	taint_region_list = g_array_new(FALSE, FALSE, sizeof(GArray *));
		// 	for (int i = 0; i < tag_val_len; i++) {
		// 		GArray *taint_region = g_array_new(FALSE, FALSE, sizeof(uint64_t));
		// 		g_array_append_val(taint_region_list, taint_region);
		// 	}

		// 	fprintf(stderr, "restore taint_region list\n");
		// 	// restore taint_region_list
		// 	for (int i = 1; i < taint_region_list->len; i+=2) {
		// 		GArray *taint_region = g_array_index(taint_region_list, GArray *, i);
		// 		char addr_buf[4096];
		// 		char *ptr;
		// 		uint64_t addr;

		// 		fgets(addr_buf, sizeof(addr_buf), fp);
		// 		if (addr_buf[0] == '\n') {
		// 			fprintf(stderr, "%d continue\n", i);
		// 			continue;
		// 		}
		// 		ptr = strtok(addr_buf, " ");
		// 		if (!ptr) {
		// 			fprintf(stderr, "space %d continue\n", i);
		// 			continue;
		// 		}
		// 		addr = (strtol(ptr, NULL, 10));
		// 		g_array_append_val(taint_region, addr);
		// 		while ((ptr = strtok(NULL, " "))) {
		// 			addr = (strtol(ptr, NULL, 10));
		// 			g_array_append_val(taint_region, addr);
		// 		}
		// 		fprintf(stderr, "restore %d\n", i);
		// 		for (int k = 0; k < 5; k++) {
		// 			fprintf(stderr, "%x ", addr_buf[k]&0xff);
		// 		}
		// 		fprintf(stderr, "\n");
		// 	}
		// 	fprintf(stderr, "end of restore\n");
		// 	fclose(fp);

		// 	return;
		// }

		// find tainted region
		fprintf(stderr, "tag_val_init\n");
		if (tag_val_init()) {
			fprintf(stderr, "ERROR : Failed to init tag-value\n");
			abort();
		}

		fprintf(stderr, "taint_tag_list_init\n");
		if (taint_tag_list_init()) {
			fprintf(stderr, "ERROR : Failed to init taint_tag_list\n");
			abort();
		}

		fprintf(stderr, "find tainted region!\n");
		fprintf(stderr, "input size : %d\n", tag_val->len/2);
		fprintf(stderr, "tag list size : %d\n", taint_tag_list->len);
		taint_region_list = g_array_new(FALSE, FALSE, sizeof(GArray *));
		for (int i = 0; i < tag_val->len; i++) {
			GArray *taint_region = g_array_new(FALSE, FALSE, sizeof(uint64_t));
			g_array_append_val(taint_region_list, taint_region);
		}

		find_taint_region_list();

		// check tainted region
		for (int i = 1; i < taint_region_list->len; i+=2) {
			GArray *taint_region = g_array_index(taint_region_list, GArray *, i);
			//fprintf(stderr, "[%d] : ", i);
			for (int j = 0; j < taint_region->len; j++) {
				is_region_found = 1;
				break;
			}
			//fprintf(stderr, "\n");
		} 

		if (!is_region_found) {
			fprintf(stderr, "failed to find region!!\n");
			abort();
		}

		// // save hook state
		// fprintf(stderr, "save hook state\n");
		// fp = fopen("./.hook_state", "w+");
		// fprintf(fp, "%d\n", tag_val_len);

		// for (int i = 1; i < taint_region_list->len; i+=2) {
		// 	GArray *taint_region = g_array_index(taint_region_list, GArray *, i);
		// 	for (int j = 0; j < taint_region->len; j++) {
		// 		uint64_t addr2mutate = g_array_index(taint_region, uint64_t, j);
				
		// 		if (j == (taint_region->len-1)) {
		// 			fprintf(fp, "%ld", addr2mutate);
		// 		} else {
		// 			fprintf(fp, "%ld ", addr2mutate);
		// 		}
		// 	}
		// 	fprintf(fp, "\n");
		// }
		// fclose(fp);
		char *env_str;
		if ((env_str = getenv("OVERHEAD_TEST"))) {
			FILE *fo = fopen("./memory_scanning_overhead", "w");
			fprintf(fo, "done\n");
			fclose(fo);
			abort();
		}

		fprintf(stderr, "finding tainted region done\n");
	}

	fprintf(stderr, "===============end hook=================\n");
}

int afl_persistent_hook_init(void) {
	// create initial hook state file
	FILE *fp = fopen("./.hook_state", "w+");
	fprintf(fp, "init");
	fclose(fp);

	return 1;
}
