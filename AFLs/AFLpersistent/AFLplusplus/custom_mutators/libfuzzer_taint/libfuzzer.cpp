#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
//#include "config.h"
//#include "debug.h"
#include "afl-fuzz.h"

#ifdef  INTROSPECTION
  const char *introspection_ptr;
#endif

afl_state_t *afl_struct;

size_t input_size;
int *taint_index;

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
extern "C" int    LLVMFuzzerRunDriver(int *argc, char ***argv,
                                      int (*UserCb)(const uint8_t *Data,
                                                 size_t         Size));
extern "C" void   LLVMFuzzerMyInit(int (*UserCb)(const uint8_t *Data,
                                               size_t         Size),
                                   unsigned int Seed);

typedef struct my_mutator {

  afl_state_t *afl;
  u8 *         mutator_buf;
  u8 *         trim_buf;
  unsigned int seed;
  unsigned int extras_cnt, a_extras_cnt;

  size_t       trim_size_current;

} my_mutator_t;

extern "C" int dummy(const uint8_t *Data, size_t Size) {

  (void)(Data);
  (void)(Size);
  fprintf(stderr, "dummy() called\n");
  return 0;

}

extern "C" my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  fprintf(stderr, "afl custom init\n");
  my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->mutator_buf = (u8 *)malloc(MAX_FILE)) == NULL) {

    free(data);
    perror("mutator_buf alloc");
    return NULL;

  }

  if ((data->trim_buf = (u8 *)malloc(MAX_FILE)) == NULL) {

    free(data);
    perror("mutator_buf alloc");
    return NULL;

  }

  // read taint tag
  char tmp_buf[128];
  size_t tag_val_size = 0;
  FILE *fp = fopen("./tag_value", "r");
  if (fp == NULL) {
    fprintf(stderr, "failed to open tag val\n");
    return NULL;
  }
  while (fgets(tmp_buf, 128, fp)) {
    tag_val_size++;
  }
  fprintf(stderr, "input size : %ld\n", tag_val_size);
  input_size = tag_val_size;
  fclose(fp);

  fp = fopen("taint_tag", "r");
  if (fp == NULL) {
    fprintf(stderr, "failed to open taint tag\n");
    free(data);
    return NULL;
  }
  if ((taint_index = (int *)malloc(sizeof(int) * input_size)) == NULL) {
    free(data);
    perror("taint index alloc");
    return NULL;
  }

  for (int i = 0; i < input_size; i++) {
    taint_index[i] = 0;
  }

  int buf_size = sizeof(char) * 10 * input_size;
  char *read_buf = (char *)malloc(buf_size);
  while (fgets(read_buf, buf_size, fp)) {
		char *ptr;
		int tmp_tag;

		ptr = strtok(read_buf, " ");
		while(ptr != NULL) {			
			tmp_tag = strtol(ptr, NULL, 10);
			tmp_tag = (tmp_tag-1) / 2;
      taint_index[tmp_tag] = 1;
			ptr = strtok(NULL, " ");
		}
  }
  fclose(fp);
  free(read_buf);
  
  // fprintf(stderr, "taint index : ");
  // for (int i = 0; i < input_size; i++) {
  //   if (taint_index[i]) {
  //     fprintf(stderr, "%d ", i*2+1);
  //   }
  // }
  // fprintf(stderr, "\n");

  data->afl = afl;
  data->seed = seed;
  afl_struct = afl;

  /*
    char **argv;
    argv = (char**)malloc(sizeof(size_t) * 2);
    argv[0] = (char*)"foo";
    argv[1] = NULL;
    int eins = 1;
    LLVMFuzzerRunDriver(&eins, &argv, dummy);
  */

  LLVMFuzzerMyInit(dummy, seed);

  return data;

}

/* When a new queue entry is added we check if there are new dictionary
   entries to add to honggfuzz structure */
#if 0
extern "C" uint8_t afl_custom_queue_new_entry(my_mutator_t * data,
                                              const uint8_t *filename_new_queue,
                                              const uint8_t *filename_orig_queue) {

  while (data->extras_cnt < afl_struct->extras_cnt) {

    /*
        memcpy(run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].val,
               afl_struct->extras[data->extras_cnt].data,
               afl_struct->extras[data->extras_cnt].len);
        run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].len =
            afl_struct->extras[data->extras_cnt].len;
        run.global->mutate.dictionaryCnt++;
    */
    data->extras_cnt++;

  }

  while (data->a_extras_cnt < afl_struct->a_extras_cnt) {

    /*
        memcpy(run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].val,
               afl_struct->a_extras[data->a_extras_cnt].data,
               afl_struct->a_extras[data->a_extras_cnt].len);
        run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].len =
            afl_struct->a_extras[data->a_extras_cnt].len;
        run.global->mutate.dictionaryCnt++;
        data->a_extras_cnt++;
    */

  }

  return 0;

}

#endif
/* we could set only_printable if is_ascii is set ... let's see
uint8_t afl_custom_queue_get(void *data, const uint8_t *filename) {

  //run.global->cfg.only_printable = ...

}

*/

/* here we run the honggfuzz mutator, which is really good */

extern "C" size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf,
                                  size_t buf_size, u8 **out_buf,
                                  uint8_t *add_buf, size_t add_buf_size,
                                  size_t max_size) {

  memcpy(data->mutator_buf, buf, buf_size);
  size_t ret = LLVMFuzzerMutate(data->mutator_buf, buf_size, max_size);

  /* return size of mutated data */
  *out_buf = data->mutator_buf;
  return ret;

}

#ifdef  INTROSPECTION
extern "C" const char* afl_custom_introspection(my_mutator_t *data) {

  return introspection_ptr;

}
#endif

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
extern "C" void afl_custom_deinit(my_mutator_t *data) {

  free(data->mutator_buf);
  free(data);

}

extern "C" int32_t afl_custom_init_trim(my_mutator_t *data, uint8_t *buf,
                             size_t buf_size) {
  memcpy(data->trim_buf, buf, buf_size);
  data->trim_size_current = buf_size;
  return 0;
}

// /**
//  * This method is called for each trimming operation. It doesn't have any
//  * arguments because we already have the initial buffer from init_trim and we
//  * can memorize the current state in *data. This can also save
//  * reparsing steps for each iteration. It should return the trimmed input
//  * buffer, where the returned data must not exceed the initial input data in
//  * length. Returning anything that is larger than the original data (passed
//  * to init_trim) will result in a fatal abort of AFLFuzz.
//  *
//  * (Optional)
//  *
//  * @param[in] data pointer returned in afl_custom_init for this fuzz case
//  * @param[out] out_buf Pointer to the buffer containing the trimmed test case.
//  *     External library should allocate memory for out_buf.
//  *     AFL++ will not release the memory after saving the test case.
//  *     Keep a ref in *data.
//  *     *out_buf = NULL is treated as error.
//  * @return Pointer to the size of the trimmed test case
// // //  */
extern "C" size_t afl_custom_trim(my_mutator_t *data, uint8_t **out_buf) {
  return data->trim_size_current;
}

// /**
//  * This method is called after each trim operation to inform you if your
//  * trimming step was successful or not (in terms of coverage). If you receive
//  * a failure here, you should reset your input to the last known good state.
//  *
//  * (Optional)
//  *
//  * @param[in] data pointer returned in afl_custom_init for this fuzz case
//  * @param success Indicates if the last trim operation was successful.
//  * @return The next trim iteration index (from 0 to the maximum amount of
//  *     steps returned in init_trim). negative ret on failure.
//  */
extern "C" int32_t afl_custom_post_trim(my_mutator_t *data, int success) {
  return 0;
}

/**
 * Determine whether the fuzzer should fuzz the queue entry or not.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param filename File name of the test case in the queue entry
 * @return Return True(1) if the fuzzer will fuzz the queue entry, and
 *     False(0) otherwise.
 */
extern "C" uint8_t afl_custom_queue_get(my_mutator_t *data, const uint8_t *filename) {

  return 1;

}

/**
 * Allow for additional analysis (e.g. calling a different tool that does a
 * different kind of coverage and saves this for the custom mutator).
 *
 * (Optional)
 *
 * @param data pointer returned in afl_custom_init for this fuzz case
 * @param filename_new_queue File name of the new queue entry
 * @param filename_orig_queue File name of the original queue entry
 * @return if the file contents was modified return 1 (True), 0 (False)
 *         otherwise
 */
extern "C" uint8_t afl_custom_queue_new_entry(my_mutator_t  *data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {

  /* Additional analysis on the original or new test case */
  return 0;

}