#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    char buf[16384];
    char input[1024];
    int fdin, fdout;
    int buf_size, input_size;

    if (argc !=3) {
        printf("wrong format\n");
        return 0;
    }

    fdin = open(argv[1], O_RDWR);
    buf_size = read(fdin, buf, 16384);

    while (1) {
        int tag;
        int v2replace;

        printf("tag : ");
        fflush(stdout);
        input_size = read(0, input, 1024);
        input[input_size-1] = '\0';

        tag = atoi(input);
        if (tag == 0) {
            break;
        }
 
        printf("value to replace (orig = %x) : ", buf[tag/2] & 0xff);
        fflush(stdout);
        input_size = read(0, input, 1024);
        input[input_size-1] = '\0';
        v2replace = atoi(input);

        buf[tag/2] = v2replace;
    } 
    fdout = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fdout, buf, buf_size);

    return 0;
}