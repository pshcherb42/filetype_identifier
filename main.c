#include <stdio.h>
#include <stdlib.h>
#include "filetype.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: filetype <file> [file ...]\n");
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        FileResult r = identify_file(argv[i]);
        print_result(&r, argv[i]);
        free_result(&r);
    }

    return 0;
}
