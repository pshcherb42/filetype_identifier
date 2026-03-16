#ifndef FILETYPE_H
#define FILETYPE_H

#include <stdint.h>
#include <stddef.h>

#define MAX_MAGIC_BYTES 16
#define READ_BUFFER_SIZE 264  /* enough for ZIP central directory offset */

typedef struct {
    const char     *name;        /* "PNG", "ELF", "PDF" … */
    const char     *mime;        /* "image/png" */
    const char     *extension;   /* ".png" */
    uint8_t         magic[MAX_MAGIC_BYTES];
    uint8_t         mask[MAX_MAGIC_BYTES];  /* 0xFF = must match, 0x00 = wildcard */
    size_t          magic_len;
    size_t          offset;      /* byte offset where magic starts */
} FileSignature;

typedef struct {
    const FileSignature *sig;    /* NULL if unknown */
    const char          *detail; /* extra info: ELF arch, ZIP contents… */
} FileResult;

FileResult identify_file(const char *path);
void zip_identifier(const char *path);
void       print_result(const FileResult *r, const char *path);
void       free_result(FileResult *r);

#endif
