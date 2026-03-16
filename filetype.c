#include "filetype.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EOCD_MAX_COMMENT 0xFFFF
#define EOCD_MIN_SIZE 22

/* ------------------------------------------------------------------ *
 *  Signature table
 *  mask: 0xFF = byte must match exactly, 0x00 = wildcard (don't care)
 * ------------------------------------------------------------------ */
static const FileSignature SIGNATURES[] = {
    /* ---- Images ---- */
    {
        "PNG", "image/png", ".png",
        {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        8, 0
    },
    {
        "JPEG", "image/jpeg", ".jpg",
        {0xFF, 0xD8, 0xFF},
        {0xFF, 0xFF, 0xFF},
        3, 0
    },
    {
        "GIF", "image/gif", ".gif",
        {0x47, 0x49, 0x46, 0x38},   /* GIF8 */
        {0xFF, 0xFF, 0xFF, 0xFF},
        4, 0
    },
    {
        "BMP", "image/bmp", ".bmp",
        {0x42, 0x4D},
        {0xFF, 0xFF},
        2, 0
    },
    /* ---- Documents ---- */
    {
        "PDF", "application/pdf", ".pdf",
        {0x25, 0x50, 0x44, 0x46},   /* %PDF */
        {0xFF, 0xFF, 0xFF, 0xFF},
        4, 0
    },
    /* ---- Archives ---- */
    {
        "ZIP/JAR/DOCX", "application/zip", ".zip",
        {0x50, 0x4B, 0x03, 0x04},   /* PK.. */
        {0xFF, 0xFF, 0xFF, 0xFF},
        4, 0
    },
    {
        "GZIP", "application/gzip", ".gz",
        {0x1F, 0x8B},
        {0xFF, 0xFF},
        2, 0
    },
    {
        "7-Zip", "application/x-7z-compressed", ".7z",
        {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        6, 0
    },
    /* ---- Executables ---- */
    {
        "ELF", "application/x-elf", "",
        {0x7F, 0x45, 0x4C, 0x46},   /* .ELF */
        {0xFF, 0xFF, 0xFF, 0xFF},
        4, 0
    },
    {
        "PE (Windows EXE/DLL)", "application/x-msdownload", ".exe",
        {0x4D, 0x5A},               /* MZ */
        {0xFF, 0xFF},
        2, 0
    },
    {
        "Mach-O (64-bit)", "application/x-mach-binary", "",
        {0xCF, 0xFA, 0xED, 0xFE},
        {0xFF, 0xFF, 0xFF, 0xFF},
        4, 0
    },
    {
        "Mach-O (32-bit)", "application/x-mach-binary", "",
        {0xCE, 0xFA, 0xED, 0xFE},
        {0xFF, 0xFF, 0xFF, 0xFF},
        4, 0
    },
    /* ---- Databases / data ---- */
    {
        "SQLite", "application/x-sqlite3", ".db",
        {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66},  /* "SQLite f" */
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        8, 0
    },
    /* ---- Media ---- */
    {
        "MP3", "audio/mpeg", ".mp3",
        {0xFF, 0xFB},
        {0xFF, 0xFF},
        2, 0
    },
    {
        "MP3 (ID3)", "audio/mpeg", ".mp3",
        {0x49, 0x44, 0x33},   /* ID3 */
        {0xFF, 0xFF, 0xFF},
        3, 0
    },
    {
        "MP4", "video/mp4", ".mp4",
        {0x00, 0x00, 0x00, 0x00, 0x66, 0x74, 0x79, 0x70},  /* ....ftyp */
        {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},   /* first 4 = size, wildcard */
        8, 0
    },
};

#define N_SIGNATURES (sizeof(SIGNATURES) / sizeof(SIGNATURES[0]))

/* ------------------------------------------------------------------ *
 *  ELF deep inspection
 * ------------------------------------------------------------------ */
static char *elf_detail(const uint8_t *buf, size_t len)
{
    if (len < 20) return NULL;

    const char *bits   = (buf[4] == 1) ? "32-bit" : (buf[4] == 2) ? "64-bit" : "unknown-class";
    const char *endian = (buf[5] == 1) ? "little-endian" : (buf[5] == 2) ? "big-endian" : "unknown-endian";

    uint16_t e_type = (buf[5] == 2)
        ? (uint16_t)((buf[16] << 8) | buf[17])   /* big endian */
        : (uint16_t)(buf[16] | (buf[17] << 8));   /* little endian */

    const char *type;
    switch (e_type) {
        case 1:  type = "relocatable (.o)";  break;
        case 2:  type = "executable";        break;
        case 3:  type = "shared library";    break;
        case 4:  type = "core dump";         break;
        default: type = "unknown type";      break;
    }

    uint16_t e_machine = (buf[5] == 2)
        ? (uint16_t)((buf[18] << 8) | buf[19])
        : (uint16_t)(buf[18] | (buf[19] << 8));

    const char *arch;
    switch (e_machine) {
        case 0x03: arch = "x86";     break;
        case 0x28: arch = "ARM";     break;
        case 0x3E: arch = "x86-64";  break;
        case 0xB7: arch = "AArch64"; break;
        case 0xF3: arch = "RISC-V";  break;
        default:   arch = "unknown arch"; break;
    }

    char *detail = malloc(128);
    if (detail)
        snprintf(detail, 128, "%s %s · %s · %s", bits, endian, type, arch);
    return detail;
}

/* ------------------------------------------------------------------ *
 *  Core identify
 * ------------------------------------------------------------------ */
    FileResult identify_file(const char *path)
{
    FileResult result = { NULL, NULL };

    FILE *f = fopen(path, "rb");

    if (!f) 
    {
        perror("fopen failed");
        return result;
    }
    
    uint8_t buf[READ_BUFFER_SIZE];
    size_t  n = fread(buf, 1, sizeof(buf), f);
    printf("Bytes: %02X %02X %02X %02X\n", buf[0], buf[1], buf[2], buf[3]);
    fclose(f);

    for (size_t i = 0; i < N_SIGNATURES; i++) {
        const FileSignature *s = &SIGNATURES[i];

        if (n < s->offset + s->magic_len) continue;

        const uint8_t *data = buf + s->offset;
        int match = 1;
        for (size_t j = 0; j < s->magic_len; j++) {
            if ((data[j] & s->mask[j]) != (s->magic[j] & s->mask[j])) {
                match = 0;
                break;
            }
        }

        if (match) {
            result.sig = s;
            /* deep inspection for specific formats */
            if (strcmp(s->name, "ELF") == 0)
                result.detail = elf_detail(buf, n);
            else if (strcmp(s->name, "ZIP/JAR/DOCX") == 0)
                zip_identifier(path);
            break;
        }
    }

    return result;
}

void zip_identifier(const char *path){
    FILE *f = fopen(path, "rb");
    if(!f){
        perror("could not open file\n");
        return ;
    }

    fseek(f, 0, SEEK_END); // find end
    long filesize = ftell(f); // file size
    long read_size = EOCD_MAX_COMMENT + EOCD_MIN_SIZE; //0xffff + 22
    if (read_size > filesize) read_size = filesize; // if this true can we assure that the zip file is empty?

    uint8_t *buf = malloc(read_size);
    if(!buf){
        perror("no buffer\n");
        fclose(f);
        return ;
    }

    fseek(f, filesize - read_size, SEEK_SET); // mover puntero desde el principio al principio de EOCD
    fread(buf, 1, read_size, f);
    //fclose(f);

    for (long i = read_size - EOCD_MIN_SIZE; i >= 0; i--) {
        if (buf[i] == 0x50 && buf[i+1] == 0x4B &&
            buf[i+2] == 0x05 && buf[i+3] == 0x06) {
            printf("Bytes: %02X %02X %02X %02X\n", buf[i], buf[i+1], buf[i+2], buf[i+3]);
            uint32_t cd_offset = *(uint32_t *)(buf + i + 16);
            printf("CD offset: %u\n", cd_offset);

            uint8_t sig[4];
            fseek(f, cd_offset, SEEK_SET);
            fread(sig, 1, 4, f);
            printf("CD signature: %02X %02X %02X %02X\n",
                sig[0], sig[1], sig[2], sig[3]);

            free(buf);
            return ; // нашли EOCD
        }
    }
}

void print_result(const FileResult *r, const char *path)
{
    if (!r->sig) {
        printf("%-40s  UNKNOWN\n", path);
        return;
    }
    printf("%-40s  %-22s  %s", path, r->sig->name, r->sig->mime);
    if (r->detail)
        printf("  [%s]", r->detail);
    printf("\n");
}

void free_result(FileResult *r)
{
    free((void *)r->detail);
    r->detail = NULL;
}
