
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <mach-o/arch.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a)-1)
#define __ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))

#define is_fat_magic(__magicval)                                               \
    (__magicval == FAT_MAGIC || __magicval == FAT_CIGAM)
#define is_mach32_magic(__magicval)                                            \
    (__magicval == MH_MAGIC || __magicval == MH_CIGAM)
#define is_mach64_magic(__magicval)                                            \
    (__magicval == MH_MAGIC_64 || __magicval == MH_CIGAM_64)
#define is_mach_magic(__magicval)                                              \
    (is_mach32_magic(__magicval) || is_mach64_magic(__magicval))

typedef enum {
    OPERATION_UNKNOWN = 0,
    OPERATION_DECRYPT,
    OPERATION_LIST
} operation_t;

static int s_verbose = 0;
#define VERBOSE(...)                                                           \
    {                                                                          \
        if (s_verbose)                                                         \
            printf(__VA_ARGS__);                                               \
    }

#define VVERBOSE(...)                                                          \
    {                                                                          \
        if (s_verbose > 1)                                                     \
            printf(__VA_ARGS__);                                               \
    }

/*---------------------------------------------------------------------------*/

static void usage(char *name) {
    printf("Mach-O Decryptor\n");
    printf("Usage: %s [OPERATION] [OPTIONS] [MACH-O]\n", name);
    printf("Operation:\n");
    printf("  -d, --decrypt           decrypt all encrypted pages\n");
    printf("  -l, --list              list all the encrypted pages\n");
    printf("Options:\n");
    printf(
        "  -o, --output            specify file output (otherwise in-place)\n");
    printf("  -v, --verbose           be verbose\n");
    printf("  -vv                     be even more verbose\n");
    printf("  -h, --help              display this message\n\n");
    exit(1);
}

/*---------------------------------------------------------------------------*/

static void *decrypt_macho(const char *filename, off_t start_of_macho,
                           struct encryption_info_command *eic) {
    int fd = -1;
    void *crypt_data = MAP_FAILED;
    off_t cryptoff = (off_t)(start_of_macho + eic->cryptoff);
    cpu_subtype_t cpu_sub_type;
    cpu_type_t cpu_type;
    uint32_t magic;
    int res = -1;

    fd = open(filename, O_RDONLY);

    if (fd < 0) {
        return MAP_FAILED;
    }

    pread(fd, &magic, sizeof(uint32_t), start_of_macho);
    if (!is_mach_magic(magic)) {
        fprintf(stderr, "ERROR: wrong magic 0x%08X\n", magic);
        close(fd);
        return MAP_FAILED;
    }

    pread(fd, &cpu_type, sizeof(cpu_type_t), start_of_macho + sizeof(uint32_t));
    pread(fd, &cpu_sub_type, sizeof(cpu_subtype_t),
          start_of_macho + sizeof(uint32_t) + sizeof(cpu_type_t));

    if (cpu_type != CPU_TYPE_ARM && cpu_type != CPU_TYPE_ARM64) {
        fprintf(stderr, "ERROR: wrong CPU type 0x%08X\n", cpu_type);
        close(fd);
        return MAP_FAILED;
    }

    crypt_data = mmap(NULL, eic->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE,
                      fd, cryptoff);
    close(fd);

    if (crypt_data == MAP_FAILED) {
        perror("mmap");
        return MAP_FAILED;
    }

    res = syscall(SYS_mremap_encrypted, crypt_data, eic->cryptsize,
                  eic->cryptid, cpu_type, cpu_sub_type);

    if (res != 0) {
        fprintf(stderr, "ERROR: mremap_encrypted failed: %d\n", errno);
        munmap(crypt_data, eic->cryptsize);
        crypt_data = MAP_FAILED;
    }

    return crypt_data;
}

/*---------------------------------------------------------------------------*/

static int find_encryption_info(FILE *fp, off_t start_of_macho,
                                struct encryption_info_command *eic,
                                off_t *eic_off) {
    int i = 0;
    struct mach_header mach = {0};
    const NXArchInfo *arch_info = NULL;

    fseek(fp, start_of_macho, SEEK_SET);
    fread(&mach, sizeof(struct mach_header), 1, fp);

    arch_info = NXGetArchInfoFromCpuType(mach.cputype, mach.cpusubtype);
    if (arch_info != NULL) {
        VVERBOSE("Searching for encryption info LC in %s mach-o at 0x%016llX\n",
                 arch_info->description, start_of_macho);
    }

    if (is_mach64_magic(mach.magic)) {
        uint32_t reserved = 0;
        fread(&reserved, sizeof(uint32_t), 1, fp);
    }

    for (i = 0; i < mach.ncmds; i++) {
        struct load_command l_cmd = {0};
        fread(&l_cmd, sizeof(struct load_command), 1, fp);

        if ((LC_ENCRYPTION_INFO_64 == l_cmd.cmd) ||
            (LC_ENCRYPTION_INFO == l_cmd.cmd)) {
            fseek(fp, -1 * sizeof(struct load_command), SEEK_CUR);
            if (eic_off != NULL) {
                *eic_off = ftello(fp);
            }
            VVERBOSE("Found encryption LC at 0x%016llX\n", ftello(fp));
            fread(eic, sizeof(struct encryption_info_command), 1, fp);
            return 0;
        } else {
            /* skip this load command */
            fseek(fp, l_cmd.cmdsize - sizeof(struct load_command), SEEK_CUR);
        }
    }

    return i;
}

/*---------------------------------------------------------------------------*/

static int copy_file(const char *to, const char *from) {
    struct stat st = {0};
    int fd_from = -1;
    void *mem = MAP_FAILED;
    int fd_to = -1;
    ssize_t nwritten = 0;
    int saved_errno = 0;

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0) {
        return -1;
    }

    if (fstat(fd_from, &st) < 0) {
        goto out_error;
    }

    mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd_from, 0);
    if (mem == MAP_FAILED) {
        goto out_error;
    }

    fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, st.st_mode);
    if (fd_to < 0) {
        goto out_error;
    }

    nwritten = write(fd_to, mem, st.st_size);
    if (nwritten < st.st_size) {
        goto out_error;
    }

    if (close(fd_to) < 0) {
        fd_to = -1;
        goto out_error;
    }
    close(fd_from);

    return 0;

out_error:
    saved_errno = errno;

    close(fd_from);
    if (fd_to >= 0) {
        close(fd_to);
    }

    errno = saved_errno;
    return -1;
}

/*---------------------------------------------------------------------------*/

static int write_decrypted_macho(FILE *fp, off_t start_of_macho,
                                 struct encryption_info_command *eic,
                                 off_t eic_off, void *decrypted_bytes) {
    int status = 0;
    uint8_t buffer[16];

    /* check that bytes differ */
    if (fseeko(fp, start_of_macho + eic->cryptoff, SEEK_SET) == -1) {
        fprintf(stderr, "ERROR: unable to seek to encrypted offset 0x%016llX\n",
                start_of_macho + eic->cryptoff);
        status = 1;
        goto error;
    }

    if (fread(buffer, sizeof(uint8_t), 16, fp) != 16 ||
        !memcmp(buffer, (uint8_t *)decrypted_bytes, 16)) {
        fprintf(stderr, "ERROR: decrypted bytes == encrypted bytes\n");
        status = 1;
        goto error;
    }

    /* write the decrypted __TEXT */
    if (fseeko(fp, start_of_macho + eic->cryptoff, SEEK_SET) == -1) {
        fprintf(stderr, "ERROR: unable to seek to encrypted offset 0x%016llX\n",
                start_of_macho + eic->cryptoff);
        status = 1;
        goto error;
    }

    if (fwrite(decrypted_bytes, sizeof(uint8_t), eic->cryptsize, fp) !=
        eic->cryptsize) {
        fprintf(stderr, "ERROR: unable to write decrypted data\n");
        status = 1;
        goto error;
    }

    /* clear the cryptid */
    eic->cryptid = 0;
    if (fseeko(fp, eic_off, SEEK_SET) == -1) {
        fprintf(stderr, "ERROR: unable to seek to encryption info command at "
                        "offset 0x%016llX\n",
                eic_off);
        status = 1;
        goto error;
    }

    if (fwrite(eic, sizeof(struct encryption_info_command), 1, fp) != 1) {
        fprintf(stderr, "ERROR: unable to clear the cryptid\n");
        status = 1;
        goto error;
    }

error:
    fclose(fp);

    return status;
}

/*---------------------------------------------------------------------------*/

static int parse_macho(const char *path, FILE *fp, off_t start_of_macho,
                       uint32_t op, const char *output) {
    struct encryption_info_command eic = {0};
    off_t eic_off = 0;
    int found = find_encryption_info(fp, start_of_macho, &eic, &eic_off);

    VERBOSE("%s has %s pages starting at 0x%016llX\n", path,
            eic.cryptid ? "encrypted" : "unencrypted",
            eic.cryptoff + start_of_macho);

    if (op == OPERATION_DECRYPT) {
        if (found == 0 && eic.cryptid > 0) {
            void *decrypted = decrypt_macho(path, start_of_macho, &eic);

            if (decrypted != NULL && decrypted != MAP_FAILED) {
                FILE *output_fp = NULL;
                int ret = 0;
                /* copy path to output */
                if (output != NULL) {
                    struct stat st;
                    if ((lstat(output, &st) == -1) &&
                        (copy_file(output, path) != 0)) {
                        fprintf(stderr, "ERROR: unable to copy %s to %s\n",
                                path, output);
                        return 1;
                    }
                    output_fp = fopen(output, "r+");
                } else {
                    output_fp = fdopen(dup(fileno(fp)), "r+");
                }
                /* write out the decrypted __TEXT */
                ret = write_decrypted_macho(output_fp, start_of_macho, &eic,
                                            eic_off, decrypted);
                fclose(output_fp);
                return ret;
            } else {
                fprintf(stderr, "ERROR: unable to decrypt %s\n", path);
                return 1;
            }
        } else if (!found && eic.cryptid == 0) {
            VERBOSE("INFO: %s is not encrypted\n", path);
            return 0;
        } else {
            fprintf(stderr, "ERROR: unable to find the LC_ENCRYPTION_INFO\n");
            return 1;
        }
    } else if (op == OPERATION_LIST) {
        printf("%s\n\tcryptoff:  0x%08X\n\tcryptsize: 0x%08X\n\tcryptid:   "
               "0x%08X\n",
               path, eic.cryptoff, eic.cryptsize, eic.cryptid);
    }

    return 0;
}

/*---------------------------------------------------------------------------*/

static uint32_t check_for_hidden_macho(FILE *fp, uint32_t offset, uint32_t size,
                                       uint32_t align) {
    off_t end_of_fat = 0;
    off_t end_of_mach = ALIGN(offset + size, align);
    uint32_t magic = 0;

    fseeko(fp, 0, SEEK_END);
    end_of_fat = ftello(fp);

    if (end_of_fat > end_of_mach) {
        fseek(fp, end_of_mach, SEEK_SET);
        fread(&magic, sizeof(magic), 1, fp);

        if (is_mach_magic(magic)) {
            VERBOSE("Additional mach-o found at 0x%08llx\n", end_of_mach);
            return (uint32_t)end_of_mach;
        }
    }

    return 0;
}

/*---------------------------------------------------------------------------*/

static uint32_t ipow(uint32_t base, uint32_t exp) {
    uint32_t result = 1;
    while (exp != 0) {
        if ((exp & 1) == 1)
            result *= base;
        exp >>= 1;
        base *= base;
    }

    return result;
}

/*---------------------------------------------------------------------------*/

static uint32_t *find_mach_o_offsets(FILE *fp, uint32_t *nfat) {
    uint32_t *offsets = NULL;
    uint32_t magic = 0;
    off_t total_len = 0;

    if (NULL == fp || NULL == nfat)
        return NULL;

    /* get total len */
    fseeko(fp, 0, SEEK_END);
    total_len = ftello(fp);
    fseeko(fp, 0, SEEK_SET);

    fread(&magic, sizeof(magic), 1, fp);

    if (is_fat_magic(magic)) {
        uint32_t i;
        struct fat_arch arch;
        uint32_t size = 0;
        uint32_t align = 0;

        fread(nfat, 4, 1, fp);
        (*nfat) = ntohl(*nfat);
        offsets = (uint32_t *)malloc(sizeof(uint32_t) * (*nfat));

        VERBOSE("FAT table lists %d mach-o %s\n", *nfat,
                *nfat > 1 ? "entries" : "entry");

        for (i = 0; i < (*nfat); i++) {
            off_t curr_mach_off = 0;
            fread(&arch, sizeof(struct fat_arch), 1, fp);
            offsets[i] = ntohl(arch.offset);

            if (offsets[i] > total_len) {
                fprintf(stderr,
                        "ERROR: FAT points to mach-o at 0x%08x beyond EOF\n",
                        offsets[i]);
                goto fail;
            } else if ((offsets[i] + ntohl(arch.size)) > total_len) {
                fprintf(stderr, "ERROR: FAT points to mach-o at 0x%08x of len "
                                "0x%08x beyond EOF\n",
                        offsets[i], ntohl(arch.size));
                goto fail;
            }

            /* save current offset and check the mach magic */
            curr_mach_off = ftello(fp);
            fseeko(fp, (off_t)offsets[i], SEEK_SET);
            fread(&magic, sizeof(uint32_t), 1, fp);
            fseeko(fp, curr_mach_off, SEEK_SET);
            if (!is_mach_magic(magic)) {
                fprintf(stderr, "ERROR: FAT points to mach-o with bad magic "
                                "(0x%08x) at 0x%08x\n",
                        magic, offsets[i]);
                goto fail;
            }
        }

        if (*nfat) {
            /* double check */
            uint32_t offset = 0;

            size = ntohl(arch.size);
            align = ipow(2, ntohl(arch.align));
            if ((offset = check_for_hidden_macho(fp, offsets[(*nfat) - 1], size,
                                                 align))) {
                *nfat += 1;
                offsets =
                    (uint32_t *)realloc(offsets, sizeof(uint32_t) * (*nfat));
                offsets[1] = offset;
            }
        }
    } else if (is_mach_magic(magic)) {
        *nfat = 1;
        offsets = (uint32_t *)malloc(sizeof(uint32_t) * (*nfat));
        offsets[0] = 0;
    }

    return offsets;

fail:
    free(offsets);
    *nfat = 0;

    return NULL;
}

/*---------------------------------------------------------------------------*/

int main(int argc, char *argv[]) {
    static struct option long_opts[] = {
        {"decrypt", 0, 0, 'd'}, {"list", 0, 0, 'l'}, {"output", 1, 0, 'o'},
        {"verbose", 0, 0, 'v'}, {"help", 0, 0, 'h'}, {0, 0, 0, 0}};
    int i = 0;
    int opt = -1;
    int opt_i = 0;
    FILE *fp = NULL;
    int status = 0;
    uint32_t nfat = 0;
    uint32_t *offsets = NULL;
    char *mach_o = NULL;
    char *output = NULL;
    uint32_t op = 0;

    if (argc < 3) {
        usage(argv[0]);
    }

    mach_o = argv[argc - 1];

    while (-1 != (opt = getopt_long(argc, argv, "dlvho:", long_opts, &opt_i))) {
        switch (opt) {
        case 'd':
            op = OPERATION_DECRYPT;
            VERBOSE("Decrypting %s\n", mach_o);
            break;
        case 'l':
            op = OPERATION_LIST;
            break;
        case 'o':
            output = strdup(optarg);
            break;
        case 'v':
            s_verbose++;
            break;
        case 'h':
        default:
            usage(argv[0]);
            break;
        }
    }

    if (NULL == (fp = fopen(mach_o, "r+"))) {
        fprintf(stderr, "ERROR: unable to open %s\n", mach_o);
        status = -1;
        goto done;
    }

    offsets = find_mach_o_offsets(fp, &nfat);
    if (offsets == NULL || nfat <= 0) {
        status = -1;
        goto done;
    }

    VERBOSE("%s has %d mach-o entries\n", mach_o, nfat);
    for (i = 0; i < nfat; i++) {
        VVERBOSE("Parsing mach-o at offset 0x%08X\n", offsets[i]);
        status += parse_macho(mach_o, fp, offsets[i], op, output);
    }

done:
    if (offsets != NULL) {
        free(offsets);
    }

    if (output != NULL) {
        free(output);
    }

    if (NULL != fp) {
        fclose(fp);
    }

    return status;
}
