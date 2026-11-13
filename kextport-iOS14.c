/* iOS 14.0 beta 2 port. Validated against supplied mini4/6S 18A5319i inputs. */
#define _POSIX_C_SOURCE 200809L
/*
 * kextport - graft prelinked kexts between arm64 kernelcaches
 *
 * Copies ApplePinotLCD and AppleChestnutDisplayPMU from a source
 * (iPhone 6S) kernelcache into a destination (iPad mini 4) kernelcache,
 * finding free zero-filled space dynamically. No hardcoded offsets.
 *
 * Usage: ./kextport <dst_kernel> <src_kernel> <output>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>

/* Mach-O constants */
#define MH_MAGIC_64      0xfeedfacf
#define LC_SEGMENT_64    0x19
#define LC_SYMTAB        0x02

#pragma pack(push, 1)
struct mach_header_64 {
    uint32_t magic, cputype, cpusubtype, filetype;
    uint32_t ncmds, sizeofcmds, flags, reserved;
};

struct load_command {
    uint32_t cmd, cmdsize;
};

struct segment_command_64 {
    uint32_t cmd, cmdsize;
    char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
};

struct section_64 {
    char sectname[16], segname[16];
    uint64_t addr, size;
    uint32_t offset, align, reloff, nreloc, flags;
    uint32_t reserved1, reserved2, reserved3;
};

struct symtab_command {
    uint32_t cmd, cmdsize;
    uint32_t symoff, nsyms, stroff, strsize;
};
#pragma pack(pop)

/* kmod_info offsets (arm64, packed struct) */
#define KMOD_NAME_OFF    0x10
#define KMOD_VERS_OFF    0x50
#define KMOD_ID_OFF      0x08
#define KMOD_REFCOUNT_OFF 0x90
#define KMOD_REFLIST_OFF 0x94
#define KMOD_ADDR_OFF    0x9c
#define KMOD_SIZE_OFF    0xa4
#define KMOD_HDRSIZE_OFF 0xac
#define KMOD_START_OFF   0xb4
#define KMOD_STOP_OFF    0xbc

#define MAX_SEGS  32
#define MAX_SECTS 32
#define MAX_GAPS  512
#define MAX_KEXTS 256

struct seg_info {
    char name[17];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t nsects;
    struct {
        char name[17];
        uint64_t addr, size;
        uint32_t offset;
    } sects[MAX_SECTS];
};

struct kext_seg {
    struct seg_info seg;
};

struct kext_info {
    char bundle_id[256];
    uint64_t load_addr;
    uint64_t size;
    uint64_t source_addr;
    uint64_t kmod_info_addr;
    int nseg;
    struct seg_info segs[8];
};

struct gap {
    uint64_t vmaddr;
    uint64_t fileoff;
    uint64_t size;
};

struct kernel {
    uint8_t *data;
    size_t len;
    int nseg;
    struct seg_info segs[MAX_SEGS];
    uint32_t symoff, nsyms, stroff, strsize;
};

/* ---- helpers ---- */

static int seg_by_name(struct kernel *k, const char *name) {
    for (int i = 0; i < k->nseg; i++)
        if (strcmp(k->segs[i].name, name) == 0) return i;
    return -1;
}

static int64_t vm_to_fileoff(struct kernel *k, uint64_t vm) {
    for (int i = 0; i < k->nseg; i++) {
        struct seg_info *s = &k->segs[i];
        if (vm >= s->vmaddr && vm < s->vmaddr + s->filesize)
            return (int64_t)(vm - s->vmaddr + s->fileoff);
    }
    return -1;
}

static void parse_kernel(struct kernel *k) {
    struct mach_header_64 *mh = (struct mach_header_64 *)k->data;
    if (k->len < 32 || mh->magic != MH_MAGIC_64 || mh->cputype != 0x0100000c ||
        mh->sizeofcmds > k->len - 32) {
        fprintf(stderr, "Not a Mach-O 64 file\n");
        exit(1);
    }
    uint32_t off = 32;
    k->nseg = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (off > k->len || k->len - off < 8) { fprintf(stderr,"Truncated load command\n"); exit(1); }
        struct load_command *lc = (struct load_command *)(k->data + off);
        if (lc->cmdsize < 8 || lc->cmdsize > k->len - off) { fprintf(stderr,"Invalid load command size\n"); exit(1); }
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sc = (struct segment_command_64 *)(k->data + off);
            if (k->nseg == MAX_SEGS || sc->cmdsize < sizeof(*sc) || sc->nsects > MAX_SECTS ||
                sc->nsects * sizeof(struct section_64) > sc->cmdsize - sizeof(*sc) ||
                sc->fileoff > k->len || sc->filesize > k->len - sc->fileoff) {
                fprintf(stderr,"Invalid outer segment\n"); exit(1);
            }
            struct seg_info *si = &k->segs[k->nseg++];
            memset(si, 0, sizeof(*si));
            memcpy(si->name, sc->segname, 16); si->name[16] = 0;
            si->vmaddr = sc->vmaddr;
            si->vmsize = sc->vmsize;
            si->fileoff = sc->fileoff;
            si->filesize = sc->filesize;
            si->nsects = sc->nsects;
            struct section_64 *sec = (struct section_64 *)(k->data + off + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < sc->nsects && j < MAX_SECTS; j++) {
                memcpy(si->sects[j].name, sec[j].sectname, 16);
                si->sects[j].name[16] = 0;
                si->sects[j].addr = sec[j].addr;
                si->sects[j].size = sec[j].size;
                si->sects[j].offset = sec[j].offset;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            struct symtab_command *st = (struct symtab_command *)(k->data + off);
            k->symoff = st->symoff;
            k->nsyms = st->nsyms;
            k->stroff = st->stroff;
            k->strsize = st->strsize;
        }
        off += lc->cmdsize;
    }
}

static void parse_kext_segs(struct kernel *k, uint64_t load_addr, struct kext_info *ki) {
    int64_t fo = vm_to_fileoff(k, load_addr);
    if (fo < 0) return;
    struct mach_header_64 *mh = (struct mach_header_64 *)(k->data + fo);
    if (mh->magic != MH_MAGIC_64) return;
    uint32_t off = (uint32_t)fo + 32;
    ki->nseg = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (off > k->len || k->len - off < 8) { fprintf(stderr,"Truncated load command\n"); exit(1); }
        struct load_command *lc = (struct load_command *)(k->data + off);
        if (lc->cmdsize < 8 || lc->cmdsize > k->len - off) { fprintf(stderr,"Invalid load command size\n"); exit(1); }
        if (lc->cmd == LC_SEGMENT_64 && ki->nseg < 8) {
            struct segment_command_64 *sc = (struct segment_command_64 *)(k->data + off);
            if (sc->cmdsize < sizeof(*sc) || sc->nsects > MAX_SECTS ||
                sc->nsects * sizeof(struct section_64) > sc->cmdsize - sizeof(*sc)) {
                fprintf(stderr,"Invalid kext segment\n"); exit(1);
            }
            struct seg_info *si = &ki->segs[ki->nseg++];
            memset(si, 0, sizeof(*si));
            memcpy(si->name, sc->segname, 16); si->name[16] = 0;
            si->vmaddr = sc->vmaddr;
            si->vmsize = sc->vmsize;
            si->fileoff = sc->fileoff;
            si->filesize = sc->filesize;
            si->nsects = sc->nsects;
            struct section_64 *sec = (struct section_64 *)(k->data + off + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < sc->nsects && j < MAX_SECTS; j++) {
                memcpy(si->sects[j].name, sec[j].sectname, 16);
                si->sects[j].name[16] = 0;
                si->sects[j].addr = sec[j].addr;
                si->sects[j].size = sec[j].size;
                si->sects[j].offset = sec[j].offset;
            }
        }
        off += lc->cmdsize;
    }
}

/* Only allocate outside every embedded kext's declared VM ranges.
 * Zero bytes inside a live segment include BSS, vtables and reserved storage. */
static int find_gaps(struct kernel *k, const char *segname, uint64_t min_size,
                     struct gap *gaps, int max_gaps)
{
    int si = seg_by_name(k, segname), pt = seg_by_name(k, "__PRELINK_TEXT");
    if (si < 0 || pt < 0) return 0;
    struct seg_info *s = &k->segs[si], *headers = &k->segs[pt];
    uint8_t *busy = calloc(s->filesize, 1);
    if (!strcmp(segname,"__DATA")) {
        /* Kernel DATA padding is a fallback header home. Protect every declared
         * section, including zerofill sections with offset=0; they are live. */
        for (uint32_t j=0;j<s->nsects;j++) {
            uint64_t lo=s->sects[j].addr, hi=lo+s->sects[j].size;
            if (lo<s->vmaddr) lo=s->vmaddr;
            if (hi>s->vmaddr+s->filesize) hi=s->vmaddr+s->filesize;
            if (hi>lo) memset(busy+lo-s->vmaddr,1,hi-lo);
        }
    }
    for (uint64_t pos = 0; pos + 32 <= headers->filesize; pos += 4) {
        uint64_t fo = headers->fileoff + pos;
        struct mach_header_64 mh;
        memcpy(&mh, k->data + fo, sizeof(mh));
        if (mh.magic != MH_MAGIC_64 || mh.cputype != 0x0100000c) continue;
        if (mh.sizeofcmds > headers->filesize - pos - 32) {
            fprintf(stderr, "Invalid embedded Mach-O header\n"); exit(1);
        }
        if (si == pt) memset(busy + pos, 1, 32 + mh.sizeofcmds);
        /* KPI pseudoextensions contain overlapping, stripped headers and no VM storage. */
        struct segment_command_64 *first = (void *)(k->data + fo + 32);
        if (first->cmd == LC_SEGMENT_64 && !strncmp(first->segname, "__LINKEDIT",16) && !first->vmaddr) continue;
        uint64_t off = fo + 32, end = off + mh.sizeofcmds;
        for (uint32_t j = 0; j < mh.ncmds; j++) {
            struct load_command *lc = (void *)(k->data + off);
            if (off + 8 > end || lc->cmdsize < 8 || lc->cmdsize > end - off) {
                fprintf(stderr, "Invalid embedded load command at header %llx cmd %u ncmds %u size %u\n", (unsigned long long)fo, j, mh.ncmds, mh.sizeofcmds); exit(1);
            }
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *sc = (void *)lc;
                uint64_t lo = sc->vmaddr > s->vmaddr ? sc->vmaddr : s->vmaddr;
                uint64_t hi = sc->vmaddr + sc->vmsize;
                if (hi > s->vmaddr + s->filesize) hi = s->vmaddr + s->filesize;
                if (hi > lo) memset(busy + lo - s->vmaddr, 1, hi - lo);
            }
            off += lc->cmdsize;
        }
    }
    int n = 0;
    for (uint64_t i = 0; i < s->filesize;) {
        if (busy[i] || k->data[s->fileoff + i]) { i++; continue; }
        uint64_t start = i;
        while (i < s->filesize && !busy[i] && !k->data[s->fileoff + i]) i++;
        /* Eight-byte alignment also keeps GOT loads encodable. */
        start = (start + 7) & ~7ULL;
        if (i >= start && i - start >= min_size) {
            if (n == max_gaps) { fprintf(stderr, "Too many free gaps\n"); exit(1); }
            gaps[n++] = (struct gap){s->vmaddr + start, s->fileoff + start, i - start};
        }
    }
    free(busy);
    return n;
}

/* Find a gap that fits 'needed' bytes, prefer smallest fit */
static struct gap *find_best_gap(struct gap *gaps, int ngap, uint64_t needed,
                                 uint64_t *used_addrs, int nused)
{
    struct gap *best = NULL;
    for (int i = 0; i < ngap; i++) {
        if (gaps[i].size < needed) continue;
        /* skip if overlaps a used region */
        bool ok = true;
        for (int j = 0; j < nused; j++) {
            if (gaps[i].vmaddr == used_addrs[j]) { ok = false; break; }
        }
        if (!ok) continue;
        if (!best || gaps[i].size < best->size) best = &gaps[i];
    }
    static struct gap selected;
    if (!best) return NULL;
    selected = *best;
    uint64_t take = (needed + 7) & ~7ULL;
    if (take > best->size) take = needed;
    best->vmaddr += take; best->fileoff += take; best->size -= take;
    return &selected;
}

/* ---- XML plist helpers ---- */

static char *find_prelink_info(struct kernel *k, uint64_t *offset, uint64_t *max_size) {
    int si = seg_by_name(k, "__PRELINK_INFO");
    if (si < 0) return NULL;
    struct seg_info *s = &k->segs[si];
    if (!memchr(k->data + s->fileoff,0,s->filesize)) {
        fprintf(stderr,"Unterminated prelink plist\n"); exit(1);
    }
    *offset = s->fileoff;
    *max_size = s->filesize;
    return (char *)(k->data + s->fileoff);
}

/* Find a kext entry in the plist by bundle ID, return its load addr + kmod addr */
static bool find_kext_in_plist(const char *plist, const char *bundle_id,
                               uint64_t *load_addr, uint64_t *size,
                               uint64_t *source_addr, uint64_t *kmod_info)
{
    /* Search for the bundle path that contains the bundle_id */
    char needle[512];
    snprintf(needle, sizeof(needle), "%s</string>", bundle_id);
    const char *p = plist;
    while ((p = strstr(p, needle)) != NULL) {
        /* Find the enclosing <dict> */
        const char *dict_start = p;
        for (int i = 0; i < 40 && dict_start > plist; i++) {
            dict_start--;
            if (strncmp(dict_start, "<dict>", 6) == 0) break;
        }
        if (strncmp(dict_start, "<dict>", 6) != 0) {
            /* search further back */
            const char *ds2 = p;
            while (ds2 > plist) {
                ds2--;
                if (strncmp(ds2, "<dict>", 6) == 0) { dict_start = ds2; break; }
            }
        }
        /* Find dict end */
        const char *dict_end = strstr(p, "</dict>");
        if (!dict_end) { p += strlen(needle); continue; }

        /* Extract fields */
        const char *la = strstr(dict_start, "_PrelinkExecutableLoadAddr");
        if (la && la < dict_end) {
            la = strstr(la, "0x");
            if (la) *load_addr = strtoull(la, NULL, 16);
        }
        const char *sz = strstr(dict_start, "_PrelinkExecutableSize");
        if (sz && sz < dict_end) {
            sz = strstr(sz, "0x");
            if (sz) *size = strtoull(sz, NULL, 16);
        }
        const char *sa = strstr(dict_start, "_PrelinkExecutableSourceAddr");
        if (sa && sa < dict_end) {
            sa = strstr(sa, "0x");
            if (sa) *source_addr = strtoull(sa, NULL, 16);
        }
        const char *km = strstr(dict_start, "_PrelinkKmodInfo");
        if (km && km < dict_end) {
            km = strstr(km, "0x");
            if (km) *kmod_info = strtoull(km, NULL, 16);
        }
        return true;
    }
    return false;
}

/* Find AppleARMPlatform load addr in a kernel's plist */
static uint64_t find_arm_platform_addr(struct kernel *k) {
    uint64_t off, maxsz;
    char *plist = find_prelink_info(k, &off, &maxsz);
    if (!plist) return 0;
    uint64_t la = 0, sz = 0, sa = 0, km = 0;
    if (find_kext_in_plist(plist, "com.apple.driver.AppleARMPlatform", &la, &sz, &sa, &km))
        return la;
    return 0;
}

/* Segment-offset mapping is valid only for the same dependency build. */
static bool matching_kext_uuid(struct kernel *a, uint64_t av, struct kernel *b, uint64_t bv) {
    uint8_t uuids[2][16];
    struct kernel *kernels[2] = {a,b}; uint64_t addrs[2] = {av,bv};
    for (int j=0;j<2;j++) {
        int64_t f=vm_to_fileoff(kernels[j],addrs[j]); if (f<0) return false;
        struct mach_header_64 *mh=(void *)(kernels[j]->data+f);
        uint64_t off=f+32; bool found=false;
        for (uint32_t i=0;i<mh->ncmds;i++) {
            struct load_command *lc=(void *)(kernels[j]->data+off);
            if (lc->cmd==0x1b && lc->cmdsize==24) { memcpy(uuids[j],kernels[j]->data+off+8,16); found=true; }
            off+=lc->cmdsize;
        }
        if (!found) return false;
    }
    return !memcmp(uuids[0],uuids[1],16);
}

/* ---- KASLR offset table ---- */

struct kaslr_table {
    uint64_t plist_data_fileoff;  /* file offset of the base64 <data> content start */
    uint64_t base64_len;
    uint32_t *offsets;
    uint32_t count;
    uint64_t prelink_text_base;
};

/* Simple base64 decoder */
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static uint8_t *b64_decode(const char *in, size_t in_len, size_t *out_len) {
    uint8_t *out = malloc(in_len);
    size_t oi = 0;
    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        int v = b64_val(in[i]);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[oi++] = (buf >> bits) & 0xff;
        }
    }
    *out_len = oi;
    return out;
}

/* Simple base64 encoder */
static const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *in, size_t in_len, size_t *out_len) {
    size_t olen = 4 * ((in_len + 2) / 3);
    char *out = malloc(olen + 1);
    size_t oi = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t n = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) n |= (uint32_t)in[i+1] << 8;
        if (i + 2 < in_len) n |= (uint32_t)in[i+2];
        out[oi++] = b64_chars[(n >> 18) & 0x3f];
        out[oi++] = b64_chars[(n >> 12) & 0x3f];
        out[oi++] = (i + 1 < in_len) ? b64_chars[(n >> 6) & 0x3f] : '=';
        out[oi++] = (i + 2 < in_len) ? b64_chars[n & 0x3f] : '=';
    }
    out[oi] = 0;
    *out_len = oi;
    return out;
}

static bool parse_kaslr_table(struct kernel *k, struct kaslr_table *kt) {
    uint64_t pi_off, pi_max;
    char *plist = find_prelink_info(k, &pi_off, &pi_max);
    if (!plist) return false;

    int si = seg_by_name(k, "__PRELINK_TEXT");
    if (si < 0) return false;
    kt->prelink_text_base = k->segs[si].vmaddr;

    const char *key = strstr(plist, "_PrelinkLinkKASLROffsets");
    if (!key) return false;
    const char *data_start = strstr(key, "<data");
    if (!data_start) return false;
    data_start = strchr(data_start, '>');
    if (!data_start) return false;
    data_start++;
    const char *data_end = strstr(data_start, "</data>");
    if (!data_end) return false;

    kt->plist_data_fileoff = pi_off + (data_start - plist);
    kt->base64_len = data_end - data_start;

    size_t decoded_len;
    uint8_t *decoded = b64_decode(data_start, data_end - data_start, &decoded_len);
    if (decoded_len < 4) { free(decoded); return false; }

    memcpy(&kt->count, decoded, 4);
    if (decoded_len < 4 + kt->count * 4) { free(decoded); return false; }

    kt->offsets = malloc(kt->count * 4);
    memcpy(kt->offsets, decoded + 4, kt->count * 4);
    free(decoded);
    return true;
}

/* ---- The main grafting logic ---- */

struct placement {
    uint64_t text_vm, text_fo;       /* __TEXT (Mach-O header) */
    uint64_t texec_vm, texec_fo;     /* __TEXT_EXEC */
    uint64_t data_vm, data_fo;       /* __DATA */
    uint64_t dconst_vm, dconst_fo;   /* __DATA_CONST */
};

static void copy_and_fixup_segment(uint8_t *dst, struct kernel *src_k,
                                   struct seg_info *src_seg,
                                   uint64_t dst_fo, uint64_t dst_vm)
{
    (void)dst_vm;
    if (src_seg->filesize == 0) return;
    int64_t src_fo = vm_to_fileoff(src_k, src_seg->vmaddr);
    if (src_fo < 0) {
        /* Segment lives in inner Mach-O with fileoff=0, compute from parent */
        return;
    }
    memcpy(dst + dst_fo, src_k->data + src_fo, src_seg->filesize);
}

/* Rewrite the kext's inner Mach-O header to reflect new addresses */
static void rewrite_kext_header(uint8_t *out, uint64_t header_fo,
                                struct kext_info *ki, struct placement *pl)
{
    (void)ki;
    struct mach_header_64 *mh = (struct mach_header_64 *)(out + header_fo);
    if (mh->magic != MH_MAGIC_64) return;

    uint32_t off = (uint32_t)header_fo + 32;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)(out + off);
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sc = (struct segment_command_64 *)(out + off);
            uint64_t new_vm = 0, new_fo = 0;

            if (strncmp(sc->segname, "__TEXT", 6) == 0 && sc->segname[6] == 0) {
                new_vm = pl->text_vm; new_fo = pl->text_fo;
            } else if (strncmp(sc->segname, "__TEXT_EXEC", 11) == 0) {
                new_vm = pl->texec_vm; new_fo = pl->texec_fo;
            } else if (strncmp(sc->segname, "__DATA_CONST", 12) == 0) {
                new_vm = pl->dconst_vm; new_fo = pl->dconst_fo;
            } else if (strncmp(sc->segname, "__DATA", 6) == 0 && sc->segname[6] == 0) {
                new_vm = pl->data_vm; new_fo = pl->data_fo;
            } else if (strncmp(sc->segname, "__LINKEDIT", 10) == 0) {
                if (sc->vmsize || sc->filesize) { fprintf(stderr,"Nonempty kext LINKEDIT unsupported\n"); exit(1); }
                sc->vmaddr = 0; sc->fileoff = 0;
                /* No donor linkedit storage survives in the receiver. */
                off += lc->cmdsize;
                continue;
            }

            if (new_vm) {
                if (new_fo < header_fo || new_fo-header_fo > UINT32_MAX) {
                    fprintf(stderr,"Kext segment cannot be represented relative to header\n"); exit(1);
                }
                uint64_t old_vm = sc->vmaddr;
                uint64_t old_fo = sc->fileoff;

                /* Update sections */
                struct section_64 *sec = (struct section_64 *)(out + off + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < sc->nsects; j++) {
                    uint64_t sect_delta = sec[j].addr - old_vm;
                    sec[j].addr = new_vm + sect_delta;
                    if (sec[j].size > 0 && sec[j].offset != 0) {
                        sec[j].offset = (uint32_t)(new_fo - header_fo + (sec[j].offset - old_fo));
                    }
                }
                sc->vmaddr = new_vm;
                sc->fileoff = new_fo - header_fo;
            }
        }
        off += lc->cmdsize;
    }
}

/* Fix up KASLR-tracked pointers in DATA and DATA_CONST regions */
static uint64_t placed_base(const char *name, const struct placement *p) {
    if (!strcmp(name, "__TEXT")) return p->text_vm;
    if (!strcmp(name, "__TEXT_EXEC")) return p->texec_vm;
    if (!strcmp(name, "__DATA")) return p->data_vm;
    if (!strcmp(name, "__DATA_CONST")) return p->dconst_vm;
    return 0;
}

/* Resolve by identity, never by nearest-symbol guesses or one global delta. */
static uint64_t translate(struct kernel *src, struct kernel *dst,
                          struct kext_info *ki, struct placement *pl, uint64_t value) {
    for (int i = 0; i < ki->nseg; i++) {
        struct seg_info *s = &ki->segs[i];
        uint64_t base = placed_base(s->name, pl);
        if (base && value >= s->vmaddr && value - s->vmaddr < s->vmsize)
            return base + value - s->vmaddr;
    }
    for (uint32_t i = 0; i < src->nsyms; i++) {
        uint64_t v; uint32_t name;
        memcpy(&v, src->data + src->symoff + i * 16 + 8, 8);
        if (v != value) continue;
        memcpy(&name, src->data + src->symoff + i * 16, 4);
        const char *symbol = (char *)src->data + src->stroff + name;
        for (uint32_t j = 0; j < dst->nsyms; j++) {
            uint32_t dn; uint64_t dv;
            memcpy(&dn, dst->data + dst->symoff + j * 16, 4);
            memcpy(&dv, dst->data + dst->symoff + j * 16 + 8, 8);
            if (dv && !strcmp(symbol, (char *)dst->data + dst->stroff + dn)) return dv;
        }
    }
    struct kext_info a = {0}, b = {0};
    parse_kext_segs(src, find_arm_platform_addr(src), &a);
    parse_kext_segs(dst, find_arm_platform_addr(dst), &b);
    for (int i = 0; i < a.nseg; i++) {
        struct seg_info *as = &a.segs[i];
        if (value < as->vmaddr || value - as->vmaddr >= as->vmsize) continue;
        for (int j = 0; j < b.nseg; j++) {
            struct seg_info *bs = &b.segs[j];
            if (!strcmp(as->name, bs->name) && as->vmsize == bs->vmsize &&
                as->nsects == bs->nsects) {
                /* This mapping requires matching section layouts as well. */
                for (uint32_t n = 0; n < as->nsects; n++) {
                    if (strcmp(as->sects[n].name, bs->sects[n].name) ||
                        as->sects[n].size != bs->sects[n].size ||
                        as->sects[n].addr - as->vmaddr != bs->sects[n].addr - bs->vmaddr) {
                        fprintf(stderr, "AppleARMPlatform section layout mismatch\n"); exit(1);
                    }
                }
                return bs->vmaddr + value - as->vmaddr;
            }
        }
    }
    fprintf(stderr, "Unresolved source address %llx in %s; refusing output\n",
            (unsigned long long)value, ki->bundle_id);
    exit(1);
}

static int64_t sign_extend(uint64_t n, unsigned bits) {
    return (int64_t)(n ^ (1ULL << (bits - 1))) - (int64_t)(1ULL << (bits - 1));
}
static uint32_t read32(const uint8_t *p) { uint32_t n; memcpy(&n,p,4); return n; }
static void write32(uint8_t *p, uint32_t n) { memcpy(p,&n,4); }
static uint32_t encode_delta(uint32_t ins, int64_t delta, unsigned bits,
                             unsigned shift, unsigned field) {
    int64_t unit = 1LL << shift;
    if (delta % unit || delta / unit < -(1LL << (bits - 1)) ||
        delta / unit >= (1LL << (bits - 1))) {
        fprintf(stderr, "PC-relative relocation out of range/alignment\n"); exit(1);
    }
    uint32_t mask = ((1U << bits) - 1);
    return (ins & ~(mask << field)) | (((uint32_t)(delta / unit) & mask) << field);
}

/* Supported ADRP pairs consume/overwrite the page register immediately.
 * Reject unfamiliar sequences rather than silently emitting broken code. */
static void fixup_instructions(uint8_t *out, struct kernel *src, struct kernel *dst,
                               struct kext_info *ki, struct placement *pl) {
    unsigned pairs = 0, relatives = 0;
    for (int si = 0; si < ki->nseg; si++) {
        struct seg_info *s = &ki->segs[si];
        if (strcmp(s->name,"__TEXT_EXEC")) continue;
        int64_t sf = vm_to_fileoff(src,s->vmaddr);
        for (uint64_t i = 0; i + 4 <= s->filesize; i += 4) {
            uint32_t w = read32(src->data + sf + i), patched = w;
            uint64_t pc = s->vmaddr + i, npc = pl->texec_vm + i;
            if ((w & 0x9f000000) == 0x90000000) {
                if (i + 8 > s->filesize) { fprintf(stderr,"Truncated ADRP pair\n"); exit(1); }
                uint32_t next = read32(src->data + sf + i + 4), rd = w & 31;
                bool add = (next & 0xffc00000) == 0x91000000;
                bool load = (next & 0xffc00000) == 0xf9400000;
                if ((!add && !load) || ((next >> 5) & 31) != rd || (next & 31) != rd) {
                    fprintf(stderr,"Unsupported ADRP consumer at %llx\n",(unsigned long long)pc); exit(1);
                }
                int64_t imm = sign_extend(((w >> 5 & 0x7ffff) << 2) | (w >> 29 & 3),21);
                uint64_t target = (pc & ~4095ULL) + imm * 4096 +
                    ((next >> 10 & 4095) << (load ? 3 : 0));
                uint64_t mapped = translate(src,dst,ki,pl,target);
                int64_t pages = ((int64_t)(mapped & ~4095ULL) - (int64_t)(npc & ~4095ULL))/4096;
                if (pages < -(1<<20) || pages >= (1<<20) || (load && (mapped & 7))) {
                    fprintf(stderr,"Unencodable ADRP target\n"); exit(1);
                }
                uint32_t imm21 = (uint32_t)pages & 0x1fffff;
                patched = (w & ~0x60ffffe0U) | ((imm21 & 3) << 29) | ((imm21 >> 2) << 5);
                next = (next & ~(4095U << 10)) | (((mapped & 4095) >> (load ? 3 : 0)) << 10);
                write32(out + pl->texec_fo + i,patched);
                write32(out + pl->texec_fo + i + 4,next);
                pairs++; i += 4; continue;
            }
            if ((w & 0x9f000000) == 0x10000000) {
                int64_t imm = sign_extend(((w >> 5 & 0x7ffff) << 2) | (w >> 29 & 3),21);
                int64_t delta = (int64_t)translate(src,dst,ki,pl,pc + imm) - (int64_t)npc;
                if (delta < -(1<<20) || delta >= (1<<20)) { fprintf(stderr,"ADR out of range\n"); exit(1); }
                uint32_t im = (uint32_t)delta & 0x1fffff;
                patched = (w & ~0x60ffffe0U) | ((im & 3) << 29) | ((im >> 2) << 5);
                relatives++;
            } else {
                unsigned bits = 0, field = 0;
                if ((w & 0x7c000000) == 0x14000000) bits = 26;
                else if ((w & 0xff000010) == 0x54000000 ||
                         (w & 0x7e000000) == 0x34000000 ||
                         (w & 0x3b000000) == 0x18000000) { bits = 19; field = 5; }
                else if ((w & 0x7e000000) == 0x36000000) { bits = 14; field = 5; }
                if (bits) {
                    int64_t off = sign_extend((w >> field) & ((1U << bits)-1),bits)*4;
                    uint64_t mapped = translate(src,dst,ki,pl,pc + off);
                    patched = encode_delta(w,(int64_t)mapped-(int64_t)npc,bits,2,field);
                    relatives++;
                }
            }
            write32(out + pl->texec_fo + i,patched);
        }
    }
    printf("  Relocated %u ADRP pairs and %u other PC-relative instructions\n",pairs,relatives);
}

/* Iterate relocation records, including pointers aligned to four bytes. */
static int fixup_pointers(uint8_t *out, struct kernel *src_k, struct kernel *dst_k,
                          struct kext_info *ki, struct placement *pl,
                          struct kaslr_table *src_kt, struct kaslr_table *dst_kt,
                          uint64_t arm_platform_delta,
                          uint32_t **new_kaslr_offsets, int *new_kaslr_count) {
    (void)arm_platform_delta;
    *new_kaslr_count = 0;
    *new_kaslr_offsets = malloc((src_kt->count + 1ULL) * sizeof(uint32_t));
    for (uint32_t r = 0; r < src_kt->count; r++) {
        uint64_t loc = src_kt->prelink_text_base + src_kt->offsets[r];
        for (int i = 0; i < ki->nseg; i++) {
            struct seg_info *s = &ki->segs[i];
            uint64_t base = placed_base(s->name,pl), fo = 0;
            if (!base || loc < s->vmaddr || loc - s->vmaddr + 8 > s->filesize) continue;
            if (!strcmp(s->name,"__DATA")) fo = pl->data_fo;
            else if (!strcmp(s->name,"__DATA_CONST")) fo = pl->dconst_fo;
            else { fprintf(stderr,"Unexpected relocation in %s\n",s->name); exit(1); }
            uint64_t off = loc - s->vmaddr, ptr;
            int64_t sf = vm_to_fileoff(src_k,loc);
            memcpy(&ptr,src_k->data + sf,8);
            ptr = translate(src_k,dst_k,ki,pl,ptr);
            memcpy(out + fo + off,&ptr,8);
            (*new_kaslr_offsets)[(*new_kaslr_count)++] = (uint32_t)(base+off-dst_kt->prelink_text_base);
        }
    }
    return *new_kaslr_count;
}

/* Fix kmod_info structure */
static void fixup_kmod_info(uint8_t *out, uint64_t kmod_fo, struct placement *pl,
                            uint64_t old_text_vm, uint64_t old_text_exec_vm,
                            uint64_t text_size)
{
    (void)old_text_vm; (void)old_text_exec_vm; (void)text_size;
    /* kmod_info.address = kext __TEXT base */
    memcpy(out + kmod_fo + KMOD_ADDR_OFF, &pl->text_vm, 8);

    /* kmod_info.size stays the same (total kext size, doesn't change) */

    /* kmod_info.start and stop are function pointers into __TEXT_EXEC,
       they're KASLR-tracked and handled by the pointer fixup */
}

/* ---- PRELINK_INFO plist manipulation ---- */

/* XML fragments here use Apple's serialized plist grammar (ID/IDREF).
 * Expand donor references before insertion to avoid colliding with receiver IDs. */
static const char *xml_end(const char *start) {
    char tag[64]; size_t n = 0;
    const char *p = start + 1;
    while (*p && *p != '>' && *p != ' ' && *p != '/' && n < sizeof(tag)-1) tag[n++] = *p++;
    tag[n] = 0;
    const char *gt = strchr(p,'>');
    if (!n || !gt) { fprintf(stderr,"Invalid plist XML element\n"); exit(1); }
    if (gt[-1] == '/') return gt+1;
    int depth = 1; p = gt+1;
    while ((p = strchr(p,'<'))) {
        bool close = p[1]=='/'; const char *name = p+1+close;
        if (!strncmp(name,tag,n) && (name[n]=='>' || name[n]==' ' || name[n]=='/')) {
            const char *e = strchr(name,'>');
            if (!e) break;
            if (close) depth--; else if (e[-1]!='/') depth++;
            if (!depth) return e+1;
        }
        p++;
    }
    fprintf(stderr,"Unterminated plist element\n"); exit(1);
}
static char *extract_kext_dict(const char *plist, const char *bundle_id) {
    char needle[512]; snprintf(needle,sizeof(needle),"<key>CFBundleIdentifier</key><string>%s</string>",bundle_id);
    const char *match = strstr(plist,needle);
    if (!match) return NULL;
    const char *stack[128]; int depth = 0;
    for (const char *p=plist; p<match; p++) {
        if (!strncmp(p,"<dict>",6)) { if (depth==128) exit(1); stack[depth++]=p; }
        else if (!strncmp(p,"</dict>",7)) depth--;
    }
    if (depth<=0) return NULL;
    const char *start = stack[depth-1], *end=xml_end(start);
    size_t size=end-start; char *out=malloc(size+1);
    memcpy(out,start,size); out[size]=0; return out;
}
static char *expand_xml(const char *fragment, const char *source, int depth) {
    if (depth > 32) { fprintf(stderr,"Cyclic plist reference\n"); exit(1); }
    size_t cap=1024, n=0; char *result=malloc(cap);
    for (const char *p=fragment; *p;) {
        const char *end=p+1; char *owned=NULL; const char *chunk=p; size_t count=1;
        if (*p=='<') {
            const char *gt=strchr(p,'>'); if (!gt) exit(1);
            const char *ref=strstr(p," IDREF=\"");
            if (ref && ref<gt) {
                const char *id=ref+8, *q=strchr(id,'"');
                char needle[128]; if (!q || q-id>80) exit(1);
                snprintf(needle,sizeof(needle)," ID=\"%.*s\"",(int)(q-id),id);
                const char *def=strstr(source,needle); if (!def) { fprintf(stderr,"Missing XML ID\n"); exit(1); }
                while (def>source && *def!='<') def--;
                const char *de=xml_end(def); char *tmp=malloc(de-def+1);
                memcpy(tmp,def,de-def); tmp[de-def]=0;
                owned=expand_xml(tmp,source,depth+1); free(tmp);
                chunk=owned; count=strlen(owned); end=xml_end(p);
            } else {
                const char *id=strstr(p," ID=\"");
                end=gt+1;
                if (id && id<gt) {
                    const char *q=strchr(id+5,'"'); if (!q || q>gt) exit(1);
                    owned=malloc(end-p+1); size_t head=id-p;
                    memcpy(owned,p,head); memcpy(owned+head,q+1,end-q-1);
                    count=head+end-q-1; owned[count]=0; chunk=owned;
                } else count=end-p;
            }
        }
        if (n+count+1>cap) { cap=(n+count+1)*2; result=realloc(result,cap); }
        memcpy(result+n,chunk,count); n+=count; free(owned); p=end;
    }
    result[n]=0; return result;
}
static char *set_xml_address(char *entry,const char *key,uint64_t address) {
    char needle[128]; snprintf(needle,sizeof(needle),"<key>%s</key>",key);
    char *p=strstr(entry,needle); if (!p) { fprintf(stderr,"Missing %s\n",key); exit(1); }
    p+=strlen(needle); while (*p==' '||*p=='\n'||*p=='\t') p++;
    const char *end=xml_end(p); char value[128];
    int n=snprintf(value,sizeof(value),"<integer size=\"64\">0x%llx</integer>",(unsigned long long)address);
    size_t head=p-entry, tail=strlen(end);
    char *out=malloc(head+n+tail+1); memcpy(out,entry,head); memcpy(out+head,value,n);
    memcpy(out+head+n,end,tail+1); free(entry); return out;
}

/* Reclaim metadata space without resizing: preserve ID definitions and replace
 * repeated literal strings with references to identical existing definitions.
 * Comments are nonsemantic. No dictionaries or driver properties are dropped. */
static void compact_prelink(uint8_t *out, uint64_t off, uint64_t capacity) {
    char *xml=(char *)out+off;
    size_t old=strlen(xml), n=0;
    struct { const char *value; size_t size; char ref[96]; int fresh; char opening[96]; } defs[4096];
    unsigned count=0;
    for (const char *p=xml; (p=strstr(p,"<string ID=\"")); p++) {
        const char *id=p+12,*quote=strchr(id,'"'),*gt=strchr(p,'>');
        if (!quote || !gt || quote>gt || gt[-1]=='/') continue;
        const char *end=strstr(gt+1,"</string>");
        if (!end || quote-id>32 || count==4096) { fprintf(stderr,"Invalid string definition\n");exit(1); }
        defs[count].value=gt+1;defs[count].size=end-gt-1;
        snprintf(defs[count].ref,sizeof(defs[count].ref),"<string IDREF=\"%.*s\"/>",(int)(quote-id),id);
        defs[count].fresh=0;count++;
    }
    unsigned next_id=0;
    for (const char *p=xml; (p=strstr(p," ID=\""));p++) {
        unsigned id=(unsigned)strtoul(p+5,NULL,10);
        if (id>=next_id) next_id=id+1;
    }
    /* Intern repeated long strings that Apple left as literals in beta 2. */
    for (const char *p=xml; (p=strstr(p,"<string>"));p+=8) {
        const char *end=strstr(p+8,"</string>");if (!end) exit(1);
        size_t size=end-p-8;if (size<48) continue;
        bool known=false;
        for (unsigned i=0;i<count;i++)
            if (size==defs[i].size && !memcmp(p+8,defs[i].value,size)) { known=true;break; }
        if (known) continue;
        char *literal=malloc(size+18);memcpy(literal,p,size+17);literal[size+17]=0;
        unsigned occurrences=0;
        for (const char *q=xml; (q=strstr(q,literal));q+=size+17) occurrences++;
        free(literal);
        if (occurrences<2 || count==4096) continue;
        defs[count].value=p+8;defs[count].size=size;defs[count].fresh=1;
        snprintf(defs[count].ref,96,"<string IDREF=\"%u\"/>",next_id);
        snprintf(defs[count].opening,96,"<string ID=\"%u\">",next_id++);count++;
    }
    char *result=malloc(old*2+1);
    for (const char *p=xml; *p;) {
        if (!strncmp(p,"<!--",4)) {
            const char *end=strstr(p+4,"-->");
            if (!end) { fprintf(stderr,"Unterminated XML comment\n");exit(1); }
            p=end+3;continue;
        }
        if (!strncmp(p,"<string>",8)) {
            const char *end=strstr(p+8,"</string>");
            if (!end) { fprintf(stderr,"Unterminated string\n");exit(1); }
            size_t size=end-p-8; bool replaced=false;
            for (unsigned i=0;i<count;i++) {
                size_t r=strlen(defs[i].ref);
                if (size==defs[i].size && r<size+17 && !memcmp(p+8,defs[i].value,size)) {
                    if (defs[i].fresh) {
                        size_t head=strlen(defs[i].opening);
                        memcpy(result+n,defs[i].opening,head);n+=head;
                        memcpy(result+n,p+8,size+9);n+=size+9;defs[i].fresh=0;
                    } else { memcpy(result+n,defs[i].ref,r);n+=r; }
                    p=end+9;replaced=true;break;
                }
            }
            if (replaced) continue;
            size_t span=end+9-p;memcpy(result+n,p,span);n+=span;p=end+9;continue;
        }
        result[n++]=*p++;
    }
    result[n]=0;
    if (n>=capacity) { fprintf(stderr,"Metadata exceeds segment\n");exit(1); }
    memset(xml,0,capacity);memcpy(xml,result,n);free(result);
    printf("Reclaimed %zu bytes of prelink metadata space\n",old-n);
}

/* ---- main ---- */

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <dst_kernel> <src_kernel> <output>\n", argv[0]);
        return 1;
    }

    struct stat input_stat, output_stat;
    for (int i=1;i<=2;i++) {
        if (!stat(argv[i],&input_stat) && !stat(argv[3],&output_stat) &&
            input_stat.st_dev==output_stat.st_dev && input_stat.st_ino==output_stat.st_ino) {
            fprintf(stderr,"Output must not alias an input file\n"); return 1;
        }
    }
    /* Load files */
    FILE *f;
    struct kernel dst, src;
    memset(&dst, 0, sizeof(dst));
    memset(&src, 0, sizeof(src));

    f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END); dst.len = ftell(f); fseek(f, 0, SEEK_SET);
    dst.data = malloc(dst.len);
    if (dst.len < 32 || fread(dst.data, 1, dst.len, f) != dst.len) { fprintf(stderr,"Invalid destination read\n"); return 1; }
    fclose(f);

    f = fopen(argv[2], "rb");
    if (!f) { perror(argv[2]); return 1; }
    fseek(f, 0, SEEK_END); src.len = ftell(f); fseek(f, 0, SEEK_SET);
    src.data = malloc(src.len);
    if (src.len < 32 || fread(src.data, 1, src.len, f) != src.len) { fprintf(stderr,"Invalid source read\n"); return 1; }
    fclose(f);

    parse_kernel(&dst);
    parse_kernel(&src);

    printf("Dst kernel: %zu bytes, %d segments\n", dst.len, dst.nseg);
    printf("Src kernel: %zu bytes, %d segments\n", src.len, src.nseg);

    /* Make output as copy of dst */
    uint8_t *out = malloc(dst.len);
    memcpy(out, dst.data, dst.len);

    uint64_t pi_off_check, pi_size_check;
    char *existing = find_prelink_info(&dst,&pi_off_check,&pi_size_check);
    if (!existing || strstr(existing,"com.apple.driver.ApplePinotLCD</string>") ||
        strstr(existing,"com.apple.driver.AppleChestnutDisplayPMU</string>")) {
        fprintf(stderr,"Destination missing metadata or already contains a requested kext\n"); return 1;
    }
    /* Find source plist */
    uint64_t src_pi_off, src_pi_max;
    char *src_plist = find_prelink_info(&src, &src_pi_off, &src_pi_max);
    if (!src_plist) { fprintf(stderr, "No __PRELINK_INFO in source\n"); return 1; }

    /* Locate both kexts in source */
    struct {
        const char *bundle_id;
        const char *short_name;
        struct kext_info ki;
    } kexts[2] = {
        { "com.apple.driver.ApplePinotLCD", "ApplePinotLCD", {0} },
        { "com.apple.driver.AppleChestnutDisplayPMU", "AppleChestnutDisplayPMU", {0} }
    };

    for (int i = 0; i < 2; i++) {
        struct kext_info *ki = &kexts[i].ki;
        memset(ki, 0, sizeof(*ki));
        strncpy(ki->bundle_id, kexts[i].bundle_id, sizeof(ki->bundle_id) - 1);

        if (!find_kext_in_plist(src_plist, kexts[i].bundle_id,
                                &ki->load_addr, &ki->size,
                                &ki->source_addr, &ki->kmod_info_addr)) {
            fprintf(stderr, "Cannot find %s in source kernel\n", kexts[i].bundle_id);
            return 1;
        }

        parse_kext_segs(&src, ki->load_addr, ki);
        printf("\n%s: load=%llx size=%llx kmod=%llx segs=%d\n",
               kexts[i].short_name,
               (unsigned long long)ki->load_addr,
               (unsigned long long)ki->size,
               (unsigned long long)ki->kmod_info_addr,
               ki->nseg);
        for (int s = 0; s < ki->nseg; s++)
            printf("  %-16s vm=%llx vmsize=%llx filesize=%llx\n",
                   ki->segs[s].name,
                   (unsigned long long)ki->segs[s].vmaddr,
                   (unsigned long long)ki->segs[s].vmsize,
                   (unsigned long long)ki->segs[s].filesize);
    }

    /* Find free gaps in dst kernel */
    struct gap te_gaps[MAX_GAPS], pt_gaps[MAX_GAPS], pd_gaps[MAX_GAPS], pdc_gaps[MAX_GAPS], header_gaps[MAX_GAPS];
    int n_header = find_gaps(&dst, "__DATA", 0x100, header_gaps, MAX_GAPS);
    int n_te = find_gaps(&dst, "__PLK_TEXT_EXEC", 0x100, te_gaps, MAX_GAPS);
    int n_pt = find_gaps(&dst, "__PRELINK_TEXT", 0x40, pt_gaps, MAX_GAPS);
    int n_pd = find_gaps(&dst, "__PRELINK_DATA", 0x40, pd_gaps, MAX_GAPS);
    int n_pdc = find_gaps(&dst, "__PLK_DATA_CONST", 0x40, pdc_gaps, MAX_GAPS);

    printf("\nFree gaps: TEXT_EXEC=%d, PRELINK_TEXT=%d, PRELINK_DATA=%d, DATA_CONST=%d\n",
           n_te, n_pt, n_pd, n_pdc);

    /* Calculate AppleARMPlatform delta */
    uint64_t arm_src = find_arm_platform_addr(&src);
    uint64_t arm_dst = find_arm_platform_addr(&dst);
    if (!arm_src || !arm_dst || !matching_kext_uuid(&src,arm_src,&dst,arm_dst)) {
        fprintf(stderr,"AppleARMPlatform build UUID mismatch; cannot map private addresses\n"); return 1;
    }
    int64_t arm_delta = (int64_t)(arm_dst - arm_src);
    printf("\nAppleARMPlatform headers: src=%llx dst=%llx (header delta=%lld; mapping each segment separately)\n",
           (unsigned long long)arm_src, (unsigned long long)arm_dst, (long long)arm_delta);

    /* Parse KASLR tables */
    struct kaslr_table src_kt, dst_kt;
    if (!parse_kaslr_table(&src, &src_kt)) {
        fprintf(stderr, "Failed to parse source KASLR table\n"); return 1;
    }
    if (!parse_kaslr_table(&dst, &dst_kt)) {
        fprintf(stderr, "Failed to parse dst KASLR table\n"); return 1;
    }
    printf("KASLR offsets: src=%u dst=%u\n", src_kt.count, dst_kt.count);

    /* Place kexts */
    uint64_t used_te[4] = {0}, used_pt[4] = {0}, used_pd[4] = {0}, used_pdc[4] = {0};
    int nused_te = 0, nused_pt = 0, nused_pd = 0, nused_pdc = 0;

    uint64_t used_headers[4] = {0}; int nused_headers = 0;
    struct placement placements[2];
    uint32_t *all_new_kaslr = malloc(16384 * sizeof(uint32_t));
    int total_new_kaslr = 0;

    for (int i = 0; i < 2; i++) {
        struct kext_info *ki = &kexts[i].ki;
        struct placement *pl = &placements[i];

        /* Find __TEXT header size */
        uint64_t text_size = 0, texec_size = 0, data_size = 0, dconst_size = 0;
        for (int s = 0; s < ki->nseg; s++) {
            if (strcmp(ki->segs[s].name, "__TEXT") == 0) text_size = ki->segs[s].filesize;
            else if (strcmp(ki->segs[s].name, "__TEXT_EXEC") == 0) texec_size = ki->segs[s].filesize;
            else if (strcmp(ki->segs[s].name, "__DATA") == 0) data_size = ki->segs[s].vmsize;
            else if (strcmp(ki->segs[s].name, "__DATA_CONST") == 0) dconst_size = ki->segs[s].filesize;
        }

        printf("\n--- Placing %s ---\n", kexts[i].short_name);
        printf("  Need: TEXT=%llx TEXT_EXEC=%llx DATA=%llx DATA_CONST=%llx\n",
               (unsigned long long)text_size, (unsigned long long)texec_size,
               (unsigned long long)data_size, (unsigned long long)dconst_size);

        /* XNU writes segment/section addresses in slidePrelinkedExecutable.
         * __PLK_TEXT_EXEC is already RX then, so it cannot hold headers.
         * Kernel DATA section padding is writable and precedes kext file data,
         * preserving nonnegative embedded file offsets. */
        struct gap *g;
        g = find_best_gap(pt_gaps, n_pt, text_size, used_pt, nused_pt);
        if (g) {
            pl->text_vm = g->vmaddr;
            pl->text_fo = g->fileoff;
            used_pt[nused_pt++] = g->vmaddr;
            printf("  __TEXT -> __PRELINK_TEXT gap at %llx\n", (unsigned long long)g->vmaddr);
        } else {
            /* Use only padding outside all kernel DATA sections. */
            g = find_best_gap(header_gaps, n_header, text_size, used_headers, nused_headers);
            if (!g) { fprintf(stderr, "No gap for %s __TEXT\n", kexts[i].short_name); return 1; }
            pl->text_vm = g->vmaddr;
            pl->text_fo = g->fileoff;
            used_headers[nused_headers++] = g->vmaddr;
            printf("  __TEXT -> kernel __DATA section padding at %llx (writable fallback)\n", (unsigned long long)g->vmaddr);
        }

        /* __TEXT_EXEC */
        g = find_best_gap(te_gaps, n_te, texec_size, used_te, nused_te);
        if (!g) { fprintf(stderr, "No gap for %s __TEXT_EXEC\n", kexts[i].short_name); return 1; }
        pl->texec_vm = g->vmaddr;
        pl->texec_fo = g->fileoff;
        used_te[nused_te++] = g->vmaddr;
        printf("  __TEXT_EXEC -> gap at %llx (size %llx)\n",
               (unsigned long long)g->vmaddr, (unsigned long long)g->size);

        /* __DATA */
        g = find_best_gap(pd_gaps, n_pd, data_size, used_pd, nused_pd);
        if (!g) { fprintf(stderr, "No gap for %s __DATA\n", kexts[i].short_name); return 1; }
        pl->data_vm = g->vmaddr;
        pl->data_fo = g->fileoff;
        used_pd[nused_pd++] = g->vmaddr;
        printf("  __DATA -> gap at %llx\n", (unsigned long long)g->vmaddr);

        /* __DATA_CONST */
        g = find_best_gap(pdc_gaps, n_pdc, dconst_size, used_pdc, nused_pdc);
        /* Beta 2 lacks enough const padding for both donors. DATA padding
         * is mapped RW and can hold const data without changing outer mappings.
         * Consume the same allocator so DATA and CONST never overlap. */
        if (!g) g = find_best_gap(pd_gaps, n_pd, dconst_size, NULL, 0);
        if (!g) { fprintf(stderr, "No safe backed gap for %s __DATA_CONST\n", kexts[i].short_name); return 1; }
        pl->dconst_vm = g->vmaddr;
        pl->dconst_fo = g->fileoff;
        used_pdc[nused_pdc++] = g->vmaddr;
        printf("  __DATA_CONST -> gap at %llx\n", (unsigned long long)g->vmaddr);

        /* Copy segment data from source */
        for (int s = 0; s < ki->nseg; s++) {
            struct seg_info *seg = &ki->segs[s];
            uint64_t dst_fo = 0;

            if (strcmp(seg->name, "__TEXT") == 0) {
                /* Copy the kext Mach-O header from source */
                int64_t src_fo = vm_to_fileoff(&src, seg->vmaddr);
                if (src_fo >= 0 && seg->filesize > 0)
                    memcpy(out + pl->text_fo, src.data + src_fo, seg->filesize);
            } else if (strcmp(seg->name, "__TEXT_EXEC") == 0) {
                dst_fo = pl->texec_fo;
                copy_and_fixup_segment(out, &src, seg, dst_fo, pl->texec_vm);
            } else if (strcmp(seg->name, "__DATA") == 0) {
                dst_fo = pl->data_fo;
                /* DATA filesize might be less than vmsize (bss/common) */
                int64_t src_fo = vm_to_fileoff(&src, seg->vmaddr);
                if (src_fo >= 0 && seg->filesize > 0)
                    memcpy(out + dst_fo, src.data + src_fo, seg->filesize);
            } else if (strcmp(seg->name, "__DATA_CONST") == 0) {
                dst_fo = pl->dconst_fo;
                copy_and_fixup_segment(out, &src, seg, dst_fo, pl->dconst_vm);
            }
        }

        fixup_instructions(out, &src, &dst, ki, pl);

        /* Rewrite inner Mach-O header */
        rewrite_kext_header(out, pl->text_fo, ki, pl);

        /* Fix up pointers */
        uint32_t *new_offsets;
        int new_count;
        int fixed = fixup_pointers(out, &src, &dst, ki, pl,
                                   &src_kt, &dst_kt, arm_delta,
                                   &new_offsets, &new_count);
        printf("  Fixed %d KASLR-tracked pointers\n", fixed);

        /* Accumulate new KASLR offsets */
        for (int j = 0; j < new_count; j++)
            all_new_kaslr[total_new_kaslr++] = new_offsets[j];
        free(new_offsets);

        /* Fix kmod_info */
        int64_t kmod_fo = -1;
        /* kmod_info is in __DATA, compute its file offset in the output */
        for (int s = 0; s < ki->nseg; s++) {
            if (strcmp(ki->segs[s].name, "__DATA") == 0) {
                uint64_t kmod_inner_off = ki->kmod_info_addr - ki->segs[s].vmaddr;
                kmod_fo = (int64_t)(pl->data_fo + kmod_inner_off);
                break;
            }
        }
        if (kmod_fo >= 0) {
            fixup_kmod_info(out, kmod_fo, pl,
                            ki->segs[0].vmaddr, 0, text_size);

            uint64_t start_ptr, stop_ptr;
            memcpy(&start_ptr, out + kmod_fo + KMOD_START_OFF, 8);
            memcpy(&stop_ptr, out + kmod_fo + KMOD_STOP_OFF, 8);
            printf("  kmod_info at fo=%llx, addr=%llx start=%llx stop=%llx\n",
                   (unsigned long long)kmod_fo,
                   (unsigned long long)pl->text_vm,
                   (unsigned long long)start_ptr,
                   (unsigned long long)stop_ptr);
        }
    }

    /* ---- Update KASLR offset table ---- */
    printf("\nUpdating KASLR table: adding %d new offsets to %u existing\n",
           total_new_kaslr, dst_kt.count);

    /* Build new offset array: existing + new, sorted */
    uint32_t new_total = dst_kt.count + total_new_kaslr;
    uint32_t *merged = malloc(new_total * 4);
    memcpy(merged, dst_kt.offsets, dst_kt.count * 4);
    memcpy(merged + dst_kt.count, all_new_kaslr, total_new_kaslr * 4);

    /* Preserve the original unsorted table; append only distinct locations. */
    new_total = dst_kt.count;
    for (int i = 0; i < total_new_kaslr; i++) {
        bool exists = false;
        for (uint32_t j = 0; j < new_total; j++)
            if (merged[j] == all_new_kaslr[i]) { exists = true; break; }
        if (!exists) merged[new_total++] = all_new_kaslr[i];
    }

    /* Encode new table */
    size_t new_table_size = 4 + new_total * 4;
    uint8_t *new_table = malloc(new_table_size);
    memcpy(new_table, &new_total, 4);
    memcpy(new_table + 4, merged, new_total * 4);

    size_t new_b64_len;
    char *new_b64 = b64_encode(new_table, new_table_size, &new_b64_len);

    /* Find and replace the base64 data in the output plist */
    uint64_t dst_pi_off, dst_pi_max;
    find_prelink_info(&dst, &dst_pi_off, &dst_pi_max);

    compact_prelink(out,dst_pi_off,dst_pi_max);
    char *kaslr_key = strstr((char *)(out + dst_pi_off), "_PrelinkLinkKASLROffsets");
    if (!kaslr_key) { fprintf(stderr, "Cannot find KASLR key in dst plist\n"); return 1; }
    char *data_tag = strstr(kaslr_key, "<data");
    char *data_content = strchr(data_tag, '>') + 1;
    char *data_end = strstr(data_content, "</data>");

    size_t old_b64_len = data_end - data_content;
    if (new_b64_len > old_b64_len) {
        fprintf(stderr, "Warning: new KASLR base64 (%zu) larger than old (%zu), may need plist space\n",
                new_b64_len, old_b64_len);
        /* We have free space at end of PRELINK_INFO, shift content */
    }

    /* For safety, ensure it fits. KASLR addition is small (few hundred bytes of b64) */
    if (new_b64_len <= old_b64_len) {
        memcpy(data_content, new_b64, new_b64_len);
        /* Pad remainder with spaces (valid in XML) */
        memset(data_content + new_b64_len, ' ', old_b64_len - new_b64_len);
    } else {
        /* Need to expand - shift everything after </data> forward */
        size_t expand = new_b64_len - old_b64_len;
        size_t pi_end_off = dst_pi_off + dst_pi_max;
        size_t data_end_abs = (data_end - (char *)out);
        size_t tail_len = pi_end_off - data_end_abs;

        /* Check we have space (null padding at end of __PRELINK_INFO) */
        size_t null_at_end = 0;
        for (size_t i = pi_end_off - 1; i > dst_pi_off; i--) {
            if (out[i] != 0) break;
            null_at_end++;
        }
        if (expand > null_at_end) {
            fprintf(stderr, "Not enough space in __PRELINK_INFO for expanded KASLR table\n");
            return 1;
        }

        memmove(data_end + expand, data_end, tail_len - expand);
        memcpy(data_content, new_b64, new_b64_len);
    }

    free(new_b64);
    free(new_table);
    free(merged);

    /* ---- Inject kext entries into PRELINK_INFO plist ---- */
    printf("\nInjecting PRELINK_INFO entries...\n");

    /* Find the </array> before </dict></plist> at the end */
    char *pi_ptr = (char *)(out + dst_pi_off);
    size_t pi_len = 0;
    /* Find actual content length (before null padding) */
    for (size_t i = dst_pi_max - 1; i > 0; i--) {
        if (pi_ptr[i] != 0) { pi_len = i + 1; break; }
    }

    /* Find last </array> */
    char *last_array_end = NULL;
    char *search = pi_ptr;
    while ((search = strstr(search, "</array>")) != NULL) {
        last_array_end = search;
        search += 8;
    }

    if (!last_array_end) {
        fprintf(stderr, "Cannot find </array> in dst plist\n");
        return 1;
    }

    size_t total_insert = 0;
    char *insert_text = calloc(1,1);
    for (int i = 0; i < 2; i++) {
        struct kext_info *ki = &kexts[i].ki;
        struct placement *pl = &placements[i];
        char *orig = extract_kext_dict(src_plist,kexts[i].bundle_id);
        if (!orig) { fprintf(stderr,"Cannot extract donor metadata\n"); return 1; }
        char *entry = expand_xml(orig,src_plist,0); free(orig);
        entry = set_xml_address(entry,"_PrelinkExecutableLoadAddr",pl->text_vm);
        entry = set_xml_address(entry,"_PrelinkExecutableSourceAddr",pl->text_vm);
        uint64_t kmod = 0;
        for (int j=0;j<ki->nseg;j++)
            if (!strcmp(ki->segs[j].name,"__DATA"))
                kmod=pl->data_vm+ki->kmod_info_addr-ki->segs[j].vmaddr;
        entry = set_xml_address(entry,"_PrelinkKmodInfo",kmod);
        size_t n = strlen(entry);
        insert_text = realloc(insert_text,total_insert+n+1);
        memcpy(insert_text+total_insert,entry,n+1);
        total_insert+=n; free(entry);
    }

    /* Check space */
    size_t space_after = dst_pi_max - pi_len;
    if (total_insert > space_after) {
        fprintf(stderr, "Not enough space in __PRELINK_INFO for kext entries (%zu needed, %zu available)\n",
                total_insert, space_after);
        return 1;
    }

    /* Insert before </array> */
    size_t tail_from_array = pi_len - (last_array_end - pi_ptr);
    memmove(last_array_end + total_insert, last_array_end, tail_from_array);
    memcpy(last_array_end, insert_text, total_insert);

    free(insert_text);
    free(all_new_kaslr);
    free(src_kt.offsets);
    free(dst_kt.offsets);

    printf("Injected %zu bytes of plist entries\n", total_insert);

    /* Write output */
    size_t pathlen=strlen(argv[3]);
    char *temporary=malloc(pathlen+16);
    if (!temporary) { fprintf(stderr,"Out of memory\n");return 1; }
    snprintf(temporary,pathlen+16,"%s.tmp.XXXXXX",argv[3]);
    int fd=mkstemp(temporary);
    if (fd<0) { perror(argv[3]);free(temporary);return 1; }
    f=fdopen(fd,"wb");
    if (!f) { close(fd);unlink(temporary);free(temporary);return 1; }
    int bad=fwrite(out,1,dst.len,f)!=dst.len;
    if (fclose(f)) bad=1;
    if (bad || rename(temporary,argv[3])) {
        fprintf(stderr,"Cannot commit complete output\n");unlink(temporary);free(temporary);return 1;
    }
    free(temporary);

    printf("\nOutput written to %s (%zu bytes)\n", argv[3], dst.len);
    printf("\nPlacement summary:\n");
    for (int i = 0; i < 2; i++) {
        struct placement *pl = &placements[i];
        printf("  %s:\n", kexts[i].short_name);
        printf("    __TEXT       = %llx (fo %llx)\n", (unsigned long long)pl->text_vm, (unsigned long long)pl->text_fo);
        printf("    __TEXT_EXEC  = %llx (fo %llx)\n", (unsigned long long)pl->texec_vm, (unsigned long long)pl->texec_fo);
        printf("    __DATA       = %llx (fo %llx)\n", (unsigned long long)pl->data_vm, (unsigned long long)pl->data_fo);
        printf("    __DATA_CONST = %llx (fo %llx)\n", (unsigned long long)pl->dconst_vm, (unsigned long long)pl->dconst_fo);
    }

    free(out);
    free(dst.data);
    free(src.data);
    return 0;
}
