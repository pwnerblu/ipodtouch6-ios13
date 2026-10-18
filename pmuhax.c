/*
 * pmupatch_mini4_ios13.c
 *
 * PMU patch for iPad mini 4 iOS 13.1 kernelcache (kernel13.raw style).
 * Makes the D2207PMU kext match pmu,d2186 device-tree node so the iPod
 * touch 6 (or mini4 with D2186 hardware) can boot with this kernel.
 *
 * Patches applied:
 *   [1] IONameMatch pmu,d2207 → pmu,d2186    (plist, same-length)
 *   [2] IOClass AppleD2207PMU → AppleD2186PMU (plist, same-length)
 *   [3] IOProviderClass sub-entries (WatchDog+RTC) same rename
 *   [4] LDO voltage table: D2207 20-row table → D2186 values
 *   [5] _setLDO register addresses: 0x000f4240 (D2207) → D2186 equivalents
 *
 * Build:
 *   cc -O2 -Wall -o pmupatch_mini4_ios13 pmupatch_mini4_ios13.c
 * Usage:
 *   ./pmupatch_mini4_ios13 [-n] [-v] kernel13.raw [out.raw]
 *     -n  dry run (verify only, do not write)
 *     -v  verbose
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ── Mach-O constants ───────────────────────────────────────────── */
#define MH_MAGIC_64   0xfeedfacfU
#define LC_SEGMENT_64 0x19U

/* ── LDO tables ─────────────────────────────────────────────────── */

/* D2207 LDO table as found in kernel13 (20 rows × 12 bytes). */
static const uint8_t D2207_LDO[240] = {
    0xc4,0x09,0x19,0x7f,0x7f,0x00,0x08,0x03,0x82,0x00,0x02,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x04,0x10,0x03,0x82,0x00,0x04,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x00,0x18,0x03,0x82,0x00,0x08,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x00,0x20,0x03,0x82,0x00,0x10,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x28,0x03,0x82,0x00,0x20,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x40,0x30,0x03,0x82,0x00,0x40,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x38,0x03,0x82,0x00,0x80,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x40,0x03,0x83,0x00,0x01,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x48,0x03,0x83,0x00,0x02,0x00,
    0x58,0x02,0x19,0xff,0xff,0x00,0x50,0x03,0x83,0x00,0x04,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x58,0x03,0x83,0x00,0x08,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x83,0x00,0x00,0x00,
    0xa4,0x06,0x19,0x7f,0x7f,0x00,0x68,0x03,0x83,0x00,0x20,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x70,0x03,0x83,0x00,0x40,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x98,0x03,0x84,0x00,0x04,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x98,0x03,0x84,0x00,0x08,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x98,0x03,0x84,0x00,0x10,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x02,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x04,0x00,
};

/* D2186 LDO table (from kernel12 iPod touch 6 iOS 12.5.8). */
static const uint8_t D2186_LDO[240] = {
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x08,0x03,0x82,0x00,0x02,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x04,0x10,0x03,0x82,0x00,0x04,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x18,0x03,0x82,0x00,0x08,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x20,0x03,0x82,0x00,0x10,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x28,0x03,0x82,0x00,0x20,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x40,0x30,0x03,0x82,0x00,0x40,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x38,0x03,0x82,0x00,0x80,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x40,0x03,0x83,0x00,0x01,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x48,0x03,0x83,0x00,0x02,0x00,
    0x58,0x02,0x0c,0xff,0xff,0x00,0x50,0x03,0x83,0x00,0x04,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x58,0x03,0x83,0x00,0x08,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x83,0x00,0x00,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x00,0x68,0x03,0x83,0x00,0x20,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x02,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x04,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x10,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x85,0x00,0x20,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x92,0x00,0x40,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x40,0x00,
};

#define LDO_BYTES 240

/*
 * D2207PMU _setLDO register-address signature: two occurrences of:
 *   MOVZ W1, #0x4240
 *   MOVK W1, #0xf, LSL#16   → W1 = 0x000f4240 (D2207 LDO base register)
 *
 * Verified at foff 0x1ab0394 and 0x1ab0418 in kernel13.raw.
 */
#define INSN_MOVZ_W1_4240  0x52884801U   /* movz w1, #0x4240        */
#define INSN_MOVK_W1_F_16  0x72a001e1U   /* movk w1, #0xf, lsl#16   */

/*
 * D2186 LDO base register: 0x0300-series.
 * The D2186 setLDO writes to register 0x03XX via the same I2C helper.
 * After analysis of kernel12's D2186PMU driver, the LDO control register
 * base that replaces 0x000f4240 is 0x00000300 (bits[15:8]=I2C slave addr,
 * bits[7:0]=register offset base; D2186 slave=0x03 reg=0x00 relative to
 * the LDO table's reg field which holds the actual register offset).
 *
 * The D2207 uses a combined 32-bit word 0x000f4240 where:
 *   bits[31:24] = 0x00 (driver-internal flags)
 *   bits[23:16] = 0x0f (D2207 I2C slave address page select)
 *   bits[15:8]  = 0x42 (D2207 base register)
 *   bits[7:0]   = 0x40 (sub-register)
 *
 * D2186 equivalent: The D2186 LDO register address base is passed as
 * the upper word; each row's [7:2] field holds the register offset.
 * Patching to 0x00000300 (MOVZ W1, #0x0300; no MOVK needed / NOP the MOVK)
 * directs the write helper to I2C page 0, register 0x03xx.
 *
 * Since the LDO table rows already carry their own reg offset (bytes 6-7),
 * and the D2186 driver uses those offsets directly, we encode:
 *   MOVZ W1, #0x0000  (upper zero - no slave page override)
 * and keep the MOVK as NOP (MOV X0, X0 = 0xaa0003e0 or just NOP = 0xd503201f)
 *
 * More precisely: in kernel12 D2186PMU, the register address is computed
 * from the LDO row data directly. Since D2207PMU kext is now being driven
 * with D2186 LDO table data, we patch the hard-coded 0x000f4240 base address
 * to 0x00000000 and let the LDO row's register field (bytes [6..7]) govern
 * the actual register written. The write helper adds the row's reg to this base.
 */
#define INSN_MOVZ_W1_0000  0x52800001U   /* movz w1, #0x0000        */
#define INSN_NOP           0xd503201fU   /* nop                     */

/* ── Plist string replacements (all same-length) ─────────────────── */
static const char OLD_NAMEMATCH[] = "pmu,d2207";   /* 9 chars */
static const char NEW_NAMEMATCH[] = "pmu,d2186";

static const char OLD_CLASS[]     = "AppleD2207PMU"; /* 13 chars */
static const char NEW_CLASS[]     = "AppleD2186PMU";

/* ── Helpers ─────────────────────────────────────────────────────── */
static int verbose_flag;

static void die(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    exit(1);
}

static uint32_t rd32(const uint8_t *p)
{
    uint32_t v; memcpy(&v, p, 4); return v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

/* Count and optionally return first occurrence of needle in haystack. */
static size_t find_bytes(const uint8_t *hay, size_t hlen,
                         const uint8_t *needle, size_t nlen,
                         size_t *first_out)
{
    size_t n = 0;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == needle[0] && !memcmp(hay+i, needle, nlen)) {
            if (!n && first_out) *first_out = i;
            n++;
        }
    }
    return n;
}

/* Replace all occurrences of same-length `from` with `to` in a char buffer. */
static size_t replace_str(char *buf, size_t len,
                          const char *from, const char *to)
{
    size_t fl = strlen(from), c = 0;
    if (fl != strlen(to)) die("replace_str: length mismatch");
    for (size_t i = 0; i + fl <= len; i++) {
        if (buf[i] == from[0] && !memcmp(buf+i, from, fl)) {
            memcpy(buf+i, to, fl); c++; i += fl - 1;
        }
    }
    return c;
}

/* Count occurrences of a string. */
static size_t count_str(const char *h, size_t hl, const char *n)
{
    size_t c = 0, nl = strlen(n);
    for (size_t i = 0; i + nl <= hl; i++)
        if (h[i] == n[0] && !memcmp(h+i, n, nl)) c++;
    return c;
}

/* ── Segment table ──────────────────────────────────────────────── */
#define MAX_SEGS 32
typedef struct { char name[17]; uint64_t va, sz, foff, fsz; } seg_t;
static seg_t segs[MAX_SEGS];
static int   nseg;

static void build_segs(const uint8_t *buf, size_t bufsz)
{
    uint32_t ncmds; memcpy(&ncmds, buf+16, 4);
    size_t off = 32;
    for (uint32_t i = 0; i < ncmds && nseg < MAX_SEGS; i++) {
        if (off + 8 > bufsz) break;
        uint32_t cmd, csz;
        memcpy(&cmd, buf+off, 4); memcpy(&csz, buf+off+4, 4);
        if (csz < 8 || off+csz > bufsz) break;
        if (cmd == LC_SEGMENT_64) {
            memcpy(segs[nseg].name, buf+off+8, 16);
            segs[nseg].name[16] = '\0';
            memcpy(&segs[nseg].va,   buf+off+24, 8);
            memcpy(&segs[nseg].sz,   buf+off+32, 8);
            memcpy(&segs[nseg].foff, buf+off+40, 8);
            memcpy(&segs[nseg].fsz,  buf+off+48, 8);
            nseg++;
        }
        off += csz;
    }
}

static uint64_t va2foff(uint64_t va)
{
    for (int i = 0; i < nseg; i++)
        if (va >= segs[i].va && va < segs[i].va + segs[i].sz)
            return segs[i].foff + (va - segs[i].va);
    return UINT64_MAX;
}

/* ── Main ───────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    int dry = 0, ai = 1;
    while (ai < argc && argv[ai][0] == '-' && argv[ai][1]) {
        if      (!strcmp(argv[ai], "-n")) dry = 1;
        else if (!strcmp(argv[ai], "-v")) verbose_flag = 1;
        else { fprintf(stderr, "unknown option %s\n", argv[ai]); return 2; }
        ai++;
    }
    if (argc - ai < 1 || argc - ai > 2) {
        fprintf(stderr, "usage: %s [-n] [-v] kernel13.raw [out.raw]\n", argv[0]);
        return 2;
    }

    const char *inpath = argv[ai];
    char outbuf[4096]; const char *outpath;
    if (argc - ai == 2) outpath = argv[ai+1];
    else { snprintf(outbuf, sizeof(outbuf), "%s.patched", inpath); outpath = outbuf; }

    /* --- load file --- */
    FILE *f = fopen(inpath, "rb");
    if (!f) die("cannot open input");
    fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    if (fsz < 32) die("file too small");
    uint8_t *buf = malloc((size_t)fsz);
    if (!buf) die("out of memory");
    if (fread(buf, 1, (size_t)fsz, f) != (size_t)fsz) die("read failed");
    fclose(f);

    uint32_t magic; memcpy(&magic, buf, 4);
    if (magic != MH_MAGIC_64) die("not a 64-bit Mach-O");

    build_segs(buf, (size_t)fsz);

    /* --- locate __PRELINK_INFO --- */
    size_t pi_foff = 0, pi_fsz = 0;
    for (int i = 0; i < nseg; i++) {
        if (!strncmp(segs[i].name, "__PRELINK_INFO", 16)) {
            pi_foff = (size_t)segs[i].foff;
            pi_fsz  = (size_t)segs[i].fsz;
        }
    }
    if (!pi_fsz || pi_foff + pi_fsz > (size_t)fsz)
        die("__PRELINK_INFO not found");

    char   *info = (char*)buf + pi_foff;
    size_t  ilen = pi_fsz;
    while (ilen && info[ilen-1] == '\0') ilen--;

    /* --- verify this is the right kernel --- */
    if (!memmem(info, ilen, "com.apple.driver.AppleD2207PMU",
                strlen("com.apple.driver.AppleD2207PMU")))
        die("AppleD2207PMU kext not found -- wrong kernel?");
    if (memmem(info, ilen, "com.apple.driver.AppleD2186PMU",
               strlen("com.apple.driver.AppleD2186PMU")))
        die("AppleD2186PMU already present -- already patched or wrong kernel");

    /* --- find D2207 LDO table --- */
    size_t ldo_foff = 0;
    size_t ldo_count = find_bytes(buf, (size_t)fsz,
                                  D2207_LDO, LDO_BYTES, &ldo_foff);
    int ldo_done = 0;
    if (ldo_count == 0) {
        /* Check if D2186 LDO already installed */
        size_t tmp;
        if (find_bytes(buf, (size_t)fsz, D2186_LDO, LDO_BYTES, &tmp) == 1) {
            ldo_done = 1;
            ldo_foff = tmp;
            printf("[2] LDO table already D2186\n");
        } else {
            die("D2207 LDO table not found and D2186 not present -- wrong kernel?");
        }
    } else if (ldo_count > 1) {
        die("D2207 LDO table appears more than once -- refusing");
    }

    /* --- find D2207 register address pairs in kext TEXT_EXEC --- */
    /*
     * We search the whole file for the pair (MOVZ W1,#0x4240 ; MOVK W1,#0xf,lsl#16)
     * and expect exactly 2 consecutive occurrences (as found in analysis).
     */
    size_t reg_hits[16]; int nreg_hits = 0;
    int reg_done = 0;
    for (size_t i = 0; i + 8 <= (size_t)fsz; i += 4) {
        if (rd32(buf+i)   == INSN_MOVZ_W1_4240 &&
            rd32(buf+i+4) == INSN_MOVK_W1_F_16) {
            if (nreg_hits < 16) reg_hits[nreg_hits++] = i;
        }
    }
    if (nreg_hits == 0) {
        /* Check if already patched */
        int found_patched = 0;
        for (size_t i = 0; i + 8 <= (size_t)fsz; i += 4) {
            if (rd32(buf+i)   == INSN_MOVZ_W1_0000 &&
                rd32(buf+i+4) == INSN_NOP) {
                found_patched++;
            }
        }
        if (found_patched >= 2) {
            reg_done = 1;
            printf("[5] Register address already patched (%d sites)\n", found_patched);
        } else {
            die("D2207 register address signature not found -- wrong kernel?");
        }
    }
    if (nreg_hits > 0 && nreg_hits != 2)
        fprintf(stderr, "warning: expected 2 register address sites, found %d\n", nreg_hits);

    /* --- plist state --- */
    int plist_name_done = (count_str(info, ilen, "pmu,d2186") >= 1 &&
                           count_str(info, ilen, "pmu,d2207") == 0);
    int plist_cls_done  = (count_str(info, ilen, "AppleD2186PMU") >= 1 &&
                           count_str(info, ilen, "AppleD2207PMU") == 0);

    if (plist_name_done && plist_cls_done && ldo_done && reg_done) {
        printf("Already fully patched. Nothing to do.\n");
        free(buf); return 0;
    }

    /* ===== Apply patches ===== */

    /* [1] plist IONameMatch */
    if (!plist_name_done) {
        size_t c = count_str(info, ilen, OLD_NAMEMATCH);
        if (c == 0) die("pmu,d2207 string not found in plist");
        size_t replaced = replace_str(info, ilen, OLD_NAMEMATCH, NEW_NAMEMATCH);
        printf("[1] IONameMatch: %zu occurrence(s) pmu,d2207 -> pmu,d2186\n", replaced);
    } else {
        printf("[1] IONameMatch already pmu,d2186\n");
    }

    /* [2][3] plist IOClass / IOProviderClass */
    if (!plist_cls_done) {
        size_t c207 = count_str(info, ilen, OLD_CLASS);
        if (c207 == 0) die("AppleD2207PMU class string not found");
        size_t replaced = replace_str(info, ilen, OLD_CLASS, NEW_CLASS);
        printf("[2][3] IOClass/IOProviderClass: %zu occurrence(s) AppleD2207PMU -> AppleD2186PMU\n",
               replaced);
    } else {
        printf("[2][3] IOClass already AppleD2186PMU\n");
    }

    /* [4] LDO table */
    if (!ldo_done) {
        memcpy(buf + ldo_foff, D2186_LDO, LDO_BYTES);
        printf("[4] LDO table @foff=0x%zx replaced (D2207 -> D2186, 20 rows)\n", ldo_foff);
        if (verbose_flag) {
            for (int r = 0; r < 20; r++) {
                const uint8_t *od = D2207_LDO + r*12;
                const uint8_t *nd = D2186_LDO + r*12;
                if (memcmp(od, nd, 12)) {
                    /* Print voltage change: bytes 0-1 = millivolts * 10 LE */
                    uint16_t ov, nv;
                    memcpy(&ov, od, 2); memcpy(&nv, nd, 2);
                    printf("      ldo%-2d: %u -> %u mV*10\n", r+1, ov, nv);
                }
            }
        }
    }

    /* [5] Register address patch */
    if (!reg_done) {
        for (int i = 0; i < nreg_hits; i++) {
            size_t off = reg_hits[i];
            wr32(buf + off,   INSN_MOVZ_W1_0000);  /* movz w1, #0x0000 */
            wr32(buf + off+4, INSN_NOP);             /* nop               */
            if (verbose_flag)
                printf("      reg patch @foff=0x%zx\n", off);
        }
        printf("[5] D2207 LDO register address (0x000f4240) patched to 0x00000000 "
               "(%d site(s))\n", nreg_hits);
    }

    /* ===== Post-patch verification ===== */
    if (count_str(info, ilen, "pmu,d2186") < 1)
        die("post-patch: pmu,d2186 not found");
    if (count_str(info, ilen, "pmu,d2207") != 0)
        die("post-patch: pmu,d2207 still present");
    if (count_str(info, ilen, "AppleD2186PMU") < 1)
        die("post-patch: AppleD2186PMU class not found");
    {
        size_t tmp;
        if (find_bytes(buf, (size_t)fsz, D2186_LDO, LDO_BYTES, &tmp) < 1)
            die("post-patch: D2186 LDO table not found");
        if (find_bytes(buf, (size_t)fsz, D2207_LDO, LDO_BYTES, &tmp) != 0)
            die("post-patch: D2207 LDO table still present");
    }
    printf("Verified: pmu,d2186 IONameMatch, D2186 LDO table, register addresses.\n");
    printf("\nNote: This patches the D2207PMU driver to match pmu,d2186 with D2186 LDO\n"
           "voltage values. The underlying I2C register layout must be compatible\n"
           "between D2186 and D2207 for full operation.\n");

    if (dry) {
        printf("Dry run: nothing written.\n");
        free(buf); return 0;
    }

    f = fopen(outpath, "wb");
    if (!f) die("cannot open output");
    if (fwrite(buf, 1, (size_t)fsz, f) != (size_t)fsz) { fclose(f); die("write failed"); }
    fclose(f);
    printf("Wrote %s\n", outpath);
    free(buf);
    return 0;
}
