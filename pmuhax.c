/*
 * pmupatch_mini4_ios13.c
 *
 * PMU compatibility patch: iPad mini 4 iOS 13.1 kernelcache.
 *
 * Background
 * ----------
 * iPad mini 4 (J96/J97) uses a Dialog D2186 PMU — same silicon as iPod touch 6.
 * The iOS 13.1 kernelcache ships AppleD2207PMU with IONameMatch "pmu,d2207", but
 * the device tree publishes the PMU node as "pmu,d2186".  No driver matches →
 * kernel panic at boot.
 *
 * Kext architecture in kernel13
 * -----------------------------
 * com.apple.driver.AppleDialogPMU
 *   LoadAddr  = 0xfffffff005f85d00  (in __PRELINK_TEXT)
 *   TEXT_EXEC = VA 0xfffffff006db1000, sz 0xa32c  (in __PLK_TEXT_EXEC)
 *   _setLDO lives here; hard-codes D2207 I2C cmd 0x000f4240 at two sites.
 *
 * com.apple.driver.AppleD2207PMU
 *   Plist-only subclass sharing AppleDialogPMU's LoadAddr.
 *   IOKitPersonality: IONameMatch = "pmu,d2207"
 *
 * Patches applied
 * ---------------
 *  [1]  Plist: IONameMatch  "pmu,d2207" → "pmu,d2186"
 *       NOTE: IOClass/IOProviderClass "AppleD2207PMU" strings are NOT changed.
 *       AppleD2207PMU is the compiled C++ class in kernel13; renaming it to
 *       AppleD2186PMU (which does not exist in kernel13) causes a boot panic
 *       "couldn't alloc class AppleD2186PMU". Only the device-tree match string
 *       needs to change — the runtime class stays AppleD2207PMU.
 *  [2]  LDO voltage table @ __PRELINK_TEXT foff 0xc86478:
 *           D2207 values → D2186 values (20 rows × 12 bytes)
 *  [3]  _setLDO I2C register command (in AppleDialogPMU TEXT_EXEC, 2 sites):
 *           MOVZ W1, #0x4240 / MOVK W1, #0xf, lsl#16  (= 0x000f4240, D2207)
 *         → MOVZ W1, #0x0308 / NOP                     (= 0x00000308, D2186)
 *
 * Build:
 *   cc -O2 -Wall -o pmupatch_mini4_ios13 pmupatch_mini4_ios13.c
 * Usage:
 *   ./pmupatch_mini4_ios13 [-n] [-v] [-B] kernel13.raw [out.raw]
 *     -n  dry run
 *     -v  verbose
 *     -B  skip patch [3] (register address)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MH_MAGIC_64   0xfeedfacfU
#define LC_SEGMENT_64 0x19U

/* ── LDO tables (20 rows × 12 bytes) ────────────────────────────── */
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
#define LDO_BYTES 240u

/* ── _setLDO register-address instruction signatures ─────────────── */
/*
 * D2207 I2C LDO command word: page=0x0f, reg_base=0x4240 → W1 = 0x000f4240
 *   MOVZ W1, #0x4240          0x52884801
 *   MOVK W1, #0x000f, LSL#16  0x72a001e1
 *
 * D2186 replacement: page=0x03, reg_base=0x08 → W1 = 0x00000308
 *   MOVZ W1, #0x0308  = 0x52806101
 *   NOP               = 0xd503201f
 *
 * Two sites in AppleDialogPMU TEXT_EXEC, verified by context guards:
 *   Site 0: instructions at [-3,-2,-1] = {0xd63f0100, 0x9100c3e2, 0x52800a00}
 *   Site 1: instructions at [-3,-2,-1] = {0x94001964, 0x9100c3e2, 0x52807d00}
 */
#define INSN_MOVZ_W1_4240  0x52884801u
#define INSN_MOVK_W1_F16   0x72a001e1u
#define INSN_MOVZ_W1_0308  0x52806101u
#define INSN_NOP           0xd503201fu

static const uint32_t CTX_SITE0[3] = { 0xd63f0100u, 0x9100c3e2u, 0x52800a00u };
static const uint32_t CTX_SITE1[3] = { 0x94001964u, 0x9100c3e2u, 0x52807d00u };

/* ── Plist replacements (same byte length) ───────────────────────── */
static const char OLD_NAMEMATCH[] = "pmu,d2207";
static const char NEW_NAMEMATCH[] = "pmu,d2186";
/* NOTE: IOClass "AppleD2207PMU" is NOT renamed. It is a compiled C++ class
 * that exists in kernel13. There is no compiled AppleD2186PMU in kernel13. */

/* ── Utility ─────────────────────────────────────────────────────── */
static int verbose_flag;
static void die(const char *m) { fprintf(stderr,"error: %s\n",m); exit(1); }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static void     wr32(uint8_t *p, uint32_t v) { memcpy(p,&v,4); }

static size_t count_bytes(const uint8_t *h,size_t hl,
                          const uint8_t *n,size_t nl,size_t *first)
{
    size_t c=0;
    for(size_t i=0;i+nl<=hl;i++)
        if(h[i]==n[0]&&!memcmp(h+i,n,nl)){if(!c&&first)*first=i;c++;}
    return c;
}
static size_t count_str(const char *h,size_t hl,const char *n)
{
    size_t c=0,nl=strlen(n);
    for(size_t i=0;i+nl<=hl;i++) if(h[i]==n[0]&&!memcmp(h+i,n,nl))c++;
    return c;
}
static size_t replace_str(char *b,size_t len,const char *from,const char *to)
{
    size_t fl=strlen(from),c=0;
    if(fl!=strlen(to)) die("replace_str: length mismatch");
    for(size_t i=0;i+fl<=len;i++)
        if(b[i]==from[0]&&!memcmp(b+i,from,fl)){memcpy(b+i,to,fl);c++;i+=fl-1;}
    return c;
}

/* ── Segment table ───────────────────────────────────────────────── */
#define MAX_SEGS 32
typedef struct{char name[17];uint64_t va,sz,foff,fsz;}seg_t;
static seg_t segs[MAX_SEGS]; static int nseg;

static void build_segs(const uint8_t *buf, size_t bufsz)
{
    uint32_t nc; memcpy(&nc,buf+16,4);
    size_t off=32;
    for(uint32_t i=0;i<nc&&nseg<MAX_SEGS;i++){
        if(off+8>bufsz)break;
        uint32_t cmd,csz; memcpy(&cmd,buf+off,4); memcpy(&csz,buf+off+4,4);
        if(csz<8||off+csz>bufsz)break;
        if(cmd==LC_SEGMENT_64){
            memcpy(segs[nseg].name,buf+off+8,16); segs[nseg].name[16]='\0';
            memcpy(&segs[nseg].va,  buf+off+24,8);
            memcpy(&segs[nseg].sz,  buf+off+32,8);
            memcpy(&segs[nseg].foff,buf+off+40,8);
            memcpy(&segs[nseg].fsz, buf+off+48,8);
            nseg++;
        }
        off+=csz;
    }
}

static uint64_t va2foff(uint64_t va)
{
    for(int i=0;i<nseg;i++)
        if(va>=segs[i].va&&va<segs[i].va+segs[i].sz)
            return segs[i].foff+(va-segs[i].va);
    return UINT64_MAX;
}

/*
 * find_dialog_text_exec(): locate AppleDialogPMU's TEXT_EXEC.
 *
 * The plist may contain multiple kexts near "AppleDialogPMU" strings
 * (IDREF de-duplication). We search for the canonical CFBundleIdentifier
 * string and then scan FORWARD from that point for
 * _PrelinkExecutableLoadAddr, avoiding false-positive backward matches.
 */
static int find_dialog_text_exec(const uint8_t *buf, size_t bufsz,
                                 uint64_t *tx_foff_out, uint64_t *tx_sz_out)
{
    /* Find __PRELINK_INFO */
    size_t pi_fo=0; uint64_t pi_fs=0;
    for(int i=0;i<nseg;i++)
        if(!strncmp(segs[i].name,"__PRELINK_INFO",16))
            {pi_fo=(size_t)segs[i].foff; pi_fs=segs[i].fsz;}
    if(!pi_fs){fprintf(stderr,"error: __PRELINK_INFO missing\n");return 0;}

    const char *info=(const char*)buf+pi_fo;
    size_t ilen=(size_t)pi_fs;
    while(ilen&&info[ilen-1]=='\0')ilen--;

    /*
     * Find the AppleDialogPMU entry by locating its CFBundleIdentifier.
     * Search for the canonical key/value pair to avoid IDREF false hits.
     */
    static const char DLG_BID[] =
        "<key>CFBundleIdentifier</key>"
        "<string>com.apple.driver.AppleDialogPMU</string>";
    const char *bid_hit = NULL;
    for(size_t i=0; i+strlen(DLG_BID)<=ilen; i++)
        if(!memcmp(info+i, DLG_BID, strlen(DLG_BID))){bid_hit=info+i; break;}
    if(!bid_hit){
        fprintf(stderr,"error: AppleDialogPMU CFBundleIdentifier not found\n");
        return 0;
    }

    /* Scan FORWARD up to 8 KB for _PrelinkExecutableLoadAddr */
    size_t fwd_len = ilen-(size_t)(bid_hit-info);
    if(fwd_len>8192) fwd_len=8192;
    static const char LA_KEY[] = "_PrelinkExecutableLoadAddr</key>";
    const char *la = NULL;
    for(size_t i=0; i+strlen(LA_KEY)<=fwd_len; i++)
        if(!memcmp(bid_hit+i, LA_KEY, strlen(LA_KEY))){la=bid_hit+i+strlen(LA_KEY); break;}

    /* If not found forward, also try 4 KB backward (some plist orderings) */
    if(!la){
        size_t bwd_start=(size_t)(bid_hit-info)>4096?(size_t)(bid_hit-info)-4096:0;
        const char *bwd=info+bwd_start;
        size_t bwd_len=(size_t)(bid_hit-bwd);
        const char *p=bwd;
        while(p+strlen(LA_KEY)<=(bwd+bwd_len))
            if(!memcmp(p,LA_KEY,strlen(LA_KEY))){la=p+strlen(LA_KEY);p+=strlen(LA_KEY);}
            else p++;
        /* la now points to the LAST occurrence before bid_hit */
    }
    if(!la){fprintf(stderr,"error: _PrelinkExecutableLoadAddr not found for DialogPMU\n");return 0;}

    const char *gt=memchr(la,'>',512);
    if(!gt){fprintf(stderr,"error: bad integer tag\n");return 0;}
    char *ep; uint64_t load_addr=strtoull(gt+1,&ep,0);
    if(ep==gt+1){fprintf(stderr,"error: bad load addr value\n");return 0;}
    printf("[*] AppleDialogPMU _PrelinkExecutableLoadAddr = 0x%llx\n",
           (unsigned long long)load_addr);

    /* Map to file offset */
    uint64_t kfo=va2foff(load_addr);
    if(kfo==UINT64_MAX||kfo+64>bufsz){
        fprintf(stderr,"error: cannot map DialogPMU load addr\n");return 0;}

    /* Parse embedded Mach-O for __TEXT_EXEC */
    const uint8_t *km=buf+kfo;
    uint32_t km_magic; memcpy(&km_magic,km,4);
    if(km_magic!=MH_MAGIC_64){
        fprintf(stderr,"error: bad kext Mach-O magic %#x\n",km_magic);return 0;}
    uint32_t knc; memcpy(&knc,km+16,4);
    size_t koff=32;
    for(uint32_t i=0;i<knc;i++){
        if(koff+8>0x8000)break;
        uint32_t kcmd,kcsz; memcpy(&kcmd,km+koff,4); memcpy(&kcsz,km+koff+4,4);
        if(kcsz<8||koff+kcsz>0x8000)break;
        if(kcmd==LC_SEGMENT_64){
            char sn[17]; memcpy(sn,km+koff+8,16); sn[16]='\0';
            if(!strncmp(sn,"__TEXT_EXEC",16)){
                uint64_t kva,kvs;
                memcpy(&kva,km+koff+24,8); memcpy(&kvs,km+koff+32,8);
                uint64_t txfo=va2foff(kva);
                if(txfo==UINT64_MAX){
                    fprintf(stderr,"error: cannot map DialogPMU TEXT_EXEC VA\n");return 0;}
                printf("[*] AppleDialogPMU __TEXT_EXEC VA=0x%llx sz=0x%llx foff=0x%llx\n",
                       (unsigned long long)kva,(unsigned long long)kvs,(unsigned long long)txfo);
                *tx_foff_out=txfo; *tx_sz_out=kvs;
                return 1;
            }
        }
        koff+=kcsz;
    }
    fprintf(stderr,"error: AppleDialogPMU __TEXT_EXEC segment not found\n");
    return 0;
}

/* ── Main ────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    int dry=0,no_reg=0,ai=1;
    while(ai<argc&&argv[ai][0]=='-'&&argv[ai][1]){
        if     (!strcmp(argv[ai],"-n"))dry=1;
        else if(!strcmp(argv[ai],"-v"))verbose_flag=1;
        else if(!strcmp(argv[ai],"-B"))no_reg=1;
        else{fprintf(stderr,"unknown option %s\n",argv[ai]);return 2;}
        ai++;
    }
    if(argc-ai<1||argc-ai>2){
        fprintf(stderr,"usage: %s [-n] [-v] [-B] kernel13.raw [out.raw]\n",argv[0]);
        return 2;
    }
    const char *inpath=argv[ai];
    char obuf[4096]; const char *outpath;
    if(argc-ai==2) outpath=argv[ai+1];
    else{snprintf(obuf,sizeof(obuf),"%s.patched",inpath);outpath=obuf;}

    /* Load */
    FILE *f=fopen(inpath,"rb");
    if(!f)die("cannot open input");
    fseek(f,0,SEEK_END); long fl=ftell(f); fseek(f,0,SEEK_SET);
    if(fl<32)die("file too small");
    size_t fsz=(size_t)fl;
    uint8_t *buf=malloc(fsz);
    if(!buf)die("out of memory");
    if(fread(buf,1,fsz,f)!=fsz)die("read failed");
    fclose(f);

    uint32_t magic; memcpy(&magic,buf,4);
    if(magic!=MH_MAGIC_64)die("not a 64-bit little-endian Mach-O");
    build_segs(buf,fsz);

    /* PRELINK_INFO */
    size_t pi_foff=0,pi_fsz=0;
    for(int i=0;i<nseg;i++)
        if(!strncmp(segs[i].name,"__PRELINK_INFO",16))
            {pi_foff=(size_t)segs[i].foff;pi_fsz=(size_t)segs[i].fsz;}
    if(!pi_fsz)die("__PRELINK_INFO not found");
    char *info=(char*)buf+pi_foff;
    size_t ilen=pi_fsz;
    while(ilen&&info[ilen-1]=='\0')ilen--;

    /* Identity check */
    if(!memmem(info,ilen,"com.apple.driver.AppleD2207PMU",30))
        die("AppleD2207PMU not found -- wrong kernel?");
    if(memmem(info,ilen,"com.apple.driver.AppleD2186PMU",30))
        die("AppleD2186PMU already present -- already patched or wrong kernel");

    /* Locate AppleDialogPMU TEXT_EXEC */
    uint64_t dlg_tx_foff=0,dlg_tx_sz=0;
    int have_dlg=find_dialog_text_exec(buf,fsz,&dlg_tx_foff,&dlg_tx_sz);

    /* ── Assess current state ── */

    /* [4] LDO table */
    size_t ldo_foff=0;
    size_t n207=count_bytes(buf,fsz,D2207_LDO,LDO_BYTES,&ldo_foff);
    size_t n186_tmp; {size_t t;n186_tmp=count_bytes(buf,fsz,D2186_LDO,LDO_BYTES,&t);}
    int ldo_done=(n207==0&&n186_tmp>=1);
    if(!ldo_done&&n207==0)die("D2207 LDO table not found -- wrong kernel?");
    if(!ldo_done&&n207>1) die("D2207 LDO table appears >1 time -- refusing");

    /* [5] Register address sites in AppleDialogPMU TEXT_EXEC */
    size_t reg_sites[4]; int nreg=0,reg_done=0;
    if(!no_reg&&have_dlg){
        size_t lo=(size_t)dlg_tx_foff, hi=(size_t)(dlg_tx_foff+dlg_tx_sz);
        for(size_t i=lo; i+8<=hi&&i+8<=fsz; i+=4){
            if(rd32(buf+i)==INSN_MOVZ_W1_4240&&rd32(buf+i+4)==INSN_MOVK_W1_F16){
                if(nreg<4)reg_sites[nreg++]=i;
            }
        }
        if(nreg==0){
            int np=0;
            for(size_t i=lo;i+8<=hi&&i+8<=fsz;i+=4)
                if(rd32(buf+i)==INSN_MOVZ_W1_0308&&rd32(buf+i+4)==INSN_NOP)np++;
            if(np>=2){reg_done=1;}
            else{fprintf(stderr,"warning: reg addr sig not found in DialogPMU; skipping [5]\n");no_reg=1;}
        } else if(nreg!=2){
            fprintf(stderr,"warning: expected 2 reg sites, found %d\n",nreg);
        }
    }

    int pname_done=(count_str(info,ilen,"pmu,d2186")>=1&&count_str(info,ilen,"pmu,d2207")==0);

    if(pname_done&&ldo_done&&(no_reg||reg_done)){
        printf("Already fully patched. Nothing to do.\n");
        free(buf);return 0;
    }

    /* ===== Apply ===== */

    if(!pname_done){
        size_t c=replace_str(info,ilen,OLD_NAMEMATCH,NEW_NAMEMATCH);
        printf("[1] IONameMatch: %zu pmu,d2207 -> pmu,d2186\n",c);
    } else printf("[1] IONameMatch already pmu,d2186\n");

    if(!ldo_done){
        memcpy(buf+ldo_foff,D2186_LDO,LDO_BYTES);
        printf("[2] LDO table @foff=0x%zx: D2207 -> D2186 voltages\n",ldo_foff);
        if(verbose_flag){
            for(int r=0;r<20;r++){
                if(memcmp(D2207_LDO+r*12,D2186_LDO+r*12,12)){
                    uint16_t ov,nv;
                    memcpy(&ov,D2207_LDO+r*12,2);memcpy(&nv,D2186_LDO+r*12,2);
                    printf("      ldo%-2d: %u -> %u (x10 mV)\n",r+1,ov,nv);
                }
            }
        }
    } else printf("[2] LDO table already D2186\n");

    if(!no_reg&&!reg_done){
        const uint32_t *ctxs[2]={(const uint32_t*)CTX_SITE0,(const uint32_t*)CTX_SITE1};
        int patched=0;
        for(int i=0;i<nreg;i++){
            size_t s=reg_sites[i];
            if(s<12){fprintf(stderr,"warning: site %d too close to start\n",i);continue;}
            /* Verify 3-word context guard */
            int ok=1;
            for(int j=0;j<3;j++){
                uint32_t got=rd32(buf+s-(size_t)(3-j)*4);
                if(got!=ctxs[i<2?i:1][j]){
                    fprintf(stderr,
                      "warning: ctx mismatch site %d [-%d]: got 0x%08x expected 0x%08x\n",
                      i,3-j,got,ctxs[i<2?i:1][j]);
                    ok=0; break;
                }
            }
            if(!ok)continue;
            wr32(buf+s,  INSN_MOVZ_W1_0308);
            wr32(buf+s+4,INSN_NOP);
            patched++;
            if(verbose_flag)
                printf("      reg site %d @foff=0x%zx: 0x000f4240 -> 0x00000308\n",i,s);
        }
        printf("[3] _setLDO I2C reg addr: 0x000f4240 -> 0x00000308 (%d/%d site(s))\n",
               patched,nreg);
    } else if(no_reg){
        printf("[3] -B: register address patch skipped\n");
    } else {
        printf("[3] Register address already patched\n");
    }

    /* ===== Verify ===== */
    if(count_str(info,ilen,"pmu,d2186")<1)   die("post: pmu,d2186 missing");
    if(count_str(info,ilen,"pmu,d2207")!=0)  die("post: pmu,d2207 still present");
    /* IOClass "AppleD2207PMU" intentionally retained — it is the compiled class */
    {size_t t;
     if(count_bytes(buf,fsz,D2186_LDO,LDO_BYTES,&t)<1)die("post: D2186 LDO missing");
     if(count_bytes(buf,fsz,D2207_LDO,LDO_BYTES,&t)!=0)die("post: D2207 LDO remains");}

    printf("Verified: pmu,d2186 match, D2186 LDO table%s.\n",
           no_reg?"":", reg address");
    printf("\nNote: LDO14-17 zeroed (D2207-only rails). If backlight/WLED issues arise,\n"
           "those rows may need further refinement from the hardware datasheet.\n");

    if(dry){printf("Dry run: nothing written.\n");free(buf);return 0;}

    f=fopen(outpath,"wb");
    if(!f)die("cannot open output");
    if(fwrite(buf,1,fsz,f)!=fsz){fclose(f);die("write failed");}
    fclose(f);
    printf("Wrote %s\n",outpath);
    free(buf);
    return 0;
}
