#define _POSIX_C_SOURCE 200809L
/* Experimental N102-only bluetoothd platform compatibility patch.
 * Usage: ./bluetoothdhax input-bluetoothd output-bluetoothd
 * Adds N102 to the existing iOS 13 BCM_43452 (profile 3) MG device list.
 * This does NOT restore the removed BCM_4345 implementation or prove hardware
 * compatibility. Re-sign the output with the original entitlements before use.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned char *bytes;static size_t length;
static void fail(const char *s) { fprintf(stderr,"bluetoothdhax: %s\n",s);exit(1); }
static uint32_t rd32(size_t p) {
    if (p>length || length-p<4) fail("truncated 32-bit field");
    return (uint32_t)bytes[p]|(uint32_t)bytes[p+1]<<8|(uint32_t)bytes[p+2]<<16|(uint32_t)bytes[p+3]<<24;
}
static uint64_t rd64(size_t p) { return rd32(p)|(uint64_t)rd32(p+4)<<32; }
static void wr32(size_t p,uint32_t n) { for (unsigned i=0;i<4;i++) bytes[p+i]=(unsigned char)(n>>(i*8)); }
static int64_t sx(uint64_t n,unsigned bits) { return (int64_t)(n^(1ULL<<(bits-1)))-(int64_t)(1ULL<<(bits-1)); }
struct section { uint64_t vm,size;uint32_t off,flags,reserved1,reserved2;char name[17]; };
static struct section sections[128];static unsigned section_count;
static uint64_t text_vm,text_size;static size_t text_off,commands_end;
static uint32_t symoff,nsyms,stroff,strsize,indirect_off,indirect_count;
/* Verified in both MobileGestalt cache tables, against MGGetProductType's
 * 40-byte table row for runtime ProductType 0x1564beb0. MGIsDeviceOfType
 * compares these exact 20 bytes. Native iOS 12's N102 factory uses them. */
static const unsigned char n102[20]={
    0x61,0x0d,0x7a,0x6b,0xff,0x21,0x1f,0x3c,0x5d,0x3a,
    0xbc,0x39,0xff,0xb5,0x1c,0x93,0x0c,0xd0,0xd8,0x74
};
static size_t fileoff(uint64_t vm,size_t size) {
    if (vm<text_vm || vm-text_vm>text_size || size>text_size-(vm-text_vm)) fail("address outside __TEXT mapping");
    uint64_t f=text_off+vm-text_vm;
    if (f>length || size>length-f) fail("mapping exceeds input");return (size_t)f;
}
static uint64_t branch_target(uint32_t w,uint64_t pc) { return pc+sx(w&0x3ffffff,26)*4; }
static uint32_t encode_b(uint64_t pc,uint64_t target) {
    int64_t d=(int64_t)target-(int64_t)pc;
    if (d%4 || d/4<-(1LL<<25)||d/4>=(1LL<<25)) fail("branch out of range");
    return 0x14000000|((uint32_t)(d/4)&0x3ffffff);
}
static void parse(void) {
    if (length<32 || rd32(0)!=0xfeedfacf || rd32(4)!=0x0100000c || rd32(12)!=2) fail("expected thin little-endian ARM64 Mach-O executable");
    uint32_t n=rd32(16),size=rd32(20);if (size>length-32) fail("load commands exceed file");
    commands_end=32+size;size_t p=32;int have_text=0;
    for (uint32_t i=0;i<n;i++) {
        if (p>commands_end || commands_end-p<8) fail("truncated load command");
        uint32_t c=rd32(p),z=rd32(p+4);if (z<8||z>commands_end-p) fail("invalid command size");
        /* Build UUIDs do not gate compatibility; code and import checks do. */
        if (c==25) {
            if (z<72) fail("truncated segment command");
            uint64_t fo=rd64(p+40),fs=rd64(p+48);if (fo>length || fs>length-fo) fail("segment exceeds input");
            uint32_t ns=rd32(p+64);if (ns>(z-72)/80 || ns>128-section_count) fail("invalid section count");
            if (!memcmp(bytes+p+8,"__TEXT\0",7)) {
                if (have_text++) fail("duplicate TEXT segment");
                text_vm=rd64(p+24);text_size=fs;text_off=(size_t)fo;
                if ((rd32(p+60)&5)!=5) fail("TEXT is not readable/executable");
            }
            for (uint32_t j=0;j<ns;j++) {
                size_t q=p+72+j*80;struct section *s=&sections[section_count++];
                memcpy(s->name,bytes+q,16);s->name[16]=0;s->vm=rd64(q+32);s->size=rd64(q+40);
                s->off=rd32(q+48);s->flags=rd32(q+64);s->reserved1=rd32(q+68);s->reserved2=rd32(q+72);
            }
        } else if (c==2) {
            if (z!=24) fail("invalid symbol table");
            symoff=rd32(p+8);nsyms=rd32(p+12);stroff=rd32(p+16);strsize=rd32(p+20);
        } else if (c==11) {
            if (z!=80) fail("invalid indirect symbol table");
            indirect_off=rd32(p+56);indirect_count=rd32(p+60);
        } else if (c==0x2c) { if (z<24 || rd32(p+16)) fail("encrypted executable not supported"); }
        p+=z;
    }
    if (!have_text || !section_count) fail("required Mach-O metadata missing");
    if (symoff>length || nsyms>(length-symoff)/16 || stroff>length || strsize>length-stroff ||
        indirect_off>length || indirect_count>(length-indirect_off)/4) fail("symbol metadata out of bounds");
}
static int imported(uint64_t address,const char *name) {
    for (unsigned i=0;i<section_count;i++) {
        struct section *s=&sections[i];
        if ((s->flags&255)!=8 || !s->reserved2 || address<s->vm || address-s->vm>=s->size) continue;
        uint64_t delta=address-s->vm;if (delta%s->reserved2) return 0;
        uint64_t slot=s->reserved1+delta/s->reserved2;if (slot>=indirect_count) fail("stub index exceeds indirect table");
        uint32_t ix=rd32(indirect_off+(size_t)slot*4);if (ix>=nsyms) fail("invalid imported symbol index");
        uint32_t str=rd32(symoff+(size_t)ix*16);
        if (str>=strsize || !memchr(bytes+stroff+str,0,strsize-str)) fail("invalid imported symbol name");
        return !strcmp((char *)bytes+stroff+str,name);
    }
    return 0;
}
static size_t cave(size_t wanted) {
    unsigned char *busy=calloc((size_t)text_size,1);if (!busy) fail("out of memory");
    if (text_off || commands_end>text_size) fail("unsupported header layout");
    memset(busy,1,commands_end);
    for (unsigned i=0;i<section_count;i++) {
        struct section *s=&sections[i];unsigned type=s->flags&255;
        if (type==1||type==12||type==18||!s->size) continue;
        uint64_t lo=s->off>text_off?s->off:text_off,hi=(uint64_t)s->off+s->size;
        if (hi>text_off+text_size) hi=text_off+text_size;
        if (hi>lo) memset(busy+lo-text_off,1,(size_t)(hi-lo));
    }
    size_t found=0,best=SIZE_MAX;
    for (size_t i=0;i<text_size;) {
        if (busy[i]||bytes[text_off+i]) { i++;continue; }
        size_t start=i;while (i<text_size && !busy[i]&&!bytes[text_off+i]) i++;
        start=(start+3)&~(size_t)3;
        if (i>=start && i-start>=wanted && i-start<best) { found=text_off+start;best=i-start; }
    }
    free(busy);if (!found) fail("no unowned zero-filled executable padding");return found;
}
static void save(const char *path,mode_t mode) {
    size_t n=strlen(path);char *tmp=malloc(n+16);if (!tmp) fail("out of memory");snprintf(tmp,n+16,"%s.tmp.XXXXXX",path);
    int fd=mkstemp(tmp);if (fd<0) { perror(path);exit(1); }
    if (fchmod(fd,mode&0777)) { close(fd);unlink(tmp);fail("cannot set output mode"); }
    FILE *f=fdopen(fd,"wb");if (!f) { close(fd);unlink(tmp);fail("cannot open output stream"); }
    int bad=fwrite(bytes,1,length,f)!=length;if (fclose(f)) bad=1;
    if (bad) { unlink(tmp);fail("output write failed"); }
    if (rename(tmp,path)) { perror(path);unlink(tmp);exit(1); }free(tmp);
}
int main(int argc,char **argv) {
    if (argc!=3) { fprintf(stderr,"Usage: %s input-bluetoothd output-bluetoothd\n",argv[0]);return 1; }
    struct stat in,out;if (stat(argv[1],&in)) { perror(argv[1]);return 1; }
    if (!stat(argv[2],&out)&&in.st_dev==out.st_dev&&in.st_ino==out.st_ino) fail("output must not alias input");
    FILE *f=fopen(argv[1],"rb");if (!f) { perror(argv[1]);return 1; }
    if (fseek(f,0,SEEK_END)) fail("cannot seek input");long n=ftell(f);if (n<32 || fseek(f,0,SEEK_SET)) fail("invalid input size");
    length=(size_t)n;bytes=malloc(length);if (!bytes) fail("out of memory");
    if (fread(bytes,1,length,f)!=length) fail("input read failed");fclose(f);parse();
    size_t site=0;unsigned matches=0;
    for (unsigned s=0;s<section_count;s++) {
        struct section *sec=&sections[s];if (strcmp(sec->name,"__text")) continue;
        size_t base=fileoff(sec->vm,(size_t)sec->size);
        for (size_t i=12;i+32<=sec->size;i+=4) {
            size_t p=base+i;uint32_t w=rd32(p);
            if (rd32(p-12)!=0xd10243a8 || rd32(p-8)!=0xd101c3b3 || rd32(p-4)!=0xf90003f3 ||
                (w!=0xa900ffe8 && (w&0xfc000000)!=0x14000000) || rd32(p+4)!=0xd10143a0 ||
                (rd32(p+8)&0xfc000000)!=0x94000000 || (rd32(p+12)&0xff00001f)!=0x34000000 ||
                rd32(p+16)!=0x52805e00 || (rd32(p+20)&0xfc000000)!=0x94000000 ||
                rd32(p+24)!=0xaa0003f3 || rd32(p+28)!=0x320007e1) continue;
            uint64_t pc=text_vm+p-text_off;
            if (!imported(branch_target(rd32(p+8),pc+8),"_MGIsDeviceOneOfType")) fail("device-list call is not the expected MobileGestalt import");
            if (!imported(branch_target(rd32(p+20),pc+20),"__Znwm")) fail("allocation call is not operator new");
            site=p;matches++;
        }
    }
    if (matches!=1) fail("profile-3 factory signature missing or ambiguous");
    uint64_t pc=text_vm+site-text_off;uint32_t original=rd32(site);size_t payload;
    if (original==0xa900ffe8) payload=cave(40);
    else payload=fileoff(branch_target(original,pc),40);
    uint64_t pv=text_vm+payload-text_off;
    /* Preserve first three MG list entries, append N102 as the fourth, and
     * move the terminating NULL from [sp+16] to [sp+24]. No added call or
     * hand-written allocator/constructor code is necessary. */
    uint32_t code[4]={0x10000089,0xa900a7e8,0xf9000fff,encode_b(pv+12,pc+4)};
    if (original!=0xa900ffe8) {
        for (unsigned i=0;i<4;i++) if (rd32(payload+i*4)!=code[i]) fail("existing branch is not this patch");
        if (memcmp(bytes+payload+16,n102,20) || rd32(payload+36)) fail("existing N102 payload differs");
        puts("Already patched: N102 is in the profile-3 compatibility list.");
    } else {
        for (unsigned i=0;i<4;i++) wr32(payload+i*4,code[i]);memcpy(bytes+payload+16,n102,20);wr32(payload+36,0);
        wr32(site,encode_b(pc,pv));
        printf("Patched N102 device matching at file 0x%zx; payload 0x%zx.\n",site,payload);
    }
    save(argv[2],in.st_mode);
    printf("Experimental profile: BCM_43452 (3), replacing no existing device match.\nOutput: %s (%zu bytes)\n",argv[2],length);
    if (original==0xa900ffe8) puts("Code signature is now stale: re-sign with the original entitlements before installing.");
    free(bytes);return 0;
}
