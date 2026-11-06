#define _POSIX_C_SOURCE 200809L
/* Retarget the mini4 multitouch codeless personality to the iPod touch 6.
 * cc -std=c11 -Wall -Wextra -Werror -O2 mthax.c -o mthax
 * ./mthax input-kernel output-kernel
 * Installs the native N102 IOKit personality in __PRELINK_INFO XML.
 * Bundle identity, other kexts, external ID/IDREFs and Mach-O layout survive.
 */
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void die(const char *message) { fprintf(stderr,"mthax: %s\n",message); exit(1); }
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static uint64_t u64(const unsigned char *p) { return u32(p) | (uint64_t)u32(p+4)<<32; }
static void *alloc(size_t n) { void *p=malloc(n); if (!p) die("out of memory"); return p; }
static int space(char c) { return isspace((unsigned char)c); }

/* Bounded plist element walker. XML is walked without reserializing it, so
 * Apple's nonstandard ID and IDREF attributes remain byte-for-byte intact. */
struct element { const char *start,*content,*close,*end,*tag; size_t taglen; };
static struct element element(const char *p,const char *limit,unsigned depth) {
    struct element e={0};
    if (depth>128 || p>=limit || *p!='<') die("invalid or excessively nested plist XML");
    e.start=p++; e.tag=p;
    while (p<limit && (isalnum((unsigned char)*p) || *p=='_' || *p=='-')) p++;
    e.taglen=(size_t)(p-e.tag);
    if (!e.taglen) die("invalid XML tag");
    char quote=0;
    for (;p<limit;p++) {
        if (quote) { if (*p==quote) quote=0; }
        else if (*p=='\'' || *p=='"') quote=*p;
        else if (*p=='>') break;
    }
    if (p==limit) die("truncated XML opening tag");
    e.content=p+1;
    if (p>e.start && p[-1]=='/') { e.close=e.content; e.end=e.content; return e; }
    p=e.content;
    while (p<limit) {
        if (*p!='<') { p++; continue; }
        if (limit-p>=2 && p[1]=='/') {
            const char *q=p+2;
            if ((size_t)(limit-q)<e.taglen || memcmp(q,e.tag,e.taglen)) die("mismatched XML close tag");
            q+=e.taglen;
            while (q<limit && space(*q)) q++;
            if (q==limit || *q!='>') die("invalid XML close tag");
            e.close=p; e.end=q+1; return e;
        }
        struct element child=element(p,limit,depth+1); p=child.end;
    }
    die("unterminated XML element"); return e;
}
static int tag(struct element e,const char *s) { return e.taglen==strlen(s) && !memcmp(e.tag,s,e.taglen); }
static int textis(struct element e,const char *s) {
    return e.start && (size_t)(e.close-e.content)==strlen(s) && !memcmp(e.content,s,strlen(s));
}
static const char *skip(const char *p,const char *end) { while (p<end && space(*p)) p++; return p; }
/* Fetch a direct dictionary member and optionally its key span. */
static struct element get(struct element dict,const char *key,struct element *key_out) {
    struct element result={0};
    if (!tag(dict,"dict")) die("expected plist dictionary");
    const char *p=skip(dict.content,dict.close);
    while (p<dict.close) {
        struct element k=element(p,dict.close,0);
        if (!tag(k,"key")) die("dictionary member has no key");
        p=skip(k.end,dict.close);
        if (p==dict.close) die("dictionary key has no value");
        struct element v=element(p,dict.close,0);
        if (textis(k,key)) {
            if (result.start) die("duplicate dictionary key");
            result=v; if (key_out) *key_out=k;
        }
        p=skip(v.end,dict.close);
    }
    return result;
}
/* Board configuration extracted from kernel-ipod6.raw, AppleMultitouchSPIN102
 * 2140.3. Keep the existing iOS 13 executable and codeless bundle identity.
 * No executable addresses or donor ModuleIndex are copied. */
static const char n102_personality[] =
    "<dict>"
    "<key>AutomaticallySetOperatingMode</key><true/>"
    "<key>CFBundleIdentifier</key><string>com.apple.driver.AppleMultitouchSPI</string>"
    "<key>HIDServiceSupport</key><true/>"
    "<key>IOCFPlugInTypes</key><dict>"
    "<key>0516B563-B15B-11DA-96EB-0014519758EF</key><string>AppleMultitouchSPI.kext/PlugIns/MultitouchHID.plugin</string></dict>"
    "<key>IOClass</key><string>AppleMultitouchN1SPI</string>"
    "<key>IONameMatch</key><array><string>multi-touch,n102</string></array>"
    "<key>IOProviderClass</key><string>AppleARMSPIDevice</string>"
    "<key>cal-dl-addr</key><integer size=\"64\">0x10009000</integer>"
    "<key>clk32-clock-enable-addr</key><integer size=\"64\">0x10003518</integer>"
    "<key>clk32-clock-enable-val</key><integer size=\"64\">0x1</integer>"
    "<key>fll-mval</key><integer size=\"64\">0x17d3</integer>"
    "<key>fll-mval-addr</key><integer size=\"64\">0x10003060</integer>"
    "<key>fw-execute-addr</key><integer size=\"64\">0x10003400</integer>"
    "<key>mt-merge-personality</key><string>C1F58,1</string>"
    "<key>parser-type</key><integer size=\"64\">0x1</integer>"
    "<key>prox-cal-addr</key><integer size=\"64\">0x10009600</integer>"
    "<key>ref-clk-div-val</key><integer size=\"64\">0x2</integer>"
    "<key>reset-deassert-delay</key><integer size=\"64\">0xf</integer>"
    "<key>touch-size-id</key><integer size=\"64\">0x2</integer></dict>"
    ;

struct edit { const char *start,*end,*replacement; };
static void save(const char *path,const unsigned char *bytes,size_t size) {
    size_t n=strlen(path);
    char *tmp=alloc(n+16); snprintf(tmp,n+16,"%s.tmp.XXXXXX",path);
    int fd=mkstemp(tmp); if (fd<0) { perror(path); exit(1); }
    FILE *f=fdopen(fd,"wb");
    if (!f) { close(fd); unlink(tmp); die("cannot open output stream"); }
    int failed=fwrite(bytes,1,size,f)!=size;
    if (fclose(f)) failed=1;
    if (failed) { unlink(tmp); die("output write failed"); }
    if (rename(tmp,path)) { perror(path); unlink(tmp); exit(1); }
    free(tmp);
}
int main(int argc,char **argv) {
    if (argc!=3) { fprintf(stderr,"Usage: %s [mini4 kernel] [patched output kernel]\n",argv[0]); return 1; }
    struct stat in,out;
    if (stat(argv[1],&in)) { perror(argv[1]); return 1; }
    if (!stat(argv[2],&out) && in.st_dev==out.st_dev && in.st_ino==out.st_ino)
        die("output must not alias input");
    FILE *f=fopen(argv[1],"rb"); if (!f) { perror(argv[1]); return 1; }
    if (fseek(f,0,SEEK_END)) die("cannot seek input");
    long length=ftell(f); if (length<32) die("input is too small for a Mach-O header");
    if (fseek(f,0,SEEK_SET)) die("cannot rewind input");
    size_t size=(size_t)length; unsigned char *bytes=alloc(size);
    if (fread(bytes,1,size,f)!=size) die("input read failed");
    fclose(f);
    if (u32(bytes)!=0xfeedfacf || u32(bytes+4)!=0x0100000c) die("expected a raw little-endian ARM64 Mach-O kernel");
    uint32_t commands=u32(bytes+16),command_bytes=u32(bytes+20);
    if (command_bytes>size-32) die("load commands exceed input");
    size_t off=32,cmd_end=32+command_bytes,info_off=0,info_size=0;
    for (uint32_t i=0;i<commands;i++) {
        if (off>cmd_end || cmd_end-off<8) die("truncated load command");
        uint32_t c=u32(bytes+off),n=u32(bytes+off+4);
        if (n<8 || n>cmd_end-off) die("invalid load command size");
        if (c==0x19) {
            if (n<72) die("truncated segment command");
            if (!memcmp(bytes+off+8,"__PRELINK_INFO\0\0",16)) {
                if (info_size) die("ambiguous __PRELINK_INFO segments");
                uint64_t start=u64(bytes+off+40),span=u64(bytes+off+48);
                if (start>size || !span || span>size-start) die("invalid __PRELINK_INFO extent");
                info_off=(size_t)start; info_size=(size_t)span;
            }
        }
        off+=n;
    }
    if (!info_size) die("no __PRELINK_INFO segment found");
    const char *xml=(char *)bytes+info_off,*zero=memchr(xml,0,info_size);
    if (!zero) die("prelink XML is not NUL-terminated");
    const char *start=skip(xml,zero);
    /* Apple kernelcache plists normally begin directly with <dict>. */
    if (zero-start>=5 && !memcmp(start,"<?xml",5)) {
        const char *q=start;
        while (q+1<zero && !(q[0]=='?' && q[1]=='>')) q++;
        if (q+1>=zero) die("invalid XML declaration");
        start=skip(q+2,zero);
    }
    struct element root=element(start,zero,0);
    if (tag(root,"plist")) root=element(skip(root.content,root.close),root.close,0);
    struct element array=get(root,"_PrelinkInfoDictionary",NULL);
    if (!array.start || !tag(array,"array")) die("missing prelink kext array");
    struct element entry={0};
    for (const char *p=skip(array.content,array.close);p<array.close;) {
        struct element e=element(p,array.close,0);
        struct element id=get(e,"CFBundleIdentifier",NULL);
        if (tag(id,"string") && textis(id,"com.apple.driver.AppleMultitouchSPIJ96")) {
            if (entry.start) die("multiple J96 codeless entries");
            entry=e;
        }
        p=skip(e.end,array.close);
    }
    if (!entry.start) die("AppleMultitouchSPIJ96 codeless entry not found");
    if (get(entry,"_PrelinkExecutableLoadAddr",NULL).start || get(entry,"_PrelinkKmodInfo",NULL).start)
        die("target entry unexpectedly contains executable metadata");
    struct element personalities=get(entry,"IOKitPersonalities",NULL),label={0};
    struct element personality=get(personalities,"AppleMultitouchSPI - J96",&label);
    if (!personality.start) personality=get(personalities,"AppleMultitouchSPI - N102",&label);
    if (!personality.start) personality=get(personalities,"AppleMultitouchSPI - C1,N102",&label);
    if (!personality.start) die("expected J96/N102 personality not found");
    if (!textis(get(personality,"IOClass",NULL),"AppleMultitouchN1SPI") ||
        !textis(get(personality,"IOProviderClass",NULL),"AppleARMSPIDevice")) die("unexpected multitouch class/provider");
    struct element match=get(personality,"IONameMatch",NULL),name={0};
    if (tag(match,"array")) {
        for (const char *p=skip(match.content,match.close);p<match.close;) {
            struct element e=element(p,match.close,0);
            if (tag(e,"string") && (textis(e,"multi-touch,j96") || textis(e,"multi-touch,n102"))) {
                if (name.start) die("ambiguous multitouch matching array");
                name=e;
            }
            p=skip(e.end,match.close);
        }
    } else if (tag(match,"string")) name=match;
    if (!name.start || (!textis(name,"multi-touch,j96") && !textis(name,"multi-touch,n102"))) die("expected J96/N102 IONameMatch not found");
    /* Replacing a dictionary with ID definitions could orphan references in
     * another kext. Stock J96 and earlier mthax outputs have only IDREFs here.
     * Fail closed on an unfamiliar shared definition instead of corrupting it. */
    for (const char *p=personality.start;p+5<personality.end;p++)
        if (!memcmp(p," ID=",4)) die("personality contains shared XML ID definitions; refusing replacement");
    struct edit edits[2]; unsigned count=0;
    const char *native_label="AppleMultitouchSPI - C1,N102";
    if (!textis(label,native_label)) edits[count++]=(struct edit){label.content,label.close,native_label};
    size_t old_personality=(size_t)(personality.end-personality.start);
    if (old_personality!=strlen(n102_personality) || memcmp(personality.start,n102_personality,old_personality))
        edits[count++]=(struct edit){personality.start,personality.end,n102_personality};
    if (count==2 && edits[0].start>edits[1].start) { struct edit t=edits[0];edits[0]=edits[1];edits[1]=t; }
    size_t used=(size_t)(zero-xml),new_used=used;
    for (unsigned i=0;i<count;i++) {
        size_t old=(size_t)(edits[i].end-edits[i].start),n=strlen(edits[i].replacement);
        if (i && edits[i].start<edits[i-1].end) die("overlapping edits");
        if (old>new_used) die("invalid replacement span");
        new_used-=old;
        if (n>SIZE_MAX-new_used) die("replacement size overflow");
        new_used+=n;
    }
    if (new_used>=info_size) die("insufficient XML padding; refusing to resize kernel");
    if (new_used>used)
        for (size_t i=used;i<=new_used;i++) if (xml[i]) die("nonzero bytes in required XML padding");
    char *patched=alloc(new_used+1); size_t written=0;const char *cursor=xml;
    for (unsigned i=0;i<count;i++) {
        size_t prefix=(size_t)(edits[i].start-cursor),n=strlen(edits[i].replacement);
        memcpy(patched+written,cursor,prefix);written+=prefix;
        memcpy(patched+written,edits[i].replacement,n);written+=n;cursor=edits[i].end;
    }
    size_t tail=(size_t)(zero-cursor);memcpy(patched+written,cursor,tail);written+=tail;patched[written]=0;
    if (written!=new_used) die("XML size mismatch");
    memcpy(bytes+info_off,patched,written+1);
    if (new_used<used) memset(bytes+info_off+new_used+1,0,used-new_used);
    save(argv[2],bytes,size);
    printf("%s: IONameMatch=multi-touch,n102; personality=AppleMultitouchSPI - C1,N102\n",count?"Patched":"Already patched");
    printf("N102 settings: mt-merge-personality=C1F58,1; fll-mval=0x17d3; ref-clk-div-val=2; touch-size-id=2; AutomaticallySetOperatingMode=true; parser-options removed.\n");
    printf("Preserved bundle identity, other kexts and kernel size (%zu bytes).\nOutput: %s\n",size,argv[2]);
    free(patched);free(bytes);return 0;
}
