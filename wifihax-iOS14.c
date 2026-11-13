/* iOS 14.0 beta 2 port. Validated against supplied mini4/6S 18A5319i inputs. */
#define _POSIX_C_SOURCE 200809L
/* Repair WLAN hashstore records using firmware from the PeaceUpdate volume.
 * ./wifihax input-kernel output-kernel [wifi-directory]
 * Preserves verification code. Also removes the earlier known comparison
 * override, when present and fully recognized, before repairing data records.
 */
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <CommonCrypto/CommonDigest.h>

static void die(const char *message) { fprintf(stderr,"wifihax: %s\n",message); exit(1); }
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
    /* Beta 2 metadata contains XML comments between keys and values. */
    while (limit-p>=4 && !memcmp(p,"<!--",4)) {
        const char *q=p+4;
        while (limit-q>=3 && memcmp(q,"-->",3)) q++;
        if (limit-q<3) die("unterminated XML comment");
        p=q+3; while (p<limit && isspace((unsigned char)*p)) p++;
    }
    if (p>=limit || *p!='<') die("missing element after comment");
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

struct seg { char name[17]; uint64_t vm,sz,fo,fs; size_t cmd; };
struct image { struct seg segs[32]; unsigned count; unsigned char uuid[16]; int has_uuid; };
static unsigned char *data; static size_t data_size;
static void put32(size_t off,uint32_t w) { for (unsigned i=0;i<4;i++) data[off+i]=(unsigned char)(w>>(8*i)); }
static void put64(size_t off,uint64_t w) { for (unsigned i=0;i<8;i++) data[off+i]=(unsigned char)(w>>(8*i)); }
static void parse(struct image *out,size_t off) {
    memset(out,0,sizeof(*out));
    if (off>data_size || data_size-off<32 || u32(data+off)!=0xfeedfacf || u32(data+off+4)!=0x0100000c) die("invalid ARM64 Mach-O");
    uint32_t nc=u32(data+off+16),len=u32(data+off+20);
    if (len>data_size-off-32) die("load commands exceed file");
    size_t end=off+32+len;off+=32;
    for (uint32_t i=0;i<nc;i++) {
        if (off>end || end-off<8) die("truncated load command");
        uint32_t c=u32(data+off),n=u32(data+off+4);
        if (n<8 || n>end-off) die("invalid command size");
        if (c==25) {
            if (n<72 || out->count==32) die("invalid segment");
            struct seg *s=&out->segs[out->count++];
            memcpy(s->name,data+off+8,16);s->name[16]=0;
            s->vm=u64(data+off+24);s->sz=u64(data+off+32);
            s->fo=u64(data+off+40);s->fs=u64(data+off+48);s->cmd=off;
            uint32_t ns=u32(data+off+64);
            if (ns>(n-72)/80) die("sections exceed segment command");
        } else if (c==27 && n==24) { memcpy(out->uuid,data+off+8,16);out->has_uuid=1; }
        off+=n;
    }
}
static struct seg *segment(struct image *i,const char *name) {
    for (unsigned j=0;j<i->count;j++) if (!strcmp(i->segs[j].name,name)) return &i->segs[j];
    die("required segment missing");return NULL;
}
static size_t fileoff(struct image *outer,uint64_t vm,size_t length) {
    for (unsigned i=0;i<outer->count;i++) {
        struct seg *s=&outer->segs[i];
        if (vm>=s->vm && vm-s->vm<=s->fs && length<=s->fs-(vm-s->vm)) {
            uint64_t f=s->fo+vm-s->vm;
            if (f>data_size || length>data_size-f) die("mapping exceeds file");
            return (size_t)f;
        }
    }
    die("address has no file mapping");return 0;
}
static int inside(struct seg *s,uint64_t v,size_t n) { return v>=s->vm && v-s->vm<=s->sz && n<=s->sz-(v-s->vm); }
static uint64_t loadaddr(struct element array,const char *bid) {
    uint64_t found=0;
    for (const char *p=skip(array.content,array.close);p<array.close;) {
        struct element e=element(p,array.close,0),id=get(e,"CFBundleIdentifier",NULL);
        if (textis(id,bid)) {
            struct element v=get(e,"_PrelinkExecutableLoadAddr",NULL);
            if (found || !tag(v,"integer") || v.close-v.content>40 || v.close==v.content) die("missing or ambiguous executable address");
            char buf[41];size_t n=(size_t)(v.close-v.content);memcpy(buf,v.content,n);buf[n]=0;
            char *tail;found=strtoull(buf,&tail,0);if (*tail || !found) die("unsupported executable address");
        }
        p=skip(e.end,array.close);
    }
    if (!found) die("required kext is absent");return found;
}
static int64_t sx(uint64_t v,unsigned bits) { return (int64_t)(v^(1ULL<<(bits-1)))-(int64_t)(1ULL<<(bits-1)); }
static uint64_t adrp_target(uint32_t w,uint64_t pc) {
    return (pc&~4095ULL)+sx(((w>>5&0x7ffff)<<2)|(w>>29&3),21)*4096;
}
static uint32_t branch(uint64_t from,uint64_t to) {
    int64_t d=(int64_t)to-(int64_t)from;
    if (d%4 || d/4<-(1LL<<25) || d/4>=(1LL<<25)) die("branch outside encodable range");
    return 0x14000000|((uint32_t)(d/4)&0x3ffffff);
}
static uint32_t adrp(uint64_t from,uint64_t to) {
    int64_t d=((int64_t)(to&~4095ULL)-(int64_t)(from&~4095ULL))/4096;
    if (d<-(1<<20) || d>=(1<<20)) die("vtable outside ADRP range");
    uint32_t n=(uint32_t)d&0x1fffff;return 0x90000010|((n&3)<<29)|((n>>2)<<5);
}
static uint64_t symbol(struct image *outer,const char *name) {
    (void)outer;uint32_t nc=u32(data+16);size_t off=32;
    for (uint32_t i=0;i<nc;i++) {
        uint32_t c=u32(data+off),n=u32(data+off+4);
        if (c==2) {
            if (n!=24) die("invalid symbol table command");
            size_t so=u32(data+off+8),count=u32(data+off+12),st=u32(data+off+16),sz=u32(data+off+20);
            if (so>data_size || count>(data_size-so)/16 || st>data_size || sz>data_size-st) die("invalid symbol table");
            for (size_t j=0;j<count;j++) {
                uint32_t idx=u32(data+so+j*16);
                if (idx>=sz || !memchr(data+st+idx,0,sz-idx)) die("invalid symbol string");
                if (!strcmp((char *)data+st+idx,name)) return u64(data+so+j*16+8);
            }
        }
        off+=n;
    }
    die("required exported symbol missing");return 0;
}
static uint64_t stub_target(struct image *k,uint64_t pc) {
    size_t f=fileoff(k,pc,12);uint32_t a=u32(data+f),b=u32(data+f+4),c=u32(data+f+8);
    if ((a&0x9f00001f)!=0x90000010 || (b&0xffc003ff)!=0xf9400210 || c!=0xd61f0200) die("unexpected memcmp import stub");
    uint64_t addr=adrp_target(a,pc)+(uint64_t)(b>>10&4095)*8;
    return u64(data+fileoff(k,addr,8));
}



#define MAX_FIRMWARE 256
struct firmware {
    char relative[PATH_MAX]; unsigned char key[32],sha[32]; uint32_t size;
    uint64_t record,value,digest,extra; uint32_t flags; int changed;
};
static struct firmware firmware[MAX_FIRMWARE];static size_t firmware_count;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static void scan_firmware(const char *root,const char *relative) {
    char path[PATH_MAX];
    if (snprintf(path,sizeof(path),"%s%s%s",root,*relative?"/":"",relative)>=(int)sizeof(path)) die("firmware path too long");
    struct stat st;if (lstat(path,&st)) { perror(path);exit(1); }
    if (S_ISDIR(st.st_mode)) {
        DIR *d=opendir(path);if (!d) { perror(path);exit(1); }
        struct dirent *de;
        while ((de=readdir(d))) {
            if (!strcmp(de->d_name,".") || !strcmp(de->d_name,"..")) continue;
            char next[PATH_MAX];
            if (snprintf(next,sizeof(next),"%s%s%s",relative,*relative?"/":"",de->d_name)>=(int)sizeof(next)) die("firmware relative path too long");
            scan_firmware(root,next);
        }
        closedir(d);return;
    }
    if (!S_ISREG(st.st_mode)) die("firmware directory contains non-regular files");
    if (firmware_count==MAX_FIRMWARE || st.st_size<0 || (uint64_t)st.st_size>UINT32_MAX) die("too many firmware files or oversized image");
    struct firmware *fw=&firmware[firmware_count++];strcpy(fw->relative,relative);
    CC_SHA256(relative,(CC_LONG)strlen(relative),fw->key);
    FILE *f=fopen(path,"rb");if (!f) { perror(path);exit(1); }
    CC_SHA256_CTX ctx;CC_SHA256_Init(&ctx);unsigned char buf[65536];size_t n;uint64_t size=0;
    while ((n=fread(buf,1,sizeof(buf),f))) { CC_SHA256_Update(&ctx,buf,(CC_LONG)n);size+=n; }
    if (ferror(f) || size!=(uint64_t)st.st_size) die("firmware read failed or file changed");
    fclose(f);CC_SHA256_Final(fw->sha,&ctx);fw->size=(uint32_t)size;
}
#pragma clang diagnostic pop
static int firmware_order(const void *a,const void *b) { return strcmp(((const struct firmware *)a)->relative,((const struct firmware *)b)->relative); }
static void firmware_root(char path[PATH_MAX],const char *override) {
    if (override) {
        if (strlen(override)>=PATH_MAX) die("firmware directory path too long");
        strcpy(path,override);return;
    }
    DIR *d=opendir("/Volumes");if (!d) die("cannot list /Volumes; specify wifi-directory");
    unsigned found=0;struct dirent *e;
    while ((e=readdir(d))) {
        if (strncmp(e->d_name,"PeaceUpdate",11)) continue;
        char p[PATH_MAX];
        if (snprintf(p,sizeof(p),"/Volumes/%s/usr/share/firmware/wifi",e->d_name)>=(int)sizeof(p)) continue;
        struct stat st;if (!stat(p,&st) && S_ISDIR(st.st_mode)) { strcpy(path,p);found++; }
    }
    closedir(d);
    if (found!=1) die("need one mounted PeaceUpdate Wi-Fi directory, or an explicit wifi-directory argument");
}
static void print_sha(const unsigned char *h) { for (unsigned i=0;i<32;i++) printf("%02x",h[i]); }
static uint64_t numeric(struct element e) {
    if (!tag(e,"integer") || e.close<=e.content || e.close-e.content>40) die("expected explicit integer");
    char s[41];size_t n=(size_t)(e.close-e.content);memcpy(s,e.content,n);s[n]=0;
    char *tail;uint64_t v=strtoull(s,&tail,0);if (*tail) die("invalid integer");return v;
}
static int contains_text(struct image *k,uint64_t v,const char *s) {
    size_t f=fileoff(k,v,strlen(s)+1);return !memcmp(data+f,s,strlen(s)+1);
}
struct hashstore { uint64_t header,array; uint32_t count; };
static struct hashstore find_store(struct image *k,struct image *hash) {
    struct seg *dc=segment(hash,"__DATA_CONST"),*text=segment(hash,"__TEXT"),*rw=segment(hash,"__DATA");
    size_t f=fileoff(k,dc->vm,(size_t)dc->fs);struct hashstore result={0};
    for (size_t i=0;i+56<=dc->fs;i+=8) {
        if (u64(data+f+i+16)!=0x68617368) continue; /* "hsah" little endian */
        uint64_t consumer=u64(data+f+i+24),array=u64(data+f+i+40),version=u64(data+f+i);
        uint32_t n=u32(data+f+i+32);
        if (!inside(text,consumer,32) || !inside(text,version,45) || !n || n>8192 || !inside(rw,array,(size_t)n*8)) continue;
        if (!contains_text(k,consumer,"com.apple.driver.AppleBCMWLANCore")) continue;
        size_t vf=fileoff(k,version,45);
        if (memcmp(data+vf,"IOImageLoaderDatastore version: ",31)) continue;
        if (result.header) die("ambiguous WLAN hashstore headers");
        result=(struct hashstore){dc->vm+i,array,n};
    }
    if (!result.header) die("WLAN hashstore header not identified");return result;
}
/* Records: {name-SHA256 pointer, value pointer}. Values: {data-SHA256
 * pointer, uint32 flags, uint32 image size, metadata pointer}. SHA blobs
 * contain a uint32 length followed by digest bytes. */
static const unsigned char *digest(struct image *k,uint64_t v) {
    size_t f=fileoff(k,v,36);if (u32(data+f)!=32) die("unsupported digest length");return data+f+4;
}
static int b64_value(unsigned char c) {
    if (c>='A'&&c<='Z') return c-'A';if (c>='a'&&c<='z') return c-'a'+26;
    if (c>='0'&&c<='9') return c-'0'+52;if (c=='+') return 62;if (c=='/') return 63;return -1;
}
static uint32_t *read_relocs(struct element e,uint32_t *count) {
    if (!tag(e,"data")) die("KASLR table missing");
    size_t cap=(size_t)(e.close-e.content);unsigned char *out=alloc(cap+1);size_t n=0;uint32_t bits=0;unsigned used=0;
    for (const char *p=e.content;p<e.close;p++) {
        int v=b64_value((unsigned char)*p);if (v<0) { if (*p=='='||space(*p)) continue;die("invalid KASLR base64"); }
        bits=(bits<<6)|(unsigned)v;used+=6;
        if (used>=8) { used-=8;out[n++]=(unsigned char)(bits>>used); }
    }
    if (n<4) die("truncated KASLR table");*count=u32(out);
    if ((uint64_t)*count*4+4!=n) die("invalid KASLR count");
    uint32_t *result=alloc(((size_t)*count+MAX_FIRMWARE*2)*sizeof(uint32_t));
    for (uint32_t i=0;i<*count;i++) result[i]=u32(out+4+i*4);
    free(out);return result;
}
static int has_reloc(const uint32_t *r,uint32_t n,uint32_t v) { for (uint32_t i=0;i<n;i++) if (r[i]==v) return 1;return 0; }
static void add_reloc(uint32_t *r,uint32_t *n,uint64_t base,uint64_t v) {
    if (v<base || v-base>UINT32_MAX) die("KASLR offset out of range");
    if (has_reloc(r,*n,(uint32_t)(v-base))) die("unexpected existing relocation in new data");
    r[(*n)++]=(uint32_t)(v-base);
}
/* Recover XML capacity only when needed. Shorter decimal spellings of
 * unsigned integer values preserve plist semantics, IDs and size attributes.
 * Restrict edits to the prefix before the relocation data and update its
 * offsets after each move; do not rewrite strings or binary data payloads.
 */
static void compact_integer_prefix(size_t info,size_t capacity,size_t need,
                                   size_t *used,size_t *start,size_t *end) {
    size_t cursor=info,recovered=0;
    while (need>=capacity-*used && cursor+9<*start) {
        if (memcmp(data+cursor,"<integer",8) ||
            !(data[cursor+8]=='>' || space(data[cursor+8]))) { cursor++;continue; }
        struct element item=element((char *)data+cursor,(char *)data+*start,0);
        if (!tag(item,"integer")) die("unexpected XML element during compaction");
        size_t next=(size_t)(item.end-(char *)data),old=(size_t)(item.close-item.content);
        if (old && old<128) {
            char value[128],shorter[32],*tail;memcpy(value,item.content,old);value[old]=0;
            const char *begin=value;while (space(*begin)) begin++;
            if (*begin!='-' && *begin!='+') {
                errno=0;unsigned long long number=strtoull(begin,&tail,0);
                while (space(*tail)) tail++;
                if (!errno && tail!=begin && !*tail) {
                    int z=snprintf(shorter,sizeof(shorter),"%llu",number);
                    if (z>0 && (size_t)z<old) {
                        size_t from=(size_t)(item.content-(char *)data),to=(size_t)(item.close-(char *)data);
                        size_t saved=old-(size_t)z;
                        memmove(data+from+z,data+to,info+*used-to+1);memcpy(data+from,shorter,(size_t)z);
                        memset(data+info+*used-saved+1,0,saved);
                        *used-=saved;*start-=saved;*end-=saved;next-=saved;recovered+=saved;
                    }
                }
            }
        }
        cursor=next;
    }
    if (need>=capacity-*used) die("not enough prelink XML padding for KASLR records after lossless compaction");
    if (recovered) printf("Recovered %zu bytes of XML capacity using equivalent integer spellings.\n",recovered);
}
static void replace_relocs(struct element e,const uint32_t *r,uint32_t n,size_t info,size_t capacity) {
    size_t bytes=4+(size_t)n*4;unsigned char *buf=alloc(bytes);
    for (size_t i=0;i<bytes;i++) { uint32_t w=i<4?n:r[(i-4)/4];buf[i]=(unsigned char)(w>>((i%4)*8)); }
    static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t length=4*((bytes+2)/3);char *encoded=alloc(length);size_t j=0;
    for (size_t i=0;i<bytes;i+=3) {
        uint32_t v=(uint32_t)buf[i]<<16;if (i+1<bytes) v|=(uint32_t)buf[i+1]<<8;if (i+2<bytes) v|=buf[i+2];
        encoded[j++]=alphabet[v>>18];encoded[j++]=alphabet[v>>12&63];
        encoded[j++]=i+1<bytes?alphabet[v>>6&63]:'=';encoded[j++]=i+2<bytes?alphabet[v&63]:'=';
    }
    size_t old=(size_t)(e.close-e.content),start=(size_t)(e.content-(char *)data),end=(size_t)(e.close-(char *)data);
    char *zero=memchr(data+info,0,capacity);if (!zero) die("unterminated prelink XML");
    size_t used=(size_t)(zero-((char *)data+info));
    if (length>old) {
        size_t grow=length-old;
        if (grow>=capacity-used) compact_integer_prefix(info,capacity,grow,&used,&start,&end);
        for (size_t i=0;i<=grow;i++) if (data[info+used+i]) die("nonzero prelink XML padding");
    }
    size_t tail=info+used-end+1;memmove(data+start+length,data+end,tail);memcpy(data+start,encoded,length);
    if (length<old) memset(data+info+used-(old-length)+1,0,old-length);
    free(encoded);free(buf);
}

/* Remove only the precisely recognized earlier wifihax code experiment.
 * Clean input reaches this routine without any instruction writes. */
static void restore_previous_override(struct image *k,struct image *loader,struct image *hash) {
    struct seg *code=segment(loader,"__TEXT_EXEC");size_t cf=fileoff(k,code->vm,(size_t)code->fs);
    uint64_t site=0;unsigned matches=0;
    for (size_t i=12;i+16<=code->fs;i+=4) {
        uint32_t w=u32(data+cf+i);
        /* Both encode W2=32: older ORR alias and 13.4 MOVZ. The
         * surrounding comparison and memcmp import are still validated. */
        uint32_t digest_length=u32(data+cf+i-8);
        if (u32(data+cf+i-12)==0xd10203a0 &&
            (digest_length==0x321b03e2 || digest_length==0x52800402) &&
            (u32(data+cf+i-4)&0xfc000000)==0x94000000 &&
            (w==0xaa0003f7 || (w&0xfc000000)==0x14000000) &&
            u32(data+cf+i+4)==0xd10343a0 && u32(data+cf+i+8)==0x52800001 && u32(data+cf+i+12)==0x52800822) { site=code->vm+i;matches++; }
    }
    if (matches!=1) die("unrecognized IOImageLoader comparison; cannot establish intact verification");
    size_t sf=fileoff(k,site,4);uint32_t w=u32(data+sf);
    uint64_t callsite=site-4,target=callsite+sx(u32(data+sf-4)&0x3ffffff,26)*4;
    if (stub_target(k,target)!=symbol(k,"_memcmp")) die("SHA comparison does not call memcmp");
    if (w==0xaa0003f7) { puts("Verification instructions are original; no code patch applied.");return; }
    struct seg *hc=segment(hash,"__TEXT_EXEC"),*hd=segment(hash,"__DATA_CONST");
    size_t hf=fileoff(k,hc->vm,(size_t)hc->fs);uint64_t vt=0;
    for (size_t i=0;i+12<=hc->fs;i+=4) {
        uint32_t a=u32(data+hf+i),b=u32(data+hf+i+4),c=u32(data+hf+i+8);
        if ((a&0x9f00001f)!=0x90000008 || (b&0xffc003ff)!=0x91000108 || c!=0xf9000008) continue;
        uint64_t v=adrp_target(a,hc->vm+i)+(b>>10&4095);
        if (!inside(hd,v,0x2b8) || !inside(hc,u64(data+fileoff(k,v+0x2b0,8)),4)) continue;
        if (vt&&vt!=v) die("ambiguous WLAN vtable");vt=v;
    }
    if (!vt) die("cannot validate old override vtable");
    uint64_t cave=site+sx(w&0x3ffffff,26)*4;size_t f=fileoff(k,cave,24);
    uint32_t expected[6]={adrp(cave,vt),0x91000210|((uint32_t)(vt&4095)<<10),0xf94002f1,0xeb10023f,0x9a8003f7,branch(cave+20,site+4)};
    if (cave+24!=code->vm+code->fs || code->sz!=code->fs) die("old comparison branch is not recognized");
    for (unsigned i=0;i<6;i++) if (u32(data+f+i*4)!=expected[i]) die("old override differs from known payload");
    put32(sf,0xaa0003f7);memset(data+f,0,24);code->sz-=24;code->fs-=24;
    put64(code->cmd+32,code->sz);put64(code->cmd+48,code->fs);
    puts("Removed previous wifihax comparison override and restored original verification.");
}

static uint64_t allocate_payload(struct image *k,struct element array,size_t required) {
    struct seg *dc=segment(k,"__PLK_DATA_CONST");size_t f=fileoff(k,dc->vm,(size_t)dc->fs);
    unsigned char *busy=calloc((size_t)dc->fs,1);if (!busy) die("out of memory");
    for (const char *p=skip(array.content,array.close);p<array.close;) {
        struct element e=element(p,array.close,0),v=get(e,"_PrelinkExecutableLoadAddr",NULL);
        if (v.start) {
            uint64_t addr=numeric(v);size_t h=fileoff(k,addr,104);
            /* KPI pseudoheaders contain no mapped segments. */
            if (u32(data+h+32)!=25 || memcmp(data+h+40,"__LINKEDIT",10) || u64(data+h+56)) {
                struct image other;parse(&other,h);
                for (unsigned j=0;j<other.count;j++) {
                    struct seg *s=&other.segs[j];uint64_t lo=s->vm>dc->vm?s->vm:dc->vm,hi=s->vm+s->sz;
                    if (hi>dc->vm+dc->fs) hi=dc->vm+dc->fs;
                    if (hi>lo) memset(busy+lo-dc->vm,1,(size_t)(hi-lo));
                }
            }
        }
        p=skip(e.end,array.close);
    }
    uint64_t chosen=0;size_t best=SIZE_MAX;
    for (size_t i=0;i<dc->fs;) {
        if (busy[i]||data[f+i]) { i++;continue; }
        size_t begin=i;while (i<dc->fs&&!busy[i]&&!data[f+i]) i++;
        begin=(begin+7)&~(size_t)7;
        if (i>=begin && i-begin>=required && i-begin<best) { best=i-begin;chosen=dc->vm+begin; }
    }
    free(busy);if (!chosen) die("no unowned const-data padding for private firmware records");return chosen;
}

int main(int argc,char **argv) {
    if (argc!=3 && argc!=4) { fprintf(stderr,"Usage: %s input-kernel output-kernel [wifi-directory]\n",argv[0]);return 1; }
    char rootpath[PATH_MAX];firmware_root(rootpath,argc==4?argv[3]:NULL);printf("Firmware directory: %s\n",rootpath);
    scan_firmware(rootpath,"");if (!firmware_count) die("no firmware files found");
    qsort(firmware,firmware_count,sizeof(firmware[0]),firmware_order);
    struct stat a,b;if (stat(argv[1],&a)) { perror(argv[1]);return 1; }
    if (!stat(argv[2],&b)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino) die("output aliases input");
    FILE *f=fopen(argv[1],"rb");if (!f) { perror(argv[1]);return 1; }
    if (fseek(f,0,SEEK_END)) die("cannot seek input");long len=ftell(f);
    if (len<32 || fseek(f,0,SEEK_SET)) die("invalid input length");data_size=(size_t)len;data=alloc(data_size);
    if (fread(data,1,data_size,f)!=data_size) die("input read failed");fclose(f);
    struct image kernel,loader,hash;parse(&kernel,0);struct seg *pi=segment(&kernel,"__PRELINK_INFO");
    size_t pf=fileoff(&kernel,pi->vm,(size_t)pi->fs);
    const char *xml=(char *)data+pf,*end=memchr(xml,0,(size_t)pi->fs);if (!end) die("unterminated prelink XML");
    struct element top=element(skip(xml,end),end,0),array=get(top,"_PrelinkInfoDictionary",NULL);
    if (!tag(array,"array")) die("prelink kext array missing");
    uint64_t hv=loadaddr(array,"com.apple.driver.AppleBCMWLANFirmware.Hashstore"),lv=loadaddr(array,"com.apple.driver.IOImageLoader");
    parse(&hash,fileoff(&kernel,hv,32));parse(&loader,fileoff(&kernel,lv,32));
    restore_previous_override(&kernel,&loader,&hash);
    struct hashstore store=find_store(&kernel,&hash);struct seg *dc=segment(&hash,"__DATA_CONST");
    struct element kaslr=get(top,"_PrelinkLinkKASLROffsets",NULL);uint32_t count;
    uint32_t *relocs=read_relocs(kaslr,&count);uint32_t original_count=count;
    uint64_t base=segment(&kernel,"__PRELINK_TEXT")->vm;size_t changed=0;
    for (size_t n=0;n<firmware_count;n++) {
        struct firmware *fw=&firmware[n];unsigned found=0;
        for (uint32_t i=0;i<store.count;i++) {
            uint64_t record=u64(data+fileoff(&kernel,store.array+(uint64_t)i*8,8));
            if (!inside(dc,record,16)) die("hashstore record outside const data");
            size_t rf=fileoff(&kernel,record,16);uint64_t key=u64(data+rf),value=u64(data+rf+8);
            if (memcmp(digest(&kernel,key),fw->key,32)) continue;
            if (found++) die("duplicate filename digest in hashstore");
            size_t vf=fileoff(&kernel,value,24);fw->record=record;fw->value=value;
            fw->digest=u64(data+vf);fw->flags=u32(data+vf+8);fw->extra=u64(data+vf+16);
            if (fw->flags) die("unsupported compressed firmware descriptor");
            const unsigned char *old=digest(&kernel,fw->digest);uint32_t old_size=u32(data+vf+12);
            fw->changed=memcmp(old,fw->sha,32)||old_size!=fw->size;changed+=fw->changed;
            printf("%s  %u bytes  SHA256=",fw->relative,fw->size);print_sha(fw->sha);
            printf("  [%s]\n",fw->changed?"UPDATE":"MATCH");
            if (fw->changed) { printf("  Old size=%u SHA256=",old_size);print_sha(old);putchar('\n'); }
            if (!has_reloc(relocs,count,(uint32_t)(record+8-base))) die("record pointer lacks KASLR tracking");
        }
        if (!found) die("firmware filename has no hashstore record; cannot repair by guessing");
    }
    if (changed) {
        struct seg *linkedit=NULL;
        for (unsigned i=0;i<hash.count;i++) {
            if (!strcmp(hash.segs[i].name,"__HASH_FIX")) die("existing hash repair differs from current firmware; start with original input");
            if (!strcmp(hash.segs[i].name,"__LINKEDIT")) linkedit=&hash.segs[i];
        }
        if (!linkedit || linkedit->sz || linkedit->fs || u32(data+linkedit->cmd+64)) die("no empty LINKEDIT command for firmware-record ownership");
        size_t bytes=changed*64;uint64_t payload=allocate_payload(&kernel,array,bytes);size_t payloadf=fileoff(&kernel,payload,bytes),headerf=fileoff(&kernel,hv,32);
        if (payloadf<headerf) die("record segment precedes embedded header");
        size_t slot=0;
        for (size_t n=0;n<firmware_count;n++) {
            struct firmware *fw=&firmware[n];if (!fw->changed) continue;
            uint64_t desc=payload+slot*64,blob=desc+24;size_t df=fileoff(&kernel,desc,64);
            put64(df,blob);put32(df+8,fw->flags);put32(df+12,fw->size);put64(df+16,fw->extra);
            put32(df+24,32);memcpy(data+df+28,fw->sha,32);
            put64(fileoff(&kernel,fw->record+8,8),desc);
            add_reloc(relocs,&count,base,desc);add_reloc(relocs,&count,base,desc+16);slot++;
        }
        size_t sc=linkedit->cmd;memset(data+sc+8,0,64);memcpy(data+sc+8,"__HASH_FIX",10);
        put64(sc+24,payload);put64(sc+32,bytes);put64(sc+40,payloadf-headerf);put64(sc+48,bytes);put32(sc+56,1);put32(sc+60,1);
        replace_relocs(kaslr,relocs,count,pf,(size_t)pi->fs);
        printf("Installed %zu private records at VM 0x%llx; added %u KASLR pointer records.\n",changed,(unsigned long long)payload,count-original_count);
    } else puts("All firmware hashes and sizes already match; hashstore unchanged.");
    save(argv[2],data,data_size);
    printf("Verification remains enabled. Output: %s (%zu bytes)\n",argv[2],data_size);
    free(relocs);free(data);return 0;
}
