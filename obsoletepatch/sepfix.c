/* sepfix: experimental iOS16 ACM transport adapter for an iOS15 SEP.
 * cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror sepfix.c -o sepfix
 * ./sepfix input-16-kernel.raw output-16-kernel.raw
 * Raw arm64 prelinked kernels only. Pattern discovery, no donor/UUID/offset gates.
 * Four instruction edits: send legacy body, parse legacy 8-byte response header,
 * zero absent metadata word, omit request-ID comparison unsupported by SEP15.
 * Does not forge keys, attestations, contexts, status or successful replies.
 * Rejects unknown/previously modified patterns. Hardware validation pending.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
typedef struct { uint32_t value, mask; } Word;
typedef struct { char name[17]; uint64_t va, size, offset; } Segment;
typedef struct { Segment seg[64]; size_t count; } Image;
static unsigned char *data;
static size_t length;
static void fail(const char *s) { fprintf(stderr,"sepfix: %s\n",s); exit(1); }
static int range(uint64_t o, uint64_t n) { return o <= length && n <= length-o; }
static uint32_t r32(size_t o) {
    if (!range(o,4)) fail("truncated 32-bit field");
    return (uint32_t)data[o] | (uint32_t)data[o+1]<<8 |
           (uint32_t)data[o+2]<<16 | (uint32_t)data[o+3]<<24;
}
static uint64_t r64(size_t o) { return r32(o) | (uint64_t)r32(o+4)<<32; }
static void w32(size_t o, uint32_t v) {
    if (!range(o,4)) fail("patch outside input");
    for (unsigned j=0;j<4;j++) data[o+j]=(unsigned char)(v>>(8*j));
}
/* Embedded kext segment file offsets are deliberately ignored: resolve their
 * virtual addresses through the outer kernel's file-backed segments. */
static int parse(size_t o, Image *im, int outer) {
    memset(im,0,sizeof(*im));
    if (!range(o,32) || r32(o)!=0xfeedfacf || r32(o+4)!=0x0100000c) return 0;
    uint32_t count=r32(o+16), bytes=r32(o+20);
    if (count>4096 || !range(o+32,bytes)) return 0;
    size_t p=o+32,end=p+bytes;
    for (uint32_t j=0;j<count;j++) {
        if (p>end || end-p<8) return 0;
        uint32_t cmd=r32(p), sz=r32(p+4);
        if (sz<8 || sz>end-p || (sz&7)) return 0;
        if (cmd==0x19) {
            if (sz<72 || im->count==COUNT(im->seg)) return 0;
            if (r32(p+64)>(sz-72)/80) return 0;
            Segment *s=&im->seg[im->count++];
            memcpy(s->name,data+p+8,16); s->name[16]=0;
            s->va=r64(p+24); s->size=r64(p+48); s->offset=r64(p+40);
            if (s->size>r64(p+32) || s->va>UINT64_MAX-s->size) return 0;
            if (outer && !range(s->offset,s->size)) return 0;
        }
        p+=sz;
    }
    return p==end && im->count;
}
static Segment *segment(Image *im,const char *name) {
    Segment *found=NULL;
    for (size_t j=0;j<im->count;j++) if (!strcmp(im->seg[j].name,name)) {
        if (found) fail("duplicate segment name"); found=&im->seg[j];
    }
    return found;
}
static size_t map(Image *im,uint64_t va,size_t n) {
    size_t out=0,hits=0;
    for (size_t j=0;j<im->count;j++) {
        Segment *s=&im->seg[j];
        if (va>=s->va && va-s->va<=s->size && n<=s->size-(va-s->va)) {
            out=(size_t)(s->offset+va-s->va); hits++;
        }
    }
    if (hits!=1 || !range(out,n)) fail("unmapped or ambiguous virtual address");
    return out;
}
static const Word outgoing[] = {
    {0xb9007ff6u,0xffffffffu},
    {0xf9400bbbu,0xffffffffu},
    {0x7100129fu,0xffffffffu},
    {0x54000001u,0xff00001fu},
    {0xb400001bu,0xff00001fu},
    {0x79400762u,0xffffffffu},
    {0xd101e3a5u,0xffffffffu},
    {0xaa1303e0u,0xffffffffu},
    {0xaa1b03e1u,0xffffffffu},
    {0xaa1a03e3u,0xffffffffu},
    {0xaa1503e4u,0xffffffffu},
    {0x94000000u,0xfc000000u},
    {0x34000000u,0xff00001fu},
    {0x52805b7au,0xffffffffu},
    {0x72bc001au,0xffffffffu},
    {0x93407c08u,0xffffffffu},
    {0x5280ef89u,0xffffffffu},
    {0x14000000u,0xfc000000u},
    {0xb400001au,0xff00001fu},
    {0xb4000015u,0xff00001fu},
    {0xd101e3a5u,0xffffffffu},
    {0xaa1303e0u,0xffffffffu},
    {0xaa1a03e1u,0xffffffffu},
    {0xaa1503e2u,0xffffffffu},
    {0xd2800003u,0xffffffffu},
    {0xd2800004u,0xffffffffu},
    {0x94000000u,0xfc000000u},
    {0x35000000u,0xff00001fu},
    {0x52805b68u,0xffffffffu},
};
static const Word incoming[] = {
    {0x7100129fu,0xffffffffu},
    {0x54000001u,0xff00001fu},
    {0xb4000018u,0xff00001fu},
    {0xf940ae68u,0xffffffffu},
    {0xf1002d1fu,0xffffffffu},
    {0x54000009u,0xff00001fu},
    {0xf9400309u,0xffffffffu},
    {0xf81903a9u,0xffffffffu},
    {0xb9400b0au,0xffffffffu},
    {0xb81983aau,0xffffffffu},
    {0x72001d3fu,0xffffffffu},
    {0x54000000u,0xff00001fu},
    {0xb9400769u,0xffffffffu},
    {0xb85943b5u,0xffffffffu},
    {0x6b15013fu,0xffffffffu},
    {0x54000000u,0xff00001fu},
    {0x90000009u,0x9f00001fu},
    {0x394fc129u,0xffffffffu},
    {0x7100f13fu,0xffffffffu},
    {0x54000008u,0xff00001fu},
    {0xf9400268u,0xffffffffu},
    {0xf940f508u,0xffffffffu},
    {0xaa1303e0u,0xffffffffu},
    {0xd2800001u,0xffffffffu},
    {0xd63f0100u,0xffffffffu},
    {0xb9400768u,0xffffffffu},
    {0x90000009u,0x9f00001fu},
    {0x91134529u,0xffffffffu},
    {0xa90157e8u,0xffffffffu},
    {0xa90027e0u,0xffffffffu},
    {0x90000000u,0x9f00001fu},
    {0x911b0400u,0xffffffffu},
    {0x94000000u,0xfc000000u},
    {0xf940ae68u,0xffffffffu},
    {0x785923a9u,0xffffffffu},
    {0xeb09010au,0xffffffffu},
    {0x54000003u,0xff00001fu},
    {0xf9400fa8u,0xffffffffu},
};

static int contains(size_t at,size_t size,const char *str){size_t n=strlen(str)+1;if(n>size)return 0;for(size_t p=0;p<=size-n;p++)if(!memcmp(data+at+p,str,n))return 1;return 0;}
static size_t locate(size_t at,size_t size,const Word *sig,size_t count){size_t found=0,hits=0;if(size<count*4)fail("short code section");for(size_t p=at;p<=at+size-count*4;p+=4){size_t i=0;for(;i<count;i++)if((r32(p+i*4)&sig[i].mask)!=sig[i].value)break;if(i==count){found=p;hits++;}}if(hits!=1)fail("expected one unmodified ACM pattern; unsupported or already patched kernel");return found;}
static int64_t sx(uint32_t v,unsigned bits){return (int64_t)(v^(1u<<(bits-1)))-(int64_t)(1u<<(bits-1));}
static uint64_t cond_target(size_t p,uint64_t pc){return pc+(uint64_t)(sx((r32(p)>>5)&0x7ffff,19)*4);}
static uint64_t cb_target(size_t p,uint64_t pc){return cond_target(p,pc);}
static uint32_t jump(uint64_t pc,uint64_t dest){int64_t d=(int64_t)(dest-pc);if(d%4||d/4<-(1<<25)||d/4>=(1<<25))fail("branch range");return 0x14000000|((uint32_t)(d/4)&0x3ffffff);}
static void publish(const char *path){size_t n=strlen(path);if(n>SIZE_MAX-16)fail("long output path");char *tmp=malloc(n+16);if(!tmp)fail("allocation failed");snprintf(tmp,n+16,"%s.tmp.XXXXXX",path);int fd=mkstemp(tmp);if(fd<0)fail("cannot create temporary output");int err=0;size_t off=0;while(off<length){ssize_t z=write(fd,data+off,length-off);if(z<0&&errno==EINTR)continue;if(z<=0){err=1;break;}off+=(size_t)z;}if(!err&&fsync(fd))err=1;if(close(fd))err=1;if(!err&&link(tmp,path))err=1;unlink(tmp);free(tmp);if(err)fail("output failed or already exists; existing paths never overwritten");}
int main(int argc,char **argv){
 if(argc!=3){fprintf(stderr,"Usage: %s [input 16 kernel] [output 16 kernel]\n",argv[0]);return 2;}
 FILE *f=fopen(argv[1],"rb");if(!f)fail("cannot open input");struct stat st;if(fstat(fileno(f),&st)||!S_ISREG(st.st_mode)||st.st_size<32||(uintmax_t)st.st_size>SIZE_MAX)fail("invalid input");length=(size_t)st.st_size;data=malloc(length);if(!data)fail("allocation failed");if(fread(data,1,length,f)!=length||fclose(f))fail("read failed");
 Image outer;if(!parse(0,&outer,1)||r32(12)!=2)fail("expected raw arm64 prelinked kernel");Segment *pre=segment(&outer,"__PRELINK_TEXT");if(!pre||!range(pre->offset,pre->size))fail("missing prelink text");
 Image acm={0};size_t hits=0;
 for(size_t h=(size_t)pre->offset;h+32<=pre->offset+pre->size;h+=4){if(r32(h)!=0xfeedfacf)continue;Image im;if(!parse(h,&im,0))continue;Segment *t=segment(&im,"__TEXT"),*x=segment(&im,"__TEXT_EXEC");if(!t||!x||!t->size||!x->size)continue;size_t off=map(&outer,t->va,(size_t)t->size);
  if(contains(off,(size_t)t->size,"sendSEPCommand")&&contains(off,(size_t)t->size,"processSCRDResponsePayload")&&contains(off,(size_t)t->size,"_sepContext.responseDataLength >= sizeof(SCRDResponsePayload_v1)")){acm=im;hits++;}
 }
 if(hits!=1)fail("missing or ambiguous credential-manager image");Segment *code=segment(&acm,"__TEXT_EXEC");size_t co=map(&outer,code->va,(size_t)code->size);
 size_t out=locate(co,(size_t)code->size,outgoing,COUNT(outgoing)),in=locate(co,(size_t)code->size,incoming,COUNT(incoming));
 uint64_t ov=code->va+out-co,iv=code->va+in-co;
 if(cond_target(out+12,ov+12)!=ov+72||cb_target(out+48,ov+48)!=ov+112||cb_target(out+72,ov+72)!=ov+112||cb_target(out+76,ov+76)!=ov+112)fail("unexpected outbound copy branch topology");
 if(cond_target(in+4,iv+4)!=iv+192||cond_target(in+60,iv+60)!=iv+136)fail("unexpected response parser topology");
 size_t edits[]={out+12,in+16,in+32,in+48};uint32_t words[]={jump(ov+12,ov+72),0xf1001d1f,0x5280000a,jump(iv+48,iv+136)};
 for(size_t i=0;i<COUNT(edits);i++){w32(edits[i],words[i]);printf("ACM legacy wire edit: file +0x%zx -> 0x%08x\n",edits[i],words[i]);}
 publish(argv[2]);free(data);printf("Wrote %s (%zu bytes, unchanged size). Experimental ACM envelope bridge; device validation required.\n",argv[2],length);return 0;
}
