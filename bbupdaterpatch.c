/* SE1 BBUpdater model compatibility patch, iOS 16.1 restore userspace.
 * cc -std=c11 -O2 -Wall -Wextra -Wpedantic bbupatch.c -o bbupatch
 * ./bbupatch input-libTelephonyUtilDynamic.dylib output.dylib
 * No donor, UUID gate, fixed file offsets, or runtime addresses.
 * Experimental: N69AP/N69uAP -> existing J72s product/radio/vendor profile.
 * Code signature becomes stale; signing/trust is a separate deployment step.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define N(a) (sizeof(a)/sizeof((a)[0]))
typedef struct { uint32_t v,m; } Word;
typedef struct { uint64_t va,off,size; } Region;
static unsigned char *b;
static size_t size;
static void die(const char *s) { fprintf(stderr,"bbupatch: %s\n",s);exit(1); }
static int fits(uint64_t o,uint64_t n) { return o<=size && n<=size-o; }
static uint32_t u32(size_t p) {
 if(!fits(p,4)) die("truncated field");
 return (uint32_t)b[p]|(uint32_t)b[p+1]<<8|(uint32_t)b[p+2]<<16|(uint32_t)b[p+3]<<24;
}
static uint64_t u64(size_t p) { return u32(p)|(uint64_t)u32(p+4)<<32; }
static void put32(size_t p,uint32_t v) {
 if(!fits(p,4))die("write outside file");
 for(unsigned i=0;i<4;i++)b[p+i]=(unsigned char)(v>>(8*i));
}
static int nameis(size_t p,const char *s) { return !strncmp((char *)b+p,s,16); }
static uint64_t va(Region r,size_t off) {
 if(off<r.off || off-r.off>=r.size)die("address outside region");
 return r.va+off-r.off;
}
static size_t fileoff(Region r,uint64_t a) {
 if(a<r.va || a-r.va>=r.size)die("target outside executable section");
 return (size_t)(r.off+a-r.va);
}
static size_t match(Region r,const Word *sig,size_t n,const char *label) {
 size_t hits=0,result=0;
 if(n>r.size/4)die("section too small");
 for(size_t i=0;i<=r.size-n*4;i+=4) {
  size_t j=0;
  for(;j<n;j++)if((u32((size_t)r.off+i+j*4)&sig[j].m)!=sig[j].v)break;
  if(j==n){hits++;result=(size_t)r.off+i;}
 }
 if(hits!=1){fprintf(stderr,"bbupatch: %s: expected one pattern, found %zu; no output\n",label,hits);exit(1);}
 return result;
}
#define W(x) {x,0xffffffffu}
#define PAGE(r) {0x90000000u|(r),0x9f00001fu}
/* Last model comparison + unknown-model fallback. Captures the invariant
 * x14=model pointer, x11=packed model key. Relocatable branches are masked. */
static const Word fallback[]={
 W(0xf94001cb), W(0xf85983ac), W(0xeb0c017f), {0x54000001,0xff00001f},
 W(0x7100153f), {0x54000000,0xff00001f}, W(0x7100155f),{0x54000000,0xff00001f},
 W(0x6b09015f),{0x54000000,0xff00001f},{0x3400000a,0xff00001f},{0x34000009,0xff00001f},
 PAGE(9),W(0xb900513f),PAGE(9),W(0xb900553f),PAGE(9),W(0xb900593f),W(0xb900a11f),
 {0x14000000,0xfc000000}
};
/* J72s product=57, adjacent J72t product=68, shared radio=1 path. */
static const Word profile[]={
 PAGE(8),W(0x52800729),{0x14000000,0xfc000000},
 PAGE(8),W(0x52800889),W(0xb9005109),PAGE(8),W(0x52800029),W(0xb9005509),
 PAGE(8),{0x14000000,0xfc000000}
};
static const Word vendor_end[]={
 W(0xb9005909),W(0x911383ff),W(0xa9457bfd),W(0xa9444ff4),
 W(0xa94357f6),W(0xa9425ff8),W(0xa94167fa),W(0xa8c66ffc),W(0xd65f03c0)
};
static int64_t signed_bits(uint64_t v,unsigned n) {
 uint64_t sign=UINT64_C(1)<<(n-1);
 return (v&sign)?(int64_t)v-(INT64_C(1)<<n):(int64_t)v;
}
static uint64_t branch_target(uint32_t ins,uint64_t pc,unsigned bits,unsigned shift) {
 return pc+(uint64_t)(signed_bits((ins>>shift)&((UINT64_C(1)<<bits)-1),bits)*4);
}
static uint64_t page_target(uint32_t w,uint64_t pc) {
 return (pc&~UINT64_C(4095))+(uint64_t)(signed_bits(((w>>5)&0x7ffff)*4+((w>>29)&3),21)*4096);
}
static uint32_t page_ins(unsigned reg,uint64_t pc,uint64_t target) {
 int64_t delta=(int64_t)(target&~UINT64_C(4095))-(int64_t)(pc&~UINT64_C(4095));
 int64_t pages=delta/4096;
 if(pages<-(INT64_C(1)<<20)||pages>=(INT64_C(1)<<20))die("ADRP out of range");
 uint32_t imm=(uint32_t)pages&0x1fffff;
 return 0x90000000u|((imm&3)<<29)|((imm>>2)<<5)|reg;
}
static uint32_t jump(uint64_t from,uint64_t to,int cond) {
 int64_t delta=(int64_t)to-(int64_t)from;
 unsigned bits=cond<0?26:19;
 if(delta%4 || delta/4<-(INT64_C(1)<<(bits-1)) || delta/4>=(INT64_C(1)<<(bits-1)))die("branch out of range");
 uint32_t imm=(uint32_t)(delta/4)&((1u<<bits)-1);
 return cond<0?0x14000000u|imm:0x54000000u|(imm<<5)|(unsigned)cond;
}
static void save(const char *path) {
 size_t len=strlen(path);if(len>SIZE_MAX-16)die("path too long");
 char *tmp=malloc(len+16);if(!tmp)die("allocation failed");
 snprintf(tmp,len+16,"%s.tmp.XXXXXX",path);int fd=mkstemp(tmp);
 if(fd<0){perror("bbupatch: temporary output");exit(1);}
 int err=0;size_t done=0;
 while(done<size){size_t n=size-done;if(n>1048576)n=1048576;
  ssize_t wrote=write(fd,b+done,n);if(wrote<0&&errno==EINTR)continue;
  if(wrote<=0){err=errno?errno:EIO;break;}done+=(size_t)wrote;}
 if(!err&&fsync(fd))err=errno;
 if(close(fd)&&!err)err=errno;
 if(!err&&link(tmp,path))err=errno;
 unlink(tmp);free(tmp);
 if(err){errno=err;perror("bbupatch: publish output (existing destinations are refused)");exit(1);}
}
int main(int argc,char **argv) {
 if(argc!=3){fprintf(stderr,"usage: %s [input libTelephonyUtilDynamic.dylib] [output dylib]\n",argv[0]);return 2;}
 FILE *in=fopen(argv[1],"rb");if(!in){perror("bbupatch: input");return 1;}
 struct stat st;if(fstat(fileno(in),&st)||!S_ISREG(st.st_mode)||st.st_size<32||(uintmax_t)st.st_size>SIZE_MAX)die("bad input size/type");
 size=(size_t)st.st_size;b=malloc(size);if(!b)die("allocation failed");
 if(fread(b,1,size,in)!=size)die("input read failed");if(fclose(in))die("input close failed");
 if(u32(0)!=0xfeedfacf||u32(4)!=0x0100000c||u32(12)!=6)die("expected a thin ARM64 Mach-O dylib");
 if((u32(8)&0xffffff)!=0)die("only plain ARM64 is supported (not arm64e)");
 uint32_t nc=u32(16),nb=u32(20);
 if(nc>4096||!fits(32,nb))die("invalid load commands");
 size_t end=32+(size_t)nb,p=32,first=SIZE_MAX;Region text={0},code={0};int idok=0,signature=0;
 for(uint32_t i=0;i<nc;i++){
  if(p>end||end-p<8)die("truncated load command");uint32_t cmd=u32(p),sz=u32(p+4);
  if(sz<8||(sz&7)||sz>end-p)die("invalid load command length");
  if(cmd==0xd){
   if(sz<24)die("short dylib ID");uint32_t n=u32(p+8);if(n<24||n>=sz||!memchr(b+p+n,0,sz-n))die("bad dylib ID");
   if(strcmp((char *)b+p+n,"/usr/lib/libTelephonyUtilDynamic.dylib"))die("wrong dylib: patch libTelephonyUtilDynamic.dylib, not libBBUpdaterDynamic.dylib");
   idok++;
  }
  if(cmd==0x1d){if(sz!=16||!fits(u32(p+8),u32(p+12)))die("invalid code signature command");signature=1;}
  if(cmd==0x2c||cmd==0x21){if(sz<20||u32(p+16))die("encrypted dylib unsupported");}
  if(cmd==0x19){
   if(sz<72||u32(p+64)>(sz-72)/80)die("invalid segment");
   Region r={u64(p+24),u64(p+40),u64(p+48)};
   if(!fits(r.off,r.size)||r.size>u64(p+32)||r.va>UINT64_MAX-u64(p+32))die("invalid segment extent");
   if(nameis(p+8,"__TEXT")){
    if(text.size||r.off!=0||r.size<end||!(u32(p+60)&4))die("unsupported executable TEXT layout");text=r;
    for(uint32_t j=0;j<u32(p+64);j++){
     size_t q=p+72+(size_t)j*80;Region s={u64(q+32),u32(q+48),u64(q+40)};
     if(!s.size)continue;
     if(!fits(s.off,s.size)||s.off<r.off||s.off-r.off>r.size||s.size>r.size-(s.off-r.off)||s.va!=r.va+s.off-r.off||s.off<end)die("invalid TEXT section");
     if(s.off<first)first=(size_t)s.off;
     if(nameis(q,"__text")){if(code.size)die("duplicate text section");code=s;}
    }
   }
  }
  p+=sz;
 }
 if(p!=end||idok!=1||!text.size||!code.size||code.off%4||code.size%4)die("unsupported Mach-O layout");
 size_t f=match(code,fallback,N(fallback),"unknown-model fallback");
 size_t prof=match(code,profile,N(profile),"J72s profile");
 size_t ve=match(code,vendor_end,N(vendor_end),"vendor store and epilogue");
 size_t site=f+12*4;
 /* Validate original control flow and all shared output globals. */
 if(branch_target(u32(f+12),va(code,f+12),19,5)!=va(code,site))die("fallback comparison target mismatch");
 if(branch_target(u32(prof+8),va(code,prof+8),26,0)!=va(code,prof+20))die("J72s branch mismatch");
 if(branch_target(u32(prof+40),va(code,prof+40),26,0)!=va(code,ve))die("vendor branch mismatch");
 if(branch_target(u32(site+28),va(code,site+28),26,0)!=va(code,ve+4))die("fallback epilogue mismatch");
 uint64_t globals=page_target(u32(site),va(code,site));
 size_t refs[]={site+8,site+16,prof,prof+12,prof+24,prof+36};
 for(size_t i=0;i<N(refs);i++)if(page_target(u32(refs[i]),va(code,refs[i]))!=globals)die("profile globals mismatch");
 /* Ensure last comparison's x14 load and all tested branch targets stay local. */
 for(size_t i=5;i<=11;i+=2){
  uint64_t target=branch_target(u32(f+i*4),va(code,f+i*4),19,5);
  (void)fileoff(code,target);
 }
 /* Place a leaf stub only in zero header-to-first-section padding, never in
  * a section or at an assumed offset. Keep Mach-O layout and size unchanged. */
 enum { WORDS=12 };size_t cave=0,run=0;
 for(size_t q=(end+3)&~(size_t)3;q+4<=first;q+=4){
  if(u32(q)==0)run++;else run=0;
  if(run==WORDS){cave=q+4-WORDS*4;break;}
 }
 if(!cave)die("no 48-byte zero executable header padding; no output");
 uint64_t cv=va(text,cave),sv=va(code,site),pv=va(code,prof);
 uint32_t stub[WORDS]={
  0xb94009c9, /* ldr w9,[x14,#8] : AP platform kind */
  0x7100093f, /* cmp w9,#2 */
  0,          /* b.ne original fallback */
  0xd28008a9, /* mov x9,#69 */
  0xf2c009c9, /* movk x9,#0x4e,lsl #32 : N69 */
  0xeb09017f, /* cmp x11,x9 */
  0,          /* b.eq J72s */
  0xf2cea9c9, /* movk x9,#0x754e,lsl #32 : N69u */
  0xeb09017f, /* cmp x11,x9 */
  0,          /* b.eq J72s */
  0,          /* replay displaced ADRP x9 */
  0           /* b original fallback+4 */
 };
 stub[2]=jump(cv+8,cv+40,1);
 stub[6]=jump(cv+24,pv,0);stub[9]=jump(cv+36,pv,0);
 stub[10]=page_ins(9,cv+40,globals);stub[11]=jump(cv+44,sv+4,-1);
 uint32_t redirect=jump(sv,cv,-1);
 for(size_t i=0;i<WORDS;i++)put32(cave+i*4,stub[i]);
 put32(site,redirect);
 save(argv[2]);free(b);
 printf("Patched N69AP/N69uAP -> existing J72s profile (product=57, radio=1, vendor=1).\n"
        "Selector file +0x%zx; stub +0x%zx; profile +0x%zx.\n"
        "Wrote %s (%zu bytes). No donor or UUID checks.\n",site,cave,prof,argv[2],size);
 if(signature)puts("Output's original code signature is stale; re-sign and update your ramdisk trust setup before loading it.");
 return 0;
}
