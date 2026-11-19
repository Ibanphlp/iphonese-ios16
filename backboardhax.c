/* backboardhax: compact nil UI-sensor wrappers before applyUIMode: dispatch.
 * cc -O2 -Wall -Wextra -Werror backboardhax.c -o backboardhax
 * Usage: backboardhax input-backboardd output-backboardd
 * Finds class/method/selector stubs through Mach-O and ObjC metadata.
 * No UUID gates or fixed image offsets. Changes only the selected BL instruction.
 * The output executable must be signed using the device's existing signing flow.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#define MAX_SEG 64
#define MAX_SEC 512
static uint8_t *data;static size_t length;static uint64_t slice,slicelen,imagebase;
struct seg {uint64_t va,size,off;unsigned format;} segs[MAX_SEG];static unsigned nseg;
struct sec {char name[17];uint64_t va,size;} secs[MAX_SEC];static unsigned nsec;
static void die(const char *s){fprintf(stderr,"backboardhax: %s\n",s);exit(1);}
static uint32_t r32(const void *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t r64(const void *p){uint64_t v;memcpy(&v,p,8);return v;}
static uint32_t be(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static uint8_t *at(uint64_t off,uint64_t size){if(off>slicelen || size>slicelen-off)die("file bounds");return data+slice+off;}
static unsigned owner(uint64_t va,uint64_t size){for(unsigned i=0;i<nseg;i++)if(va>=segs[i].va && va-segs[i].va<=segs[i].size && size<=segs[i].size-(va-segs[i].va))return i;die("unmapped VA");return 0;}
static uint8_t *vm(uint64_t va,uint64_t size){unsigned i=owner(va,size);return at(segs[i].off+va-segs[i].va,size);}
static uint64_t pointer(uint64_t va){unsigned i=owner(va,8);uint64_t v=r64(vm(va,8));if(!v)return 0;
 if(!segs[i].format)return v;
 if(v>>63)die("unexpected imported or authenticated pointer");
 uint64_t target=v&((1ULL<<36)-1);
 if(segs[i].format==6)return imagebase+target;
 return target|(((v>>36)&255)<<56);
}
static bool equals(uint64_t va,const char *s){size_t n=strlen(s)+1;return !memcmp(vm(va,n),s,n);}
static int64_t sx(uint64_t v,unsigned b){return (int64_t)(v^(1ULL<<(b-1)))-(int64_t)(1ULL<<(b-1));}
static struct sec *section(const char *name){struct sec *found=NULL;for(unsigned i=0;i<nsec;i++)if(!strcmp(secs[i].name,name)){if(found)die("ambiguous section");found=&secs[i];}if(!found)die("missing section");return found;}
static void parse(void){
 slice=0;slicelen=length;
 if(length>=8 && be(data)==0xcafebabe){uint32_t count=be(data+4);if(!count || count>(length-8)/20)die("fat header bounds");unsigned matches=0;
  for(uint32_t i=0;i<count;i++){uint8_t *a=data+8+i*20;uint64_t off=be(a+8),size=be(a+12);if(off>length || size>length-off)die("fat slice bounds");if(be(a)==0x100000c && (be(a+4)&0xffffff)==0){slice=off;slicelen=size;matches++;}}
  if(matches!=1)die("need one plain arm64 slice");
 }
 uint8_t *h=at(0,32);if(r32(h)!=0xfeedfacf || r32(h+4)!=0x100000c || (r32(h+8)&0xffffff))die("expected raw plain arm64 Mach-O");
 uint64_t cmds=r32(h+20),end=32+cmds,pos=32,fixoff=0,fixsize=0;at(32,cmds);
 for(uint32_t i=0;i<r32(h+16);i++){if(pos>end || end-pos<8)die("load command bounds");uint8_t *lc=at(pos,8);uint32_t cmd=r32(lc),sz=r32(lc+4);if(sz<8 || sz>end-pos)die("load command size");lc=at(pos,sz);
  if(cmd==25){if(sz<72 || nseg==MAX_SEG || r32(lc+64)>(sz-72)/80)die("segment bounds");uint64_t va=r64(lc+24),off=r64(lc+40),bytes=r64(lc+48);at(off,bytes);segs[nseg++]=(struct seg){va,bytes,off,0};
   if(!strncmp((char *)lc+8,"__TEXT",16)){if(imagebase)die("multiple text segments");imagebase=va;}
   for(uint32_t j=0;j<r32(lc+64);j++){if(nsec==MAX_SEC)die("too many sections");uint8_t *s=lc+72+80*j;struct sec *t=&secs[nsec++];memcpy(t->name,s,16);t->name[16]=0;t->va=r64(s+32);t->size=r64(s+40);}
  }else if(cmd==0x80000034){if(sz<16 || fixsize)die("chained fixup command");fixoff=r32(lc+8);fixsize=r32(lc+12);at(fixoff,fixsize);}
  pos+=sz;
 }
 if(!imagebase)die("missing image base");
 if(fixsize){uint8_t *f=at(fixoff,fixsize);if(fixsize<28 || r32(f))die("chained fixup header");uint64_t start=r32(f+4);if(start>fixsize || fixsize-start<4)die("chained starts bounds");uint32_t count=r32(f+start);if(count!=nseg || count>(fixsize-start-4)/4)die("chained segment table");
  for(uint32_t i=0;i<count;i++){uint64_t off=r32(f+start+4+4*i);if(!off)continue;if(off>fixsize-start || fixsize-start-off<22)die("chained segment bounds");uint8_t *s=f+start+off;uint32_t size=r32(s);uint16_t fmt,pages;memcpy(&fmt,s+6,2);memcpy(&pages,s+20,2);if(size<22 || size>fixsize-start-off || pages>(size-22)/2 || (fmt!=2 && fmt!=6))die("unsupported chained pointer format");segs[i].format=fmt;}
 }
}
static uint64_t find_method(uint64_t *limit){
 struct sec *list=section("__objc_classlist");uint64_t found=0;unsigned classes=0;
 for(uint64_t a=0;a+8<=list->size;a+=8){uint64_t cl=pointer(list->va+a);uint64_t ro=pointer(cl+32)&~7ULL;uint64_t name=pointer(ro+24);if(!equals(name,"BKHIDUISensorServiceMatchingWrapper"))continue;classes++;
  uint64_t ml=pointer(ro+32);uint32_t flags=r32(vm(ml,8)),count=r32(vm(ml+4,4));uint32_t stride=(flags&0x80000000)?12:(flags&0xffff);if(stride<12 || count>4096)die("method table bounds");
  for(uint32_t i=0;i<count;i++){uint64_t entry=ml+8+(uint64_t)i*stride,n,impl;
   if(flags&0x80000000){uint8_t *e=vm(entry,12);n=entry+(int32_t)r32(e);if(!(flags&0x40000000))n=pointer(n);impl=entry+8+(int32_t)r32(e+8);}
   else{if(stride<24)die("method entry size");n=pointer(entry);impl=pointer(entry+16);}
   if(equals(n,"matcher:servicesDidMatch:")){if(found)die("duplicate target method");found=impl;}
  }
  if(!found)die("target class lacks matching callback");
  *limit=UINT64_MAX;
  for(uint32_t i=0;i<count;i++){uint64_t e=ml+8+(uint64_t)i*stride;uint64_t impl=(flags&0x80000000)?e+8+(int32_t)r32(vm(e+8,4)):pointer(e+16);if(impl>found && impl<*limit)*limit=impl;}
 }
 if(classes!=1 || !found || *limit==UINT64_MAX || *limit-found>0x4000)die("target method not uniquely bounded");return found;
}
static uint64_t selector_stub(const char *name){
 struct sec *s=section("__objc_stubs");uint64_t found=0;
 for(uint64_t off=0;off+20<=s->size;off+=4){uint64_t va=s->va+off;uint8_t *p=vm(va,20);uint32_t a=r32(p),b=r32(p+4);
  if((a&0x9f00001f)!=0x90000001 || (b&0xffc003ff)!=0xf9400021 || r32(p+16)!=0xd61f0200)continue;
  uint64_t page=(va&~4095ULL)+sx(((a>>5&0x7ffff)<<2)|(a>>29&3),21)*4096;uint64_t ref=page+((b>>10&4095)*8);uint64_t sel=pointer(ref);
  if(equals(sel,name)){if(found)die("ambiguous selector stub");found=va;}
 }
 if(!found)die("required selector stub missing");return found;
}
int main(int argc,char **argv){
 if(argc!=3){fprintf(stderr,"Usage: %s <input-backboardd> <output-backboardd>\n",argv[0]);return 2;}
 FILE *f=fopen(argv[1],"rb");if(!f)die("cannot open input");if(fseek(f,0,SEEK_END))die("cannot size input");long n=ftell(f);if(n<32 || fseek(f,0,SEEK_SET))die("invalid input length");length=(size_t)n;data=malloc(length);if(!data)die("allocation failed");if(fread(data,1,length,f)!=length || fclose(f))die("input read failed");parse();
 uint64_t limit=0,method=find_method(&limit),map=selector_stub("bs_map:"),compact=selector_stub("bs_compactMap:"),site=0;unsigned maps=0,already=0;
 for(uint64_t va=method;va+4<=limit;va+=4){uint32_t w=r32(vm(va,4));if((w&0xfc000000)!=0x94000000)continue;uint64_t dest=va+sx(w&0x3ffffff,26)*4;if(dest==map){maps++;site=va;}if(dest==compact)already++;}
 if(maps==1 && !already){int64_t delta=(int64_t)compact-(int64_t)site;if(delta%4 || delta/4<-(1LL<<25) || delta/4>=(1LL<<25))die("replacement call out of range");uint32_t w=0x94000000|((uint32_t)(delta/4)&0x3ffffff);memcpy(vm(site,4),&w,4);printf("UI-sensor wrapper callback: bs_map: -> bs_compactMap: at VA 0x%llx\n",(unsigned long long)site);}
 else if(!maps && already==1)printf("UI-sensor wrapper callback is already compacting nil results.\n");
 else die("unexpected target call graph; refusing output");
 int fd=open(argv[2],O_WRONLY|O_CREAT|O_EXCL,0755);if(fd<0)die("output must be a new path");f=fdopen(fd,"wb");if(!f){close(fd);unlink(argv[2]);die("output stream failed");}if(fwrite(data,1,length,f)!=length){fclose(f);unlink(argv[2]);die("output write failed");}if(fclose(f)){unlink(argv[2]);die("output close failed");}
 printf("Wrote %s (%zu bytes, size unchanged); sign before deployment.\n",argv[2],length);free(data);return 0;
}
