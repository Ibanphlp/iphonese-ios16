/* wlanhax -- WLAN dext image/hashstore verification success shim.
 * Build: cc -O2 -Wall -Wextra -Werror wlanhax.c -o wlanhax
 * Usage: wlanhax input-dext-executable output-dext-executable
 * Identifies requestImageVerify through Mach-O's indirect-symbol metadata and
 * validates its arm64 ADRP/LDR/BR stub. No fixed file offsets or UUID checks.
 * Replaces the first eight stub bytes with MOV W0,#0; RET (IOReturn success).
 * Always replaces the validated setLMTPC entry with RET, avoiding
 * its LPC writes. Country-code handling and other commands remain intact.
 * Legacy --skip-lpc is accepted as a redundant compatibility argument.
 * Bytes outside selected edits and total length are preserved. Re-sign before use.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#define MAX_SECTIONS 1024
static const char verifier[]="__Z18requestImageVerifyPK12OSDictionaryPK29IOFileValidationTrustedFile_sm";
static uint8_t *data;static size_t length;static uint64_t base,span;
static void die(const char *s){fprintf(stderr,"wlanhax: %s\n",s);exit(1);}
static uint32_t u32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t u64(const uint8_t *p){uint64_t v;memcpy(&v,p,8);return v;}
static uint32_t be32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static uint64_t be64(const uint8_t *p){return (uint64_t)be32(p)<<32|be32(p+4);}
static uint8_t *at(uint64_t off,uint64_t n){if(off>span || n>span-off)die("slice bounds violation");return data+base+off;}
static int64_t sx(uint64_t v,unsigned b){return (int64_t)(v^(1ULL<<(b-1)))-(int64_t)(1ULL<<(b-1));}
struct section {char name[17],segment[17];uint64_t va,size;uint32_t off,flags,first,stride;};
static struct section sections[MAX_SECTIONS];static unsigned nsections;
static void slice(void){
 base=0;span=length;if(length<8)return;uint32_t magic=be32(data);
 if(magic!=0xcafebabe && magic!=0xcafebabf)return;
 uint32_t stride=magic==0xcafebabf?32:20,count=be32(data+4);if(!count || count>(length-8)/stride)die("invalid universal table");unsigned matches=0;
 for(uint32_t j=0;j<count;j++){
  const uint8_t *a=data+8+(uint64_t)j*stride;uint64_t off=stride==32?be64(a+8):be32(a+8),size=stride==32?be64(a+16):be32(a+12);
  if(off<8+(uint64_t)count*stride || off>length || size>length-off)die("universal slice bounds");
  if(be32(a)==0x100000c && (be32(a+4)&0xffffff)==0){base=off;span=size;matches++;}
 }
 if(matches!=1)die("expected exactly one plain arm64 slice");
}
/* This method only programs the LPC parameter. Skip it before its prologue,
 * leaving country-code updates, other IOVars and fault handling intact. */
static struct section *text_section(void){
 struct section *text=NULL;
 for(unsigned j=0;j<nsections;j++)if(!strcmp(sections[j].segment,"__TEXT") && !strcmp(sections[j].name,"__text")){if(text)die("ambiguous text section");text=&sections[j];}
 if(!text)die("missing text section");return text;
}
static uint64_t text_offset(struct section *t,uint64_t va,uint64_t n){
 if(va<t->va || va-t->va>t->size || n>t->size-(va-t->va))die("LPC code outside text section");return t->off+va-t->va;
}
static void skip_lpc(uint32_t symoff,uint32_t nsyms,uint32_t stroff,uint32_t strsize){
 const char *name="__ZN16AppleBCMWLANCore8setLMTPCEv";
 struct section *text=text_section();uint64_t start=0,limit=text->va+text->size;unsigned matches=0;
 for(uint32_t j=0;j<nsyms;j++){
  uint8_t *sym=at(symoff+(uint64_t)j*16,16);uint32_t idx=u32(sym);
  if(idx>=strsize || !memchr(at(stroff+idx,strsize-idx),0,strsize-idx))die("invalid local symbol name");
  if(strcmp((char *)at(stroff+idx,1),name))continue;
  if((sym[4]&0xee)!=0x0e)die("LPC target is not a defined section symbol");
  start=u64(sym+8);matches++;
 }
 if(matches!=1 || start%4)die("setLMTPC is missing or ambiguous");
 for(uint32_t j=0;j<nsyms;j++){
  uint8_t *sym=at(symoff+(uint64_t)j*16,16);uint64_t va=u64(sym+8);
  if((sym[4]&0xee)==0x0e && va>start && va<limit && va>=text->va && va-text->va<text->size)limit=va;
 }
 if(limit<=start || limit-start<40 || limit-start>0x1000 || (limit-start)%4)die("unsupported LPC function extent");
 uint64_t off=text_offset(text,start,limit-start);uint8_t *code=at(off,limit-start);
 bool patched=u32(code)==0xd65f03c0;
 const uint32_t prefix[]={0xd10203ff,0xa9064ff4,0xa9077bfd,0x9101c3fd,0xaa0003f3};
 for(unsigned j=0;j<5;j++)if(!(j==0 && patched) && u32(code+j*4)!=prefix[j])die("unexpected LPC entry pattern");
 if((u32(code+20)&0x9f00001f)!=0x90000008 || (u32(code+24)&0xffc003ff)!=0xf9400108 ||
    u32(code+28)!=0xf9400108 || u32(code+32)!=0xf81e83a8 || u32(code+36)!=0xf9402408)die("unexpected LPC entry context");
 unsigned lpc_refs=0,xz_refs=0,callers=0;
 for(uint64_t j=0;j+8<=limit-start;j+=4){
  uint32_t a=u32(code+j),b=u32(code+j+4);if((a&0x9f00001f)!=0x90000001 || (b&0xffc003ff)!=0x91000021)continue;
  uint64_t page=((start+j)&~4095ULL)+sx(((a>>5&0x7ffff)<<2)|(a>>29&3),21)*4096;
  uint64_t target=page+(b>>10&4095);
  for(unsigned k=0;k<nsections;k++){
   struct section *sec=&sections[k];if(strcmp(sec->name,"__cstring") || target<sec->va || target-sec->va>=sec->size)continue;
   uint64_t left=sec->size-(target-sec->va);uint8_t *v=at(sec->off+target-sec->va,left);
   if(left>=4 && !memcmp(v,"lpc",4))lpc_refs++;
   if(left>=3 && !memcmp(v,"XZ",3))xz_refs++;
  }
 }
 if(lpc_refs!=2 || xz_refs!=1)die("LPC function lacks expected parameter/country anchors");
 for(uint64_t j=0;j+4<=text->size;j+=4){uint32_t w=u32(at(text->off+j,4));if((w&0xfc000000)==0x94000000 && text->va+j+sx(w&0x3ffffff,26)*4==start)callers++;}
 if(!callers)die("LPC function has no direct callers");
 if(!patched){uint32_t ret=0xd65f03c0;memcpy(code,&ret,4);}
 printf("%s setLMTPC entry at VA 0x%llx: skip LPC write; %u direct callers, country handling retained.\n",patched?"Preserved already-patched":"Patched",(unsigned long long)start,callers);
}
int main(int argc,char **argv){
 if(argc!=3 && (argc!=4 || strcmp(argv[3],"--skip-lpc"))){fprintf(stderr,"Usage: %s <input-dext-executable> <output-dext-executable> [--skip-lpc]\n",argv[0]);return 2;}
 FILE *f=fopen(argv[1],"rb");if(!f)die("cannot open input");if(fseek(f,0,SEEK_END))die("cannot size input");long size=ftell(f);if(size<32 || fseek(f,0,SEEK_SET))die("invalid input size");length=(size_t)size;
 data=malloc(length);if(!data)die("allocation failed");if(fread(data,1,length,f)!=length || fclose(f))die("input read failed");slice();
 uint8_t *h=at(0,32);if(u32(h)!=0xfeedfacf || u32(h+4)!=0x100000c || (u32(h+8)&0xffffff) || u32(h+12)!=2)die("expected plain arm64 Mach-O executable");
 uint64_t end=32ULL+u32(h+20),pos=32;at(32,u32(h+20));
 uint32_t symoff=0,nsyms=0,stroff=0,strsize=0,indirect=0,nindirect=0;unsigned symcommands=0,dycommands=0;
 for(uint32_t i=0;i<u32(h+16);i++){
  if(pos>end || end-pos<8)die("load command bounds");uint8_t *lc=at(pos,8);uint32_t cmd=u32(lc),n=u32(lc+4);if(n<8 || n>end-pos)die("load command size");lc=at(pos,n);
  if(cmd==25){
   if(n<72 || u32(lc+64)>(n-72)/80)die("segment command bounds");uint64_t vm=u64(lc+24),vmsize=u64(lc+32),off=u64(lc+40),bytes=u64(lc+48);at(off,bytes);if(bytes>vmsize || vm>UINT64_MAX-vmsize)die("invalid segment geometry");
   for(uint32_t j=0;j<u32(lc+64);j++){
    if(nsections==MAX_SECTIONS)die("too many sections");uint8_t *s=lc+72+j*80;struct section *t=&sections[nsections++];memcpy(t->name,s,16);memcpy(t->segment,s+16,16);t->va=u64(s+32);t->size=u64(s+40);t->off=u32(s+48);t->flags=u32(s+64);t->first=u32(s+68);t->stride=u32(s+72);
    if(t->va<vm || t->va-vm>vmsize || t->size>vmsize-(t->va-vm))die("section VM bounds");
    unsigned type=t->flags&255;
    if(type!=1 && type!=12 && type!=18){at(t->off,t->size);if(t->off<off || t->off-off>bytes || t->size>bytes-(t->off-off) || t->va-vm!=t->off-off)die("section file bounds");}
   }
  }else if(cmd==2){if(n<24 || symcommands++)die("invalid or duplicate symtab");symoff=u32(lc+8);nsyms=u32(lc+12);stroff=u32(lc+16);strsize=u32(lc+20);at(symoff,(uint64_t)nsyms*16);at(stroff,strsize);}
  else if(cmd==11){if(n<80 || dycommands++)die("invalid or duplicate dysymtab");indirect=u32(lc+56);nindirect=u32(lc+60);at(indirect,(uint64_t)nindirect*4);}
  else if(cmd==0x21 || cmd==0x2c){if(n<20 || u32(lc+16))die("encrypted or invalid executable");}
  pos+=n;
 }
 if(symcommands!=1 || dycommands!=1 || !nsyms || !nindirect || !strsize)die("missing import metadata");
 uint64_t target=0,offset=0;unsigned matches=0;
 for(unsigned j=0;j<nsections;j++){
  struct section *s=&sections[j];if((s->flags&255)!=8)continue;
  if(strcmp(s->name,"__stubs") || strcmp(s->segment,"__TEXT") || s->stride!=12 || s->size%12)die("unsupported import-stub layout");
  uint64_t count=s->size/12;if(s->first>nindirect || count>nindirect-s->first)die("indirect symbol bounds");
  for(uint64_t i=0;i<count;i++){
   uint32_t idx=u32(at(indirect+((uint64_t)s->first+i)*4,4));if(idx&0xc0000000)continue;if(idx>=nsyms)die("invalid indirect symbol index");
   uint8_t *sym=at(symoff+(uint64_t)idx*16,16);uint32_t name=u32(sym);if(name>=strsize || !memchr(at(stroff+name,strsize-name),0,strsize-name))die("invalid import name");
   if(strcmp((char *)at(stroff+name,1),verifier))continue;
   if((sym[4]&0xee)!=0 || !(sym[4]&1))die("verification symbol is not an undefined external import");
   target=s->va+i*12;offset=s->off+i*12;matches++;
  }
 }
 if(matches!=1)die("verification import stub is missing or ambiguous");
 uint8_t *stub=at(offset,12);uint32_t a=u32(stub),b=u32(stub+4),c=u32(stub+8);
 bool already=a==0x52800000 && b==0xd65f03c0 && c==0xd61f0200;
 if(!already && !((a&0x9f00001f)==0x90000010 && (b&0xffc003ff)==0xf9400210 && c==0xd61f0200))die("unrecognized verification-stub instructions");
 unsigned callers=0;
 for(unsigned j=0;j<nsections;j++){
  struct section *s=&sections[j];if(strcmp(s->name,"__text") || strcmp(s->segment,"__TEXT"))continue;
  if(s->va%4 || s->size%4)die("unaligned code section");
  for(uint64_t off=0;off+4<=s->size;off+=4){uint32_t w=u32(at(s->off+off,4));if((w&0xfc000000)==0x94000000 && s->va+off+sx(w&0x3ffffff,26)*4==target)callers++;}
 }
 if(!callers)die("no direct callers of the verification stub");
 if(!already){uint32_t patch[2]={0x52800000,0xd65f03c0};memcpy(stub,patch,8);}
 skip_lpc(symoff,nsyms,stroff,strsize);
 int fd=open(argv[2],O_WRONLY|O_CREAT|O_EXCL,0755);if(fd<0)die("output must be a new writable path");f=fdopen(fd,"wb");if(!f){close(fd);unlink(argv[2]);die("cannot open output stream");}
 if(fwrite(data,1,length,f)!=length){fclose(f);unlink(argv[2]);die("output write failed");}if(fclose(f)){unlink(argv[2]);die("output close failed");}
 printf("%s local requestImageVerify stub at VA 0x%llx: return IOReturn success (0); %u direct callers.\n",already?"Preserved already-patched":"Patched",(unsigned long long)target,callers);
 printf("Output: %s (%zu bytes, unchanged size). Re-sign before device testing.\n",argv[2],length);free(data);return 0;
}
