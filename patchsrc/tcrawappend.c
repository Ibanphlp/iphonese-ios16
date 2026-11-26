/* Append raw CDHash entries and/or merge other trust caches into a v0/v1/v2
 * trust cache file (the raw payload after img4 unwraps a .trustcache).
 * cc -std=c11 -O2 -Wall -Wextra tcrawappend.c -o tcrawappend
 *
 * usage: tcrawappend <target> [-f FLAGS] [-c CATEGORY] [-H hexfile | -m tcfile]...
 *
 * Multiple -H and -m flags may be given in any order. -H lines are 40-char
 * hex-encoded 20-byte (truncated SHA-256) CDHashes, one per line, with blank
 * lines and leading/trailing whitespace ignored. -m merges every entry from
 * another trust cache, preserving that entry's own hash_type / flags / category
 * byte(s); -f and -c apply only to entries added via -H. Entries are sorted by
 * hash and deduplicated. Target version is preserved. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void die(const char *s){fprintf(stderr,"tcrawappend: %s\n",s);exit(1);}

static int hex_nibble(int c){
 if(c>='0'&&c<='9')return c-'0';
 if(c>='a'&&c<='f')return c-'a'+10;
 if(c>='A'&&c<='F')return c-'A'+10;
 return -1;
}

static size_t entry_size_for(uint32_t ver){
 if(ver<=1)return 22;
 if(ver==2)return 24;
 die("unsupported trust cache version");
 return 0;
}

static uint8_t *read_file(const char *path,size_t *out_len){
 FILE *f=fopen(path,"rb");if(!f){perror("tcrawappend: open");exit(1);}
 struct stat st;if(fstat(fileno(f),&st)||!S_ISREG(st.st_mode)||(uintmax_t)st.st_size>SIZE_MAX){fclose(f);die("invalid input file");}
 size_t n=(size_t)st.st_size;uint8_t *buf=malloc(n?n:1);if(!buf){fclose(f);die("out of memory");}
 if(n&&fread(buf,1,n,f)!=n){fclose(f);die("read failed");}
 fclose(f);*out_len=n;return buf;
}

static uint32_t rd32le(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void wr32le(uint8_t *p,uint32_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);p[2]=(uint8_t)(v>>16);p[3]=(uint8_t)(v>>24);}

static int cmp_hash(const void *a,const void *b){return memcmp(a,b,20);}

int main(int argc,char **argv){
 if(argc<2){fprintf(stderr,"usage: %s <target> [-f FLAGS] [-c CATEGORY] [-H hexfile | -m tcfile]...\n",argv[0]);return 2;}
 const char *target=NULL;uint8_t add_flags=1,add_cat=0;
 const char **hex_files=calloc((size_t)argc,sizeof(char *));
 const char **tc_files=calloc((size_t)argc,sizeof(char *));
 if(!hex_files||!tc_files)die("out of memory");
 size_t n_hex=0,n_tc=0;
 for(int i=1;i<argc;i++){
  const char *a=argv[i];
  if(!target&&a[0]!='-'){target=a;continue;}
  if(!strcmp(a,"-f")&&i+1<argc){unsigned long v=strtoul(argv[++i],NULL,0);if(v>255)die("flags byte out of range");add_flags=(uint8_t)v;continue;}
  if(!strcmp(a,"-c")&&i+1<argc){unsigned long v=strtoul(argv[++i],NULL,0);if(v>255)die("category byte out of range");add_cat=(uint8_t)v;continue;}
  if(!strcmp(a,"-H")&&i+1<argc){hex_files[n_hex++]=argv[++i];continue;}
  if(!strcmp(a,"-m")&&i+1<argc){tc_files[n_tc++]=argv[++i];continue;}
  fprintf(stderr,"tcrawappend: unexpected argument: %s\n",a);return 2;
 }
 if(!target)die("no target trust cache given");

 size_t tlen=0;uint8_t *tbuf=read_file(target,&tlen);
 if(tlen<24)die("target trust cache too small");
 uint32_t tver=rd32le(tbuf);uint32_t tcnt=rd32le(tbuf+20);
 size_t tesz=entry_size_for(tver);
 if(tlen<24+(size_t)tcnt*tesz)die("target trust cache truncated");

 size_t cap=(size_t)tcnt+64,n=tcnt;
 uint8_t *entries=calloc(cap,tesz);if(!entries)die("out of memory");
 memcpy(entries,tbuf+24,(size_t)tcnt*tesz);

 for(size_t fi=0;fi<n_hex;fi++){
  FILE *hf=fopen(hex_files[fi],"r");if(!hf){perror("tcrawappend: hex input");return 1;}
  char line[256];unsigned lineno=0;
  while(fgets(line,sizeof line,hf)){
   lineno++;char *p=line;while(*p==' '||*p=='\t')p++;
   size_t len=strlen(p);while(len&&(p[len-1]=='\n'||p[len-1]=='\r'||p[len-1]==' '||p[len-1]=='\t'))p[--len]=0;
   if(!len)continue;
   if(len!=40){fprintf(stderr,"tcrawappend: %s:%u: expected 40 hex chars, got %zu\n",hex_files[fi],lineno,len);exit(1);}
   if(n==cap){cap*=2;entries=realloc(entries,cap*tesz);if(!entries)die("out of memory");}
   uint8_t *e=entries+n*tesz;memset(e,0,tesz);
   for(int k=0;k<20;k++){int hi=hex_nibble(p[k*2]),lo=hex_nibble(p[k*2+1]);
    if(hi<0||lo<0){fprintf(stderr,"tcrawappend: %s:%u: invalid hex\n",hex_files[fi],lineno);exit(1);}
    e[k]=(uint8_t)((hi<<4)|lo);}
   e[20]=2;/* hashType=2 (truncated SHA-256, 20 bytes) */
   e[21]=add_flags;
   if(tesz>=24){e[22]=add_cat;e[23]=0;}
   n++;
  }
  fclose(hf);
 }

 for(size_t mi=0;mi<n_tc;mi++){
  size_t mlen=0;uint8_t *mbuf=read_file(tc_files[mi],&mlen);
  if(mlen<24)die("merge input too small");
  uint32_t mver=rd32le(mbuf);uint32_t mcnt=rd32le(mbuf+20);
  size_t mesz=entry_size_for(mver);
  if(mlen<24+(size_t)mcnt*mesz)die("merge input truncated");
  for(uint32_t i=0;i<mcnt;i++){
   if(n==cap){cap*=2;entries=realloc(entries,cap*tesz);if(!entries)die("out of memory");}
   uint8_t *dst=entries+n*tesz;const uint8_t *src=mbuf+24+(size_t)i*mesz;
   memset(dst,0,tesz);memcpy(dst,src,20);dst[20]=src[20];dst[21]=src[21];
   if(tesz>=24){dst[22]=mesz>=24?src[22]:0;dst[23]=0;}
   n++;
  }
  free(mbuf);
 }

 qsort(entries,n,tesz,cmp_hash);
 size_t out=0;
 for(size_t i=0;i<n;i++){
  if(out&&!memcmp(entries+(out-1)*tesz,entries+i*tesz,20))continue;
  if(out!=i)memmove(entries+out*tesz,entries+i*tesz,tesz);
  out++;
 }
 n=out;
 if(n>UINT32_MAX)die("too many entries");

 wr32le(tbuf+20,(uint32_t)n);
 size_t new_len=24+n*tesz;
 uint8_t *outbuf=malloc(new_len);if(!outbuf)die("out of memory");
 memcpy(outbuf,tbuf,24);memcpy(outbuf+24,entries,n*tesz);

 size_t tp=strlen(target);char *tmp=malloc(tp+16);if(!tmp)die("out of memory");
 snprintf(tmp,tp+16,"%s.tmp.XXXXXX",target);
 int fd=mkstemp(tmp);if(fd<0){perror("tcrawappend: temp output");exit(1);}
 int err=0;size_t p=0;while(p<new_len){ssize_t w=write(fd,outbuf+p,new_len-p);if(w<0&&errno==EINTR)continue;if(w<=0){err=errno?errno:EIO;break;}p+=(size_t)w;}
 if(!err&&fsync(fd))err=errno;if(close(fd)&&!err)err=errno;
 if(!err&&rename(tmp,target))err=errno;
 if(err){unlink(tmp);free(tmp);errno=err;perror("tcrawappend: publish");exit(1);}
 free(tmp);free(outbuf);free(entries);free(tbuf);free((void *)hex_files);free((void *)tc_files);
 printf("tcrawappend: %s now holds %zu entries (v%u)\n",target,n,tver);
 return 0;
}
