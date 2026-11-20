/* mthax: replace the iPad 5 SPI personality with the full SE 1 N69 profile.
 * Usage: mthax input-kernel output-kernel
 * Build: cc -std=c11 -O2 -Wall -Wextra -Werror mthax.c -o mthax
 * Single source, standard C/POSIX only; no libxml2 or project files needed.
 * Profile transcribed from the local SE 15.8.8 AppleMultitouchSPIN69 metadata.
 * No donor argument, fixed kernel offsets, UUID checks or executable changes.
 * This selects C1F57,5; it does not supply external mtprops/firmware files.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

static void die(const char *s) { fprintf(stderr,"mthax: %s\n",s);exit(1); }
static uint32_t u32(const unsigned char *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint64_t u64(const unsigned char *p) { return u32(p)|(uint64_t)u32(p+4)<<32; }
/* Small bounded parser for Apple's serialized XML plists. Source spans are
 * retained so unrelated metadata is copied verbatim. No external XML library,
 * entity expansion, DTD, donor plist or project header is needed. */
typedef struct Attr Attr;
typedef struct Node Node;
struct Attr { size_t start,end; char *name,*value; Attr *next; };
struct Node {
    size_t start,open_end,close_start,end;
    char *name,*id,*ref; Attr *attrs;
    Node *parent,*children,*last,*next;
};
typedef struct { const char *s; size_t len,pos,nodes; } Parser;
typedef struct { char *s; size_t len,cap; } Buffer;
typedef struct { const char *id; Node *node; } Id;
static Id *ids; static size_t id_count;
static void *alloc(size_t n) { void *p=calloc(1,n);if(!p)die("allocation failed");return p; }
static char *slice(const char *s,size_t n) { char *p=alloc(n+1);memcpy(p,s,n);return p; }
static int space(char c) { return c==' '||c=='\t'||c=='\r'||c=='\n'; }
static void skip_space(Parser *p) { while(p->pos<p->len && space(p->s[p->pos]))p->pos++; }
static int starts(Parser *p,const char *s) { size_t n=strlen(s);return n<=p->len-p->pos && !memcmp(p->s+p->pos,s,n); }
static int name_start(char c) { return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||c=='_'||c==':'; }
static int name_char(char c) { return name_start(c)||(c>='0'&&c<='9')||c=='-'||c=='.'; }
static char *name(Parser *p) {
    size_t begin=p->pos;if(begin==p->len||!name_start(p->s[begin]))die("invalid XML name");
    do {p->pos++;} while(p->pos<p->len && name_char(p->s[p->pos]));
    return slice(p->s+begin,p->pos-begin);
}
static char *decode(const char *s,size_t n) {
    char *out=alloc(n+1);size_t used=0;
    for(size_t i=0;i<n;i++) {
        unsigned char c=(unsigned char)s[i];
        if((c<32 && !space((char)c))||c=='<')die("invalid XML text");
        if(c!='&') {out[used++]=(char)c;continue;}
        size_t j=i+1;while(j<n && s[j]!=';' && j-i<32)j++;
        if(j==n||s[j]!=';')die("invalid XML entity");
        size_t z=j-i+1;unsigned v=0;
        if(z==5&&!memcmp(s+i,"&amp;",5))v='&';
        else if(z==4&&!memcmp(s+i,"&lt;",4))v='<';
        else if(z==4&&!memcmp(s+i,"&gt;",4))v='>';
        else if(z==6&&!memcmp(s+i,"&quot;",6))v='"';
        else if(z==6&&!memcmp(s+i,"&apos;",6))v='\'';
        else if(s[i+1]=='#') {
            size_t k=i+2;unsigned base=10;if(k<j&&s[k]=='x'){base=16;k++;}
            if(k==j)die("empty XML character reference");
            for(;k<j;k++) {unsigned d=(unsigned char)s[k];
                if(d>='0'&&d<='9')d-='0';else if(d>='a'&&d<='f')d=d-'a'+10;else if(d>='A'&&d<='F')d=d-'A'+10;else die("invalid XML character reference");
                if(d>=base||v>(0x10ffff-d)/base)die("invalid XML character reference");v=v*base+d;
            }
            if(!((v>=32&&v<=0xd7ff)||(v>=0xe000&&v<=0xfffd)||(v>=0x10000&&v<=0x10ffff)||v==9||v==10||v==13))die("invalid XML character");
        } else die("unsupported XML entity");
        if(v<128)out[used++]=(char)v;
        else if(v<2048){out[used++]=(char)(0xc0|(v>>6));out[used++]=(char)(0x80|(v&63));}
        else if(v<65536){out[used++]=(char)(0xe0|(v>>12));out[used++]=(char)(0x80|((v>>6)&63));out[used++]=(char)(0x80|(v&63));}
        else {out[used++]=(char)(0xf0|(v>>18));out[used++]=(char)(0x80|((v>>12)&63));out[used++]=(char)(0x80|((v>>6)&63));out[used++]=(char)(0x80|(v&63));}
        i=j;
    }
    out[used]=0;return out;
}
static void misc(Parser *p) {
    for(;;) {
        skip_space(p);
        if(starts(p,"<!--")) {
            p->pos+=4;while(!starts(p,"-->")) {
                if(p->pos==p->len||starts(p,"--"))die("invalid XML comment");p->pos++;
            }p->pos+=3;
        } else if(starts(p,"<?")) {
            p->pos+=2;while(!starts(p,"?>")){if(p->pos==p->len)die("unterminated XML instruction");p->pos++;}p->pos+=2;
        } else break;
    }
}
static Node *parse_node(Parser *p,Node *parent,unsigned depth) {
    if(depth>256||p->pos==p->len||p->s[p->pos]!='<')die("invalid XML element/depth");
    Node *n=alloc(sizeof(*n));n->start=p->pos++;n->parent=parent;n->name=name(p);p->nodes++;
    for(;;) {
        size_t before=p->pos;skip_space(p);
        if(starts(p,"/>")){p->pos+=2;n->open_end=n->close_start=n->end=p->pos;return n;}
        if(starts(p,">")){n->open_end=++p->pos;break;}
        if(before==p->pos)die("missing XML attribute separator");
        Attr *a=alloc(sizeof(*a));a->start=before;a->name=name(p);
        for(Attr *b=n->attrs;b;b=b->next)if(!strcmp(a->name,b->name))die("duplicate XML attribute");
        skip_space(p);if(p->pos==p->len||p->s[p->pos++]!='=')die("invalid XML attribute");skip_space(p);
        if(p->pos==p->len||(p->s[p->pos]!='\''&&p->s[p->pos]!='"'))die("unquoted XML attribute");
        char quote=p->s[p->pos++];size_t begin=p->pos;
        while(p->pos<p->len&&p->s[p->pos]!=quote)p->pos++;
        if(p->pos==p->len)die("unterminated XML attribute");
        a->value=decode(p->s+begin,p->pos-begin);a->end=++p->pos;a->next=n->attrs;n->attrs=a;
        if(!strcmp(a->name,"ID"))n->id=a->value;
        if(!strcmp(a->name,"IDREF"))n->ref=a->value;
    }
    for(;;) {
        if(starts(p,"</")) {
            n->close_start=p->pos;p->pos+=2;char *end=name(p);
            if(strcmp(end,n->name))die("mismatched XML element");free(end);skip_space(p);
            if(p->pos==p->len||p->s[p->pos++]!='>')die("invalid XML closing tag");n->end=p->pos;return n;
        }
        if(starts(p,"<!--")||starts(p,"<?")){misc(p);continue;}
        if(p->pos==p->len)die("unterminated XML element");
        if(p->s[p->pos]=='<') {
            Node *child=parse_node(p,n,depth+1);
            if(n->last)n->last->next=child;else n->children=child;n->last=child;
        } else {
            size_t begin=p->pos;while(p->pos<p->len&&p->s[p->pos]!='<')p->pos++;
            char *text=decode(p->s+begin,p->pos-begin);free(text);
        }
    }
}
static void collect_ids(Node *n) {
    for(;n;n=n->next){if(n->id){ids[id_count].id=n->id;ids[id_count++].node=n;}collect_ids(n->children);}
}
static int id_cmp(const void *a,const void *b){return strcmp(((const Id *)a)->id,((const Id *)b)->id);}
static Node *find_id(const char *id) {
    Id key={id,NULL};Id *f=bsearch(&key,ids,id_count,sizeof(*ids),id_cmp);
    if(!f)die("missing XML ID");return f->node;
}
static Node *resolved(Node *n) {
    for(unsigned depth=0;depth<=64;depth++) {
        if(!n)die("missing XML value");if(!n->ref)return n;n=find_id(n->ref);
    }die("cyclic or excessive XML reference chain");return NULL;
}
static int tag(Node *n,const char *s){return n&&!strcmp(n->name,s);}
static int text_is(Node *n,const char *value,const char *xml) {
    if(n->children)die("nested scalar XML value");
    char *s=decode(xml+n->open_end,n->close_start-n->open_end);int yes=!strcmp(s,value);free(s);return yes;
}
static Node *field(Node *dict,const char *key,const char *xml) {
    dict=resolved(dict);if(!tag(dict,"dict"))die("expected dictionary");Node *found=NULL;
    for(Node *n=dict->children;n;) {
        if(!tag(n,"key")||n->ref)die("invalid dictionary key");Node *value=n->next;if(!value)die("missing dictionary value");
        if(text_is(n,key,xml)){if(found)die("duplicate dictionary key");found=value;}n=value->next;
    }return found;
}
static int string_is(Node *n,const char *value,const char *xml){return n&&tag(resolved(n),"string")&&text_is(resolved(n),value,xml);}
static int inside(Node *n,Node *ancestor){for(;n;n=n->parent)if(n==ancestor)return 1;return 0;}
static void append(Buffer *b,const char *s,size_t n) {
    if(n>b->cap-b->len)die("insufficient existing prelink padding");memcpy(b->s+b->len,s,n);b->len+=n;
}
static void literal(Buffer *b,const char *s){append(b,s,strlen(s));}
/* Expand referenced values while stripping definition IDs from copied trees.
 * The referencing node's own ID is retained for any outside chains. */
static void plain_copy(Buffer *b,Node *original,const char *xml,unsigned depth,int keep_id) {
    if(depth>64)die("cyclic or excessive XML value depth");Node *n=resolved(original);
    literal(b,"<");literal(b,n->name);
    for(Attr *a=n->attrs;a;a=a->next)if(strcmp(a->name,"ID")&&strcmp(a->name,"IDREF"))append(b,xml+a->start,a->end-a->start);
    if(keep_id&&original->id)for(Attr *a=original->attrs;a;a=a->next)if(!strcmp(a->name,"ID"))append(b,xml+a->start,a->end-a->start);
    if(n->open_end==n->end){literal(b,"/>");return;}
    literal(b,">");size_t pos=n->open_end;
    for(Node *c=n->children;c;c=c->next){append(b,xml+pos,c->start-pos);plain_copy(b,c,xml,depth+1,0);pos=c->end;}
    append(b,xml+pos,n->close_start-pos);literal(b,"</");literal(b,n->name);literal(b,">");
}
static void emit(Buffer *b,Node *n,Node *old,const char *xml,const char *profile,size_t profile_len) {
    if(n==old){append(b,profile,profile_len);return;}
    if(n->ref&&inside(resolved(n),old)){plain_copy(b,n,xml,0,1);return;}
    size_t pos=n->start;
    for(Node *c=n->children;c;c=c->next){append(b,xml+pos,c->start-pos);emit(b,c,old,xml,profile,profile_len);pos=c->end;}
    append(b,xml+pos,n->end-pos);
}
static void validate_refs(Node *n) {
    for(;n;n=n->next){if(n->ref){(void)resolved(n);if(n->children||n->open_end!=n->end)die("nonempty XML reference");}validate_refs(n->children);}
}
static void free_node(Node *n){while(n){Node *next=n->next;free_node(n->children);Attr *a=n->attrs;while(a){Attr *next_a=a->next;free(a->name);free(a->value);free(a);a=next_a;}free(n->name);free(n);n=next;}}

static const char se_profile[] =
    "<dict>"
    "<key>AppleMultitouchSPI - C1,N69</key><dict>"
    "<key>IOCFPlugInTypes</key><dict>"
    "<key>0516B563-B15B-11DA-96EB-0014519758EF</key><string>AppleMultitouchSPI.kext/PlugIns/MultitouchHID.plugin</string></dict>"
    "<key>CFBundleIdentifier</key><string>com.apple.driver.AppleMultitouchSPI</string>"
    "<key>IOClass</key><string>AppleMultitouchN1SPI</string>"
    "<key>IOProviderClass</key><string>AppleARMSPIDevice</string>"
    "<key>fll-mval</key><integer size=\"64\">0x17d3</integer>"
    "<key>clk32-clock-enable-addr</key><integer size=\"64\">0x10003518</integer>"
    "<key>fw-execute-addr</key><integer size=\"64\">0x10003400</integer>"
    "<key>cal-dl-addr</key><integer size=\"64\">0x10009000</integer>"
    "<key>IONameMatch</key><array><string>multi-touch,n69</string></array>"
    "<key>fll-mval-addr</key><integer size=\"64\">0x10003060</integer>"
    "<key>mt-merge-personality</key><string>C1F57,5</string>"
    "<key>reset-deassert-delay</key><integer size=\"64\">0xf</integer>"
    "<key>touch-size-id</key><integer size=\"64\">0x2</integer>"
    "<key>parser-type</key><integer size=\"64\">0x1</integer>"
    "<key>prox-cal-addr</key><integer size=\"64\">0x10009600</integer>"
    "<key>HIDServiceSupport</key><true/>"
    "<key>power-ana-enable-delay-us</key><integer size=\"64\">0x1f4</integer>"
    "<key>ref-clk-div-val</key><integer size=\"64\">0x2</integer>"
    "<key>clk32-clock-enable-val</key><integer size=\"64\">0x1</integer></dict></dict>";

int main(int argc,char **argv) {
    if(argc!=3) {fprintf(stderr,"Usage: %s <input-kernel> <output-kernel>\n",argv[0]);return 2;}
    FILE *f=fopen(argv[1],"rb");if(!f)die("cannot open input");
    if(fseek(f,0,SEEK_END))die("cannot size input");long length=ftell(f);
    if(length<32 || fseek(f,0,SEEK_SET))die("invalid input size");size_t len=(size_t)length;
    unsigned char *data=malloc(len);if(!data)die("allocation failed");
    if(fread(data,1,len,f)!=len || fclose(f))die("cannot read input");
    if(u32(data)!=0xfeedfacf || u32(data+4)!=0x100000c)die("expected thin raw arm64 Mach-O");
    uint64_t commands=u32(data+20);if(commands>len-32)die("invalid Mach-O commands");
    uint64_t pos=32,pi=0,capacity=0;unsigned matches=0;
    for(uint32_t i=0;i<u32(data+16);i++) {
        if(pos+8>32+commands)die("truncated command");
        uint32_t cmd=u32(data+pos),size=u32(data+pos+4);
        if(size<8 || size>32+commands-pos)die("invalid command size");
        if(cmd==25) {
            if(size<72 || u32(data+pos+64)>(size-72)/80)die("invalid segment");
            uint64_t off=u64(data+pos+40),bytes=u64(data+pos+48);
            if(off>len || bytes>len-off)die("unbacked segment");
            if(!memcmp(data+pos+8,"__PRELINK_INFO\0\0",16)) {pi=off;capacity=bytes;matches++;}
        }
        pos+=size;
    }
    if(pos!=32+commands)die("Mach-O command count/size mismatch");
    if(matches!=1 || !capacity || capacity>INT_MAX)die("missing or ambiguous prelink metadata");
    unsigned char *zero=memchr(data+pi,0,capacity);if(!zero)die("unterminated prelink XML");
    size_t xml_len=(size_t)(zero-(data+pi));
    for(size_t j=xml_len;j<capacity;j++)if(data[pi+j])die("nonzero data after prelink XML");
    const char *xml=(const char *)data+pi;
    Parser parser={xml,xml_len,0,0};misc(&parser);
    Node *document=parse_node(&parser,NULL,0);misc(&parser);
    if(parser.pos!=parser.len)die("trailing XML data or unsupported DTD");
    ids=alloc(parser.nodes*sizeof(*ids));collect_ids(document);
    qsort(ids,id_count,sizeof(*ids),id_cmp);
    for(size_t i=1;i<id_count;i++)if(!strcmp(ids[i-1].id,ids[i].id))die("duplicate XML ID");
    validate_refs(document);
    Node *root=document;
    if(tag(root,"plist")){root=root->children;if(!root||root->next)die("invalid plist root");}
    Node *array=resolved(field(root,"_PrelinkInfoDictionary",xml));
    if(!tag(array,"array"))die("missing prelink kext array");
    Node *personality=NULL;unsigned candidates=0;
    for(Node *entry=array->children;entry;entry=entry->next) {
        Node *id=field(entry,"CFBundleIdentifier",xml);
        if(!string_is(id,"com.apple.driver.AppleMultitouchSPIC1F15",xml) &&
           !string_is(id,"com.apple.driver.AppleMultitouchSPIN69",xml))continue;
        Node *p=field(entry,"IOKitPersonalities",xml);if(!p)die("missing SPI personalities");
        /* Don't replace a reference shared by another entry. */
        if(p->ref)die("shared personality container unsupported");
        Node *a=field(p,"AppleMultitouchSPI - C1,J72",xml);
        Node *b=field(p,"AppleMultitouchSPI - C1,N69",xml);
        if((!a && !b) || (a && b))die("unexpected SPI personality names");
        Node *value=resolved(a?a:b);
        if(!string_is(field(value,"IOClass",xml),"AppleMultitouchN1SPI",xml) ||
           !string_is(field(value,"IOProviderClass",xml),"AppleARMSPIDevice",xml))die("unsupported SPI driver class");
        unsigned keys=0;for(Node *n=p->children;n;n=n->next)if(tag(n,"key"))keys++;
        if(keys!=1)die("additional SPI personalities require review");
        personality=p;candidates++;
    }
    if(candidates!=1)die("missing or ambiguous J72/N69 SPI personality");
    Buffer output={alloc((size_t)capacity),0,(size_t)capacity-1};
    append(&output,xml,document->start);
    emit(&output,document,personality,xml,se_profile,sizeof(se_profile)-1);
    append(&output,xml+document->end,xml_len-document->end);
    memset(data+pi,0,(size_t)capacity);memcpy(data+pi,output.s,output.len);
    int fd=open(argv[2],O_WRONLY|O_CREAT|O_EXCL,0644);if(fd<0)die("output must be a new writable path");
    f=fdopen(fd,"wb");if(!f) {close(fd);unlink(argv[2]);die("cannot open output stream");}
    if(fwrite(data,1,len,f)!=len) {fclose(f);unlink(argv[2]);die("output write failed");}
    if(fclose(f)) {unlink(argv[2]);die("output close failed");}
    printf("Installed full SE N69 SPI personality: C1F57,5, size-id=2, FLL=0x17d3, analog delay=500us, ref divisor=2.\n");
    printf("Output: %s (%zu bytes, unchanged size). External mtprops/firmware are still required.\n",argv[2],len);
    free(output.s);free(ids);free_node(document);free(data);return 0;
}
