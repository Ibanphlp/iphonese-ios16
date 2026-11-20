/* mthax: replace the iPad 5 SPI personality with the full SE 1 N69 profile.
 * Usage: mthax input-kernel output-kernel
 * Build: cc -O2 -Wall -Wextra -Werror mthax.c -lxml2 -o mthax
 * Profile transcribed from the local SE 15.8.8 AppleMultitouchSPIN69 metadata.
 * No donor argument, fixed kernel offsets, UUID checks or executable changes.
 * This selects C1F57,5; it does not supply external mtprops/firmware files.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

static void die(const char *s) { fprintf(stderr,"mthax: %s\n",s);exit(1); }
static uint32_t u32(const unsigned char *p) { uint32_t x;memcpy(&x,p,4);return x; }
static uint64_t u64(const unsigned char *p) { uint64_t x;memcpy(&x,p,8);return x; }
static int tag(xmlNode *n,const char *s) { return n && n->type==XML_ELEMENT_NODE && !xmlStrcmp(n->name,BAD_CAST s); }
static xmlNode *element(xmlNode *n) { while(n && n->type!=XML_ELEMENT_NODE)n=n->next;return n; }
static xmlNode *find_id(xmlNode *n,const xmlChar *id,unsigned *count) {
    xmlNode *found=NULL;
    for(;n;n=n->next) {
        xmlChar *v=xmlGetProp(n,BAD_CAST "ID");
        if(v && !xmlStrcmp(v,id)) {found=n;(*count)++;}xmlFree(v);
        xmlNode *f=find_id(n->children,id,count);if(f)found=f;
    }
    return found;
}
static xmlNode *resolved(xmlNode *n,xmlNode *root,unsigned depth) {
    if(!n || depth>64)die("missing or cyclic XML reference");
    xmlChar *id=xmlGetProp(n,BAD_CAST "IDREF");if(!id)return n;
    unsigned count=0;xmlNode *f=find_id(root,id,&count);xmlFree(id);
    if(count!=1)die("missing or ambiguous XML ID");
    return resolved(f,root,depth+1);
}
static xmlNode *field(xmlNode *dict,const char *key,xmlNode *root) {
    dict=resolved(dict,root,0);if(!tag(dict,"dict"))die("expected dictionary");
    xmlNode *found=NULL;
    for(xmlNode *n=element(dict->children);n;) {
        if(!tag(n,"key"))die("invalid dictionary key");
        xmlNode *value=element(n->next);if(!value)die("missing dictionary value");
        xmlChar *s=xmlNodeGetContent(n);
        if(!xmlStrcmp(s,BAD_CAST key)) {if(found)die("duplicate dictionary key");found=value;}
        xmlFree(s);n=element(value->next);
    }
    return found;
}
static int string_is(xmlNode *n,const char *value,xmlNode *root) {
    if(!n)return 0;n=resolved(n,root,0);if(!tag(n,"string"))return 0;
    xmlChar *s=xmlNodeGetContent(n);int yes=!xmlStrcmp(s,BAD_CAST value);xmlFree(s);return yes;
}
static int inside(xmlNode *n,xmlNode *ancestor) {
    for(;n;n=n->parent)if(n==ancestor)return 1;
    return 0;
}
/* Copy resolved values without donor IDs. Used to preserve outside references
 * to definitions that lived in the personality being removed. */
static xmlNode *plain_copy(xmlNode *n,xmlNode *root,xmlDoc *doc,unsigned depth) {
    if(depth>64)die("cyclic XML value");
    n=resolved(n,root,0);
    xmlNode *out=xmlDocCopyNode(n,doc,2);if(!out)die("XML allocation failed");
    xmlUnsetProp(out,BAD_CAST "ID");xmlUnsetProp(out,BAD_CAST "IDREF");
    for(xmlNode *c=n->children;c;c=c->next) {
        xmlNode *copy=c->type==XML_ELEMENT_NODE ? plain_copy(c,root,doc,depth+1):xmlDocCopyNode(c,doc,1);
        if(!copy)die("XML allocation failed");xmlAddChild(out,copy);
    }
    return out;
}
static void preserve_refs(xmlNode *n,xmlNode *old,xmlNode *root,xmlDoc *doc) {
    while(n) {
        xmlNode *next=n->next;
        if(n!=old) {
            xmlChar *id=xmlGetProp(n,BAD_CAST "IDREF");
            if(id) {
                unsigned count=0;xmlNode *def=find_id(root,id,&count);xmlFree(id);
                if(count!=1)die("invalid XML reference");
                if(inside(def,old)) {
                    xmlNode *copy=plain_copy(n,root,doc,0);xmlReplaceNode(n,copy);xmlFreeNode(n);n=next;continue;
                }
            }
            preserve_refs(n->children,old,root,doc);
        }
        n=next;
    }
}
static const char se_profile[] = "<dict><key>AppleMultitouchSPI - C1,N69</key><dict><key>IOCFPlugInTypes</key><dict><key>0516B563-B15B-11DA-96EB-0014519758EF</key><string>AppleMultitouchSPI.kext/PlugIns/MultitouchHID.plugin</string></dict><key>CFBundleIdentifier</key><string>com.apple.driver.AppleMultitouchSPI</string><key>IOClass</key><string>AppleMultitouchN1SPI</string><key>IOProviderClass</key><string>AppleARMSPIDevice</string><key>fll-mval</key><integer size=\"64\">0x17d3</integer><key>clk32-clock-enable-addr</key><integer size=\"64\">0x10003518</integer><key>fw-execute-addr</key><integer size=\"64\">0x10003400</integer><key>cal-dl-addr</key><integer size=\"64\">0x10009000</integer><key>IONameMatch</key><array><string>multi-touch,n69</string></array><key>fll-mval-addr</key><integer size=\"64\">0x10003060</integer><key>mt-merge-personality</key><string>C1F57,5</string><key>reset-deassert-delay</key><integer size=\"64\">0xf</integer><key>touch-size-id</key><integer size=\"64\">0x2</integer><key>parser-type</key><integer size=\"64\">0x1</integer><key>prox-cal-addr</key><integer size=\"64\">0x10009600</integer><key>HIDServiceSupport</key><true/><key>power-ana-enable-delay-us</key><integer size=\"64\">0x1f4</integer><key>ref-clk-div-val</key><integer size=\"64\">0x2</integer><key>clk32-clock-enable-val</key><integer size=\"64\">0x1</integer></dict></dict>";

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
    if(matches!=1 || !capacity || capacity>INT_MAX)die("missing or ambiguous prelink metadata");
    unsigned char *zero=memchr(data+pi,0,capacity);if(!zero)die("unterminated prelink XML");
    size_t xml_len=(size_t)(zero-(data+pi));
    for(size_t j=xml_len;j<capacity;j++)if(data[pi+j])die("nonzero data after prelink XML");
    xmlDoc *doc=xmlReadMemory((char *)data+pi,(int)xml_len,"prelink.xml",NULL,XML_PARSE_NONET);
    if(!doc || doc->intSubset || doc->extSubset)die("invalid XML or unsupported DTD");
    xmlNode *root=xmlDocGetRootElement(doc);
    if(tag(root,"plist"))root=element(root->children);
    xmlNode *array=field(root,"_PrelinkInfoDictionary",root);array=resolved(array,root,0);
    if(!tag(array,"array"))die("missing prelink kext array");
    xmlNode *personality=NULL;unsigned candidates=0;
    for(xmlNode *entry=element(array->children);entry;entry=element(entry->next)) {
        xmlNode *id=field(entry,"CFBundleIdentifier",root);
        if(!string_is(id,"com.apple.driver.AppleMultitouchSPIC1F15",root) &&
           !string_is(id,"com.apple.driver.AppleMultitouchSPIN69",root))continue;
        xmlNode *p=field(entry,"IOKitPersonalities",root);if(!p)die("missing SPI personalities");
        /* Don't replace a reference shared by another entry. */
        xmlChar *ref=xmlGetProp(p,BAD_CAST "IDREF");if(ref) {xmlFree(ref);die("shared personality container unsupported");}
        xmlNode *a=field(p,"AppleMultitouchSPI - C1,J72",root);
        xmlNode *b=field(p,"AppleMultitouchSPI - C1,N69",root);
        if((!a && !b) || (a && b))die("unexpected SPI personality names");
        xmlNode *value=resolved(a?a:b,root,0);
        if(!string_is(field(value,"IOClass",root),"AppleMultitouchN1SPI",root) ||
           !string_is(field(value,"IOProviderClass",root),"AppleARMSPIDevice",root))die("unsupported SPI driver class");
        unsigned keys=0;for(xmlNode *n=element(p->children);n;n=element(n->next))if(tag(n,"key"))keys++;
        if(keys!=1)die("additional SPI personalities require review");
        personality=p;candidates++;
    }
    if(candidates!=1)die("missing or ambiguous J72/N69 SPI personality");
    xmlDoc *profile=xmlReadMemory(se_profile,sizeof(se_profile)-1,"N69.xml",NULL,XML_PARSE_NONET);
    if(!profile)die("invalid embedded SE profile");
    preserve_refs(root,personality,root,doc);
    xmlNode *replacement=xmlDocCopyNode(xmlDocGetRootElement(profile),doc,1);
    if(!replacement)die("XML allocation failed");
    xmlReplaceNode(personality,replacement);xmlFreeNode(personality);
    xmlBuffer *buf=xmlBufferCreate();if(!buf)die("XML allocation failed");
    if(xmlNodeDump(buf,doc,xmlDocGetRootElement(doc),0,0)<0)die("XML serialization failed");
    size_t bytes=xmlBufferLength(buf);if(bytes>=capacity)die("insufficient existing prelink padding");
    memset(data+pi,0,capacity);memcpy(data+pi,xmlBufferContent(buf),bytes);
    int fd=open(argv[2],O_WRONLY|O_CREAT|O_EXCL,0644);if(fd<0)die("output must be a new writable path");
    f=fdopen(fd,"wb");if(!f) {close(fd);unlink(argv[2]);die("cannot open output stream");}
    if(fwrite(data,1,len,f)!=len) {fclose(f);unlink(argv[2]);die("output write failed");}
    if(fclose(f)) {unlink(argv[2]);die("output close failed");}
    printf("Installed full SE N69 SPI personality: C1F57,5, size-id=2, FLL=0x17d3, analog delay=500us, ref divisor=2.\n");
    printf("Output: %s (%zu bytes, unchanged size). External mtprops/firmware are still required.\n",argv[2],len);
    xmlBufferFree(buf);xmlFreeDoc(profile);xmlFreeDoc(doc);free(data);xmlCleanupParser();return 0;
}
