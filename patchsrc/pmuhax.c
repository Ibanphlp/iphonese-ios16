/*
 * pmuhax: experimental D2365 -> D2255 PMU adaptations for an SE1 port.
 * Build: cc -std=c11 -O2 -Wall -Wextra -Wpedantic pmuhax.c -o pmuhax
 * Usage: ./pmuhax input.raw output.raw
 *
 * Raw little-endian ARM64 prelinked Mach-O only. No UUID checks, donor files,
 * kernel addresses or file offsets. All sites are discovered within the PMU
 * kext using masked instruction signatures and register descriptor patterns.
 * Signatures were derived from the supplied 16.1 iPad5 kernel. Other builds
 * must satisfy every signature; this is NOT a claim of universal 16.x support.
 * See PMU-NOTES.md for scope, evidence, limitations and hardware validation.
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
typedef struct {
    const char *name; const Word *sig; size_t count, at;
    uint32_t replacement; int change; size_t found;
} Rule;
typedef struct { size_t source, target; int test_bit; } Jump;
typedef struct { char name[17]; uint64_t va, size, offset; } Segment;
typedef struct { Segment seg[64]; size_t count; } Image;
static unsigned char *data;
static size_t length;
static void fail(const char *s) { fprintf(stderr,"pmuhax: %s\n",s); exit(1); }
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
static size_t find_bytes(size_t lo,size_t n,const void *p,size_t pn,size_t *hits) {
    size_t at=0; *hits=0;
    if (!range(lo,n) || pn==0 || pn>n) return 0;
    for (size_t j=0;j<=n-pn;j++) if (!memcmp(data+lo+j,p,pn)) {at=lo+j;(*hits)++;}
    return at;
}
static size_t unique(size_t lo,size_t n,const void *p,size_t pn,const char *label) {
    size_t hits,at=find_bytes(lo,n,p,pn,&hits);
    if (hits!=1) {fprintf(stderr,"pmuhax: %s: expected 1 match, got %zu\n",label,hits);exit(1);}
    return at;
}
/* 0: GPIO geometry / transfer: cmp w0, #0x60 -> cmp w0, #0x54 */
static const Word sig0[] = {
    {0xf94002c8u, 0xffffffffu},
    {0xf9405108u, 0xffffffffu},
    {0xaa1603e0u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0x7101801fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0xf940da61u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
};
/* 1: GPIO geometry / transfer: mov w1, #0x967 -> mov w1, #0x964 */
static const Word sig1[] = {
    {0xf9400268u, 0xffffffffu},
    {0xf942e508u, 0xffffffffu},
    {0x91009fe2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52812ce1u, 0xffffffffu},
    {0x52800023u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0x39409fe8u, 0xffffffffu},
    {0x32000d08u, 0xffffffffu},
};
/* 2: GPIO geometry / transfer: mov w1, #0x967 -> mov w1, #0x964 */
static const Word sig2[] = {
    {0xf9400268u, 0xffffffffu},
    {0xf942e908u, 0xffffffffu},
    {0x91009fe2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52812ce1u, 0xffffffffu},
    {0x52800023u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0xf9400268u, 0xffffffffu},
    {0xf942e508u, 0xffffffffu},
};
/* 3: GPIO geometry / transfer: mov w3, #0x18 -> mov w3, #0x15 */
static const Word sig3[] = {
    {0x910003f5u, 0xffffffffu},
    {0x910003e2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52800001u, 0xffffffffu},
    {0x52800303u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x35000000u, 0xff00001fu},
    {0xd2800008u, 0xffffffffu},
    {0x91000689u, 0xffffffffu},
};
/* 4: GPIO geometry / transfer: cmp x8, #0x18 -> cmp x8, #0x15 */
static const Word sig4[] = {
    {0x0a2a018au, 0xffffffffu},
    {0x2a0b014au, 0xffffffffu},
    {0x38286aaau, 0xffffffffu},
    {0x91000508u, 0xffffffffu},
    {0xf100611fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x39429268u, 0xffffffffu},
    {0x34000008u, 0xff00001fu},
    {0x90000000u, 0x9f00001fu},
};
/* 5: GPIO geometry / transfer: mov w2, #0x18 -> mov w2, #0x15 */
static const Word sig5[] = {
    {0x34000008u, 0xff00001fu},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
    {0x910003e1u, 0xffffffffu},
    {0x52800302u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x910003e2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52800001u, 0xffffffffu},
};
/* 6: GPIO geometry / transfer: mov w3, #0x18 -> mov w3, #0x15 */
static const Word sig6[] = {
    {0x94000000u, 0xfc000000u},
    {0x910003e2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52800001u, 0xffffffffu},
    {0x52800303u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x14000000u, 0xfc000000u},
    {0x52800000u, 0xffffffffu},
    {0xf85d83a8u, 0xffffffffu},
};
/* 7: GPIO geometry / transfer: mov w3, #0x18 -> mov w3, #0x15 */
static const Word sig7[] = {
    {0x910163f7u, 0xffffffffu},
    {0x910163e2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52800001u, 0xffffffffu},
    {0x52800303u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x34000000u, 0xff00001fu},
    {0xaa0003f5u, 0xffffffffu},
    {0x90000000u, 0x9f00001fu},
};
/* 8: GPIO geometry / transfer: cmp x24, #0x18 -> cmp x24, #0x15 */
static const Word sig8[] = {
    {0x52800022u, 0xffffffffu},
    {0xd2800004u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x91000718u, 0xffffffffu},
    {0xf100631fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
    {0xaa1403e1u, 0xffffffffu},
};
/* 9: GPIO geometry / transfer: mov w3, #0x18 -> mov w3, #0x15 */
static const Word sig9[] = {
    {0x9101c3f8u, 0xffffffffu},
    {0x9101c3e2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52800001u, 0xffffffffu},
    {0x52800303u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x34000000u, 0xff00001fu},
    {0xaa0003f6u, 0xffffffffu},
    {0x90000000u, 0x9f00001fu},
};
/* 10: GPIO geometry / transfer: cmp x8, #0x18 -> cmp x8, #0x15 */
static const Word sig10[] = {
    {0x3948414bu, 0xffffffffu},
    {0x0a290169u, 0xffffffffu},
    {0x39084149u, 0xffffffffu},
    {0x91000508u, 0xffffffffu},
    {0xf100611fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0xf9400268u, 0xffffffffu},
    {0xf942e908u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
};
/* 11: GPIO geometry / transfer: mov w2, #0x18 -> mov w2, #0x15 */
static const Word sig11[] = {
    {0x94000000u, 0xfc000000u},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
    {0x9101c3e1u, 0xffffffffu},
    {0x52800302u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0xb941e668u, 0xffffffffu},
    {0xf90003e8u, 0xffffffffu},
    {0x90000000u, 0x9f00001fu},
};
/* 12: GPIO geometry / transfer: cmp w22, #0x18 -> cmp w22, #0x15 */
static const Word sig12[] = {
    {0xa94157f6u, 0xffffffffu},
    {0xa8c45ff8u, 0xffffffffu},
    {0xd61f0080u, 0xffffffffu},
    {0x35000017u, 0xff00001fu},
    {0x710062dfu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x910003f7u, 0xffffffffu},
    {0x52800489u, 0xffffffffu},
    {0x90000010u, 0x9f00001fu},
};
/* 13: GPIO geometry / transfer: mov w9, #0x24 -> mov w9, #0x22 */
static const Word sig13[] = {
    {0x35000017u, 0xff00001fu},
    {0x710062dfu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x910003f7u, 0xffffffffu},
    {0x52800489u, 0xffffffffu},
    {0x90000010u, 0x9f00001fu},
    {0x91000210u, 0xffc003ffu},
    {0xd63f0200u, 0xffffffffu},
    {0x910003e8u, 0xffffffffu},
};
/* 14: GPIO geometry / transfer: mov w3, #0x24 -> mov w3, #0x22 */
static const Word sig14[] = {
    {0xf9400288u, 0xffffffffu},
    {0xf942e508u, 0xffffffffu},
    {0xaa1403e0u, 0xffffffffu},
    {0xaa1603e2u, 0xffffffffu},
    {0x52800483u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0xaa0003f5u, 0xffffffffu},
    {0x35000000u, 0xff00001fu},
    {0xd2800008u, 0xffffffffu},
};
/* 15: GPIO geometry / transfer: cmp x8, #0x12 -> cmp x8, #0x11 */
static const Word sig15[] = {
    {0xd2800008u, 0xffffffffu},
    {0x384026c9u, 0xffffffffu},
    {0x38286a69u, 0xffffffffu},
    {0x91000508u, 0xffffffffu},
    {0xf100491fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x52800256u, 0xffffffffu},
    {0xf9400288u, 0xffffffffu},
    {0xf9433108u, 0xffffffffu},
};
/* 16: GPIO geometry / transfer: mov w22, #0x12 -> mov w22, #0x11 */
static const Word sig16[] = {
    {0x38286a69u, 0xffffffffu},
    {0x91000508u, 0xffffffffu},
    {0xf100491fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x52800256u, 0xffffffffu},
    {0xf9400288u, 0xffffffffu},
    {0xf9433108u, 0xffffffffu},
    {0x12001ec1u, 0xffffffffu},
    {0xaa1403e0u, 0xffffffffu},
};
/* 17: GPIO geometry / transfer: cmp x22, #0x18 -> cmp x22, #0x15 */
static const Word sig17[] = {
    {0x52800023u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0x35000000u, 0xff00001fu},
    {0x910006d6u, 0xffffffffu},
    {0xf10062dfu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x52800015u, 0xffffffffu},
    {0x14000000u, 0xfc000000u},
    {0xaa0003f5u, 0xffffffffu},
};
/* 18: GPIO geometry / transfer: cmp w1, #0x12 -> cmp w1, #0x11 */
static const Word sig18[] = {
    {0x54000003u, 0xff00001fu},
    {0x5280003bu, 0xffffffffu},
    {0x14000000u, 0xfc000000u},
    {0x529fffe8u, 0xffffffffu},
    {0x7100483fu, 0xffffffffu},
    {0x531f7829u, 0xffffffffu},
    {0x11240129u, 0xffffffffu},
    {0x528000cau, 0xffffffffu},
    {0x1b0a7c2au, 0xffffffffu},
};
/* 19: GPIO geometry / transfer: add w10, w10, #0x8bd -> add w10, w10, #0x8c0 */
static const Word sig19[] = {
    {0x531f7829u, 0xffffffffu},
    {0x11240129u, 0xffffffffu},
    {0x528000cau, 0xffffffffu},
    {0x1b0a7c2au, 0xffffffffu},
    {0x1122f54au, 0xffffffffu},
    {0x1a8a3129u, 0xffffffffu},
    {0x71005c3fu, 0xffffffffu},
    {0x1a898100u, 0xffffffffu},
    {0xd65f03c0u, 0xffffffffu},
};
/* 20: GPIO geometry / transfer: cmp w1, #0x17 -> cmp w1, #0x14 */
static const Word sig20[] = {
    {0x528000cau, 0xffffffffu},
    {0x1b0a7c2au, 0xffffffffu},
    {0x1122f54au, 0xffffffffu},
    {0x1a8a3129u, 0xffffffffu},
    {0x71005c3fu, 0xffffffffu},
    {0x1a898100u, 0xffffffffu},
    {0xd65f03c0u, 0xffffffffu},
    {0xa9bc5ff8u, 0xffffffffu},
    {0xa90157f6u, 0xffffffffu},
};
/* 21: GPIO geometry / transfer: cmp w23, #0x18 -> cmp w23, #0x15 */
static const Word sig21[] = {
    {0xa94157f6u, 0xffffffffu},
    {0xa8c45ff8u, 0xffffffffu},
    {0xd61f0080u, 0xffffffffu},
    {0x35000018u, 0xff00001fu},
    {0x710062ffu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x910003f8u, 0xffffffffu},
    {0x52800489u, 0xffffffffu},
    {0x90000010u, 0x9f00001fu},
};
/* 22: GPIO geometry / transfer: mov w9, #0x24 -> mov w9, #0x22 */
static const Word sig22[] = {
    {0x35000018u, 0xff00001fu},
    {0x710062ffu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x910003f8u, 0xffffffffu},
    {0x52800489u, 0xffffffffu},
    {0x90000010u, 0x9f00001fu},
    {0x91000210u, 0xffc003ffu},
    {0xd63f0200u, 0xffffffffu},
    {0x910003e8u, 0xffffffffu},
};
/* 23: GPIO geometry / transfer: mov w3, #0x24 -> mov w3, #0x22 */
static const Word sig23[] = {
    {0xf942e508u, 0xffffffffu},
    {0xaa1403e0u, 0xffffffffu},
    {0xaa1503e1u, 0xffffffffu},
    {0xaa1703e2u, 0xffffffffu},
    {0x52800483u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0x34000000u, 0xff00001fu},
    {0xaa0003f6u, 0xffffffffu},
    {0x14000000u, 0xfc000000u},
};
/* 24: GPIO geometry / transfer: cmp x8, #0x12 -> cmp x8, #0x11 */
static const Word sig24[] = {
    {0xaa1703e9u, 0xffffffffu},
    {0x38686a6au, 0xffffffffu},
    {0x3800252au, 0xffffffffu},
    {0x91000508u, 0xffffffffu},
    {0xf100491fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0xf9400288u, 0xffffffffu},
    {0xf942e908u, 0xffffffffu},
    {0xaa1403e0u, 0xffffffffu},
};
/* 25: GPIO geometry / transfer: mov w3, #0x24 -> mov w3, #0x22 */
static const Word sig25[] = {
    {0xf942e908u, 0xffffffffu},
    {0xaa1403e0u, 0xffffffffu},
    {0xaa1503e1u, 0xffffffffu},
    {0xaa1703e2u, 0xffffffffu},
    {0x52800483u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0xaa0003f6u, 0xffffffffu},
    {0x35000000u, 0xff00001fu},
    {0x52800255u, 0xffffffffu},
};
/* 26: GPIO geometry / transfer: mov w21, #0x12 -> mov w21, #0x11 */
static const Word sig26[] = {
    {0x52800483u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0xaa0003f6u, 0xffffffffu},
    {0x35000000u, 0xff00001fu},
    {0x52800255u, 0xffffffffu},
    {0xf9400288u, 0xffffffffu},
    {0xf9433108u, 0xffffffffu},
    {0x12001ea1u, 0xffffffffu},
    {0xaa1403e0u, 0xffffffffu},
};
/* 27: GPIO geometry / transfer: cmp x21, #0x18 -> cmp x21, #0x15 */
static const Word sig27[] = {
    {0x52800023u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0x35000000u, 0xff00001fu},
    {0x910006b5u, 0xffffffffu},
    {0xf10062bfu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x52800016u, 0xffffffffu},
    {0x9100031fu, 0xffffffffu},
    {0xf85c83a8u, 0xffffffffu},
};
/* 28: PMU event / mask geometry: mov w9, #0x1e -> mov w9, #0x19 */
static const Word sig28[] = {
    {0x94000000u, 0xfc000000u},
    {0xd2800008u, 0xffffffffu},
    {0x90000009u, 0x9f00001fu},
    {0x3dc00120u, 0xffc003ffu},
    {0x528003c9u, 0xffffffffu},
    {0x4e080d21u, 0xffffffffu},
    {0x52801feau, 0xffffffffu},
    {0x5280004bu, 0xffffffffu},
    {0x4e080d62u, 0xffffffffu},
};
/* 29: PMU event / mask geometry: cmp x8, #0x1e -> cmp x8, #0x1a */
static const Word sig29[] = {
    {0x8b08026bu, 0xffffffffu},
    {0x3905e56au, 0xffffffffu},
    {0x91000908u, 0xffffffffu},
    {0x4ee28400u, 0xffffffffu},
    {0xf100791fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x9105e262u, 0xffffffffu},
    {0xf9400268u, 0xffffffffu},
    {0xf942e908u, 0xffffffffu},
};
/* 30: PMU event / mask geometry: mov w3, #0x1e -> mov w3, #0x19 */
static const Word sig30[] = {
    {0xf9400268u, 0xffffffffu},
    {0xf942e908u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52803801u, 0xffffffffu},
    {0x528003c3u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0x90000002u, 0x9f00001fu},
    {0xf9400042u, 0xffc003ffu},
    {0xaa1303e0u, 0xffffffffu},
};
/* 31: PMU event / mask geometry: mov w1, #0x1601 -> mov w1, #0x1301 */
static const Word sig31[] = {
    {0xd63f0100u, 0xffffffffu},
    {0x90000002u, 0x9f00001fu},
    {0xf9400042u, 0xffc003ffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x5282c021u, 0xffffffffu},
    {0xaa1303e3u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0xf9404668u, 0xffffffffu},
    {0x52858029u, 0xffffffffu},
};
/* 32: PMU event / mask geometry: mov w9, #0x2c01 -> mov w9, #0x2601 */
static const Word sig32[] = {
    {0x5282c021u, 0xffffffffu},
    {0xaa1303e3u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0xf9404668u, 0xffffffffu},
    {0x52858029u, 0xffffffffu},
    {0x8b090109u, 0xffffffffu},
    {0x5285800au, 0xffffffffu},
    {0x8b0a0102u, 0xffffffffu},
    {0x3900013fu, 0xffffffffu},
};
/* 33: PMU event / mask geometry: mov w10, #0x2c00 -> mov w10, #0x2600 */
static const Word sig33[] = {
    {0x94000000u, 0xfc000000u},
    {0xf9404668u, 0xffffffffu},
    {0x52858029u, 0xffffffffu},
    {0x8b090109u, 0xffffffffu},
    {0x5285800au, 0xffffffffu},
    {0x8b0a0102u, 0xffffffffu},
    {0x3900013fu, 0xffffffffu},
    {0x3900053fu, 0xffffffffu},
    {0xf9400268u, 0xffffffffu},
};
/* 34: PMU event / mask geometry: mov w1, #0xb0 -> mov w1, #0x98 */
static const Word sig34[] = {
    {0x3900053fu, 0xffffffffu},
    {0xf9400268u, 0xffffffffu},
    {0xf942d108u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52801601u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0x79003fffu, 0xffffffffu},
    {0xf9400268u, 0xffffffffu},
    {0xf942e508u, 0xffffffffu},
};
/* 35: PMU event / mask geometry: cmp x8, #0x1e -> cmp x8, #0x19 */
static const Word sig35[] = {
    {0x38686a8bu, 0xffffffffu},
    {0x2a0a016au, 0xffffffffu},
    {0x38286a8au, 0xffffffffu},
    {0x91000508u, 0xffffffffu},
    {0xf100791fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x3904e27fu, 0xffffffffu},
    {0xd2800017u, 0xffffffffu},
    {0x52b00018u, 0xffffffffu},
};
/* 36: PMU event / mask geometry: cmp x23, #0x1e -> cmp x23, #0x19 */
static const Word sig36[] = {
    {0x394002a8u, 0xffffffffu},
    {0x35000008u, 0xff00001fu},
    {0x14000000u, 0xfc000000u},
    {0x910006f7u, 0xffffffffu},
    {0xf1007affu, 0xffffffffu},
    {0x910023f4u, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0xf94017e8u, 0xffffffffu},
    {0x90000009u, 0x9f00001fu},
};
/* 37: PMU event / mask geometry: mov w3, #0x1e -> mov w3, #0x19 */
static const Word sig37[] = {
    {0xf9400008u, 0xffffffffu},
    {0xf942e508u, 0xffffffffu},
    {0x910063e2u, 0xffffffffu},
    {0x52803001u, 0xffffffffu},
    {0x528003c3u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0x910003f5u, 0xffffffffu},
    {0x910003e2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
};
/* 38: PMU event / mask geometry: mov w3, #0x1e -> mov w3, #0x19 */
static const Word sig38[] = {
    {0xaa0103e2u, 0xffffffffu},
    {0xf9400008u, 0xffffffffu},
    {0xf942e504u, 0xffffffffu},
    {0x52803001u, 0xffffffffu},
    {0x528003c3u, 0xffffffffu},
    {0xd61f0080u, 0xffffffffu},
    {0xd10103ffu, 0xffffffffu},
    {0xa9037bfdu, 0xffffffffu},
    {0x9100c3fdu, 0xffffffffu},
};
/* 39: PMU event / mask geometry: mov w3, #0x1e -> mov w3, #0x19 */
static const Word sig39[] = {
    {0x9a810102u, 0xffffffffu},
    {0xf9400008u, 0xffffffffu},
    {0xf942e508u, 0xffffffffu},
    {0x52802801u, 0xffffffffu},
    {0x528003c3u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0xf85f83a8u, 0xffffffffu},
    {0x90000009u, 0x9f00001fu},
    {0xf9400129u, 0xffc003ffu},
};
/* 40: PMU event / mask geometry: mov w3, #0x1e -> mov w3, #0x19 */
static const Word sig40[] = {
    {0xf9400268u, 0xffffffffu},
    {0xf942e908u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52803801u, 0xffffffffu},
    {0x528003c3u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0xd2800008u, 0xffffffffu},
    {0x9104ea74u, 0xffffffffu},
    {0x3dc00280u, 0xffffffffu},
};
/* 41: PMU event / mask geometry: mov w2, #0x1e -> mov w2, #0x19 */
static const Word sig41[] = {
    {0x54000001u, 0xff00001fu},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
    {0xaa1403e1u, 0xffffffffu},
    {0x528003c2u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x39429268u, 0xffffffffu},
    {0x34000008u, 0xff00001fu},
    {0x90000000u, 0x9f00001fu},
};
/* 42: PMU event / mask geometry: mov w2, #0x1e -> mov w2, #0x19 */
static const Word sig42[] = {
    {0x34000008u, 0xff00001fu},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
    {0x9101c3e1u, 0xffffffffu},
    {0x528003c2u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0xb941e668u, 0xffffffffu},
    {0x71001d1fu, 0xffffffffu},
    {0x54000000u, 0xff00001fu},
};
/* 43: PMU event / mask geometry: mov w3, #0x1e -> mov w3, #0x19 */
static const Word sig43[] = {
    {0x90000002u, 0x9f00001fu},
    {0x91000042u, 0xffc003ffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52803801u, 0xffffffffu},
    {0x528003c3u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0xa9077fffu, 0xffffffffu},
    {0xf90043ffu, 0xffffffffu},
    {0x91084275u, 0xffffffffu},
};
/* 44: PMU event / mask geometry: mov w2, #0x1e -> mov w2, #0x19 */
static const Word sig44[] = {
    {0x34000008u, 0xff00001fu},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
    {0xaa1403e1u, 0xffffffffu},
    {0x528003c2u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0xa9037fffu, 0xffffffffu},
    {0xf80463ffu, 0xffffffffu},
    {0xf90023ffu, 0xffffffffu},
};
/* 45: PMU event / mask geometry: mov w3, #0x1e -> mov w3, #0x19 */
static const Word sig45[] = {
    {0xf942e508u, 0xffffffffu},
    {0x9100c3e2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52803801u, 0xffffffffu},
    {0x528003c3u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0x35000000u, 0xff00001fu},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
};
/* 46: PMU event / mask geometry: mov w2, #0x1e -> mov w2, #0x19 */
static const Word sig46[] = {
    {0x35000000u, 0xff00001fu},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
    {0x9100c3e1u, 0xffffffffu},
    {0x528003c2u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
    {0x9101c3e1u, 0xffffffffu},
};
/* 47: PMU event / mask geometry: cmp x22, #0x1e -> cmp x22, #0x19 */
static const Word sig47[] = {
    {0x34000000u, 0xff00001fu},
    {0x14000000u, 0xfc000000u},
    {0x38366affu, 0xffffffffu},
    {0x910006d6u, 0xffffffffu},
    {0xf1007adfu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x52800000u, 0xffffffffu},
    {0x14000000u, 0xfc000000u},
    {0x910003e8u, 0xffffffffu},
};
/* 48: PMU event / mask geometry: cmp x21, #0x1e -> cmp x21, #0x19 */
static const Word sig48[] = {
    {0x94000000u, 0xfc000000u},
    {0x3500001au, 0xff00001fu},
    {0x38356adfu, 0xffffffffu},
    {0x910006b5u, 0xffffffffu},
    {0xf1007abfu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0xf94017e8u, 0xffffffffu},
    {0x90000009u, 0x9f00001fu},
    {0xf9400129u, 0xffc003ffu},
};
/* 49: Shutdown interrupt mask size: mov w3, #0x1e -> mov w3, #0x19 */
static const Word sig49[] = {
    {0x90000002u, 0x9f00001fu},
    {0x91000042u, 0xffc003ffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x52803801u, 0xffffffffu},
    {0x528003c3u, 0xffffffffu},
    {0xd63f0100u, 0xffffffffu},
    {0xb941d661u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
};
/* 50: 25-byte external interrupt mask copy: ldur q0, [x1, #0xe] -> ldur q0, [x1, #9] */
static const Word sig50[] = {
    {0xf9400108u, 0xffffffffu},
    {0xf90017e8u, 0xffffffffu},
    {0x3dc00020u, 0xffffffffu},
    {0x3d8003e0u, 0xffffffffu},
    {0x3cc0e020u, 0xffffffffu},
    {0x3c80e3e0u, 0xffffffffu},
    {0x910003f7u, 0xffffffffu},
    {0x52800038u, 0xffffffffu},
    {0x38766af9u, 0xffffffffu},
};
/* 51: 25-byte external interrupt mask copy: stur q0, [sp, #0xe] -> stur q0, [sp, #9] */
static const Word sig51[] = {
    {0xf90017e8u, 0xffffffffu},
    {0x3dc00020u, 0xffffffffu},
    {0x3d8003e0u, 0xffffffffu},
    {0x3cc0e020u, 0xffffffffu},
    {0x3c80e3e0u, 0xffffffffu},
    {0x910003f7u, 0xffffffffu},
    {0x52800038u, 0xffffffffu},
    {0x38766af9u, 0xffffffffu},
    {0x53185edau, 0xffffffffu},
};
/* 52: 25-byte external interrupt mask copy: ldur q0, [x1, #0xe] -> ldur q0, [x1, #9] */
static const Word sig52[] = {
    {0xf9400108u, 0xffffffffu},
    {0xf90017e8u, 0xffffffffu},
    {0x3dc00020u, 0xffffffffu},
    {0x3d8003e0u, 0xffffffffu},
    {0x3cc0e020u, 0xffffffffu},
    {0x3c80e3e0u, 0xffffffffu},
    {0x910003f6u, 0xffffffffu},
    {0x52800037u, 0xffffffffu},
    {0x38756ad8u, 0xffffffffu},
};
/* 53: 25-byte external interrupt mask copy: stur q0, [sp, #0xe] -> stur q0, [sp, #9] */
static const Word sig53[] = {
    {0xf90017e8u, 0xffffffffu},
    {0x3dc00020u, 0xffffffffu},
    {0x3d8003e0u, 0xffffffffu},
    {0x3cc0e020u, 0xffffffffu},
    {0x3c80e3e0u, 0xffffffffu},
    {0x910003f6u, 0xffffffffu},
    {0x52800037u, 0xffffffffu},
    {0x38756ad8u, 0xffffffffu},
    {0x34000018u, 0xff00001fu},
};
/* 54: LDO index bound: cmp w21, #0x20 -> cmp w21, #0x1c */
static const Word sig54[] = {
    {0x91000000u, 0xffc003ffu},
    {0x94000000u, 0xfc000000u},
    {0x52805858u, 0xffffffffu},
    {0x72bc0018u, 0xffffffffu},
    {0x710082bfu, 0xffffffffu},
    {0x54000008u, 0xff00001fu},
    {0x2a1503fau, 0xffffffffu},
    {0x9000000au, 0x9f00001fu},
    {0x9100014au, 0xffc003ffu},
};
/* 55: LDO fixed rail mask: mov x8, #0x800 -> mov w8, #0x800 */
static const Word sig55[] = {
    {0x9100014au, 0xffc003ffu},
    {0x52800188u, 0xffffffffu},
    {0x9ba82abcu, 0xffffffffu},
    {0x34000016u, 0xff00001fu},
    {0xd2810008u, 0xffffffffu},
    {0xf2a7c008u, 0xffffffffu},
    {0xf2c00028u, 0xffffffffu},
    {0x9ada2508u, 0xffffffffu},
    {0x37000008u, 0xfff8001fu},
};
/* 56: LDO fixed rail mask: movk x8, #0x3e00, lsl #16 -> movk w8, #0x1f00, lsl #16 */
static const Word sig56[] = {
    {0x52800188u, 0xffffffffu},
    {0x9ba82abcu, 0xffffffffu},
    {0x34000016u, 0xff00001fu},
    {0xd2810008u, 0xffffffffu},
    {0xf2a7c008u, 0xffffffffu},
    {0xf2c00028u, 0xffffffffu},
    {0x9ada2508u, 0xffffffffu},
    {0x37000008u, 0xfff8001fu},
    {0x529effe8u, 0xffffffffu},
};
/* 57: LDO fixed rail mask high word: movk x8, #1, lsl #32 -> nop */
static const Word sig57[] = {
    {0x9ba82abcu, 0xffffffffu},
    {0x34000016u, 0xff00001fu},
    {0xd2810008u, 0xffffffffu},
    {0xf2a7c008u, 0xffffffffu},
    {0xf2c00028u, 0xffffffffu},
    {0x9ada2508u, 0xffffffffu},
    {0x37000008u, 0xfff8001fu},
    {0x529effe8u, 0xffffffffu},
    {0x72b83fe8u, 0xffffffffu},
};
/* 58: LDO programmable rail mask: movk w8, #0xc1ff, lsl #16 -> movk w8, #0xff, lsl #16 */
static const Word sig58[] = {
    {0xf2c00028u, 0xffffffffu},
    {0x9ada2508u, 0xffffffffu},
    {0x37000008u, 0xfff8001fu},
    {0x529effe8u, 0xffffffffu},
    {0x72b83fe8u, 0xffffffffu},
    {0x9ada2508u, 0xffffffffu},
    {0x37000008u, 0xfff8001fu},
    {0x5280001bu, 0xffffffffu},
    {0x79400f99u, 0xffffffffu},
};
/* 59: LDO debug entry -> main: cbz w8, #<target> -> nop */
static const Word sig59[] = {
    {0xaa0103f5u, 0xffffffffu},
    {0xaa0003f3u, 0xffffffffu},
    {0x3900bfffu, 0xffffffffu},
    {0xb940a008u, 0xffffffffu},
    {0x34000008u, 0xff00001fu},
    {0x110006a8u, 0xffffffffu},
    {0x2a1703e9u, 0xffffffffu},
    {0x2a1403eau, 0xffffffffu},
    {0xa901abe9u, 0xffffffffu},
};
/* 60: LDO alternate-enable mask test: add w8, w21, #1 -> lsr x8, x8, x26 */
static const Word sig60[] = {
    {0xaa0003f3u, 0xffffffffu},
    {0x3900bfffu, 0xffffffffu},
    {0xb940a008u, 0xffffffffu},
    {0x34000008u, 0xff00001fu},
    {0x110006a8u, 0xffffffffu},
    {0x2a1703e9u, 0xffffffffu},
    {0x2a1403eau, 0xffffffffu},
    {0xa901abe9u, 0xffffffffu},
    {0x2a1603eau, 0xffffffffu},
};
/* 61: LDO alternate-enable false -> normal: mov w9, w23 -> nop */
static const Word sig61[] = {
    {0x3900bfffu, 0xffffffffu},
    {0xb940a008u, 0xffffffffu},
    {0x34000008u, 0xff00001fu},
    {0x110006a8u, 0xffffffffu},
    {0x2a1703e9u, 0xffffffffu},
    {0x2a1403eau, 0xffffffffu},
    {0xa901abe9u, 0xffffffffu},
    {0x2a1603eau, 0xffffffffu},
    {0xa900abe8u, 0xffffffffu},
};
/* 62: LDO alternate-enable true -> option test: mov w10, w20 -> nop */
static const Word sig62[] = {
    {0xb940a008u, 0xffffffffu},
    {0x34000008u, 0xff00001fu},
    {0x110006a8u, 0xffffffffu},
    {0x2a1703e9u, 0xffffffffu},
    {0x2a1403eau, 0xffffffffu},
    {0xa901abe9u, 0xffffffffu},
    {0x2a1603eau, 0xffffffffu},
    {0xa900abe8u, 0xffffffffu},
    {0x2a1503e9u, 0xffffffffu},
};
/* 63: LDO alternate-enable rails 1,5,14,21: and w8, w21, #<target> -> mov w8, #0x4022 */
static const Word sig63[] = {
    {0x5280001bu, 0xffffffffu},
    {0x79400f99u, 0xffffffffu},
    {0xf940d660u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x121d7aa8u, 0xffffffffu},
    {0x7100051fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x36000017u, 0xfff8001fu},
    {0x52800188u, 0xffffffffu},
};
/* 64: LDO alternate-enable rails 1,5,14,21: cmp w8, #1 -> movk w8, #0x20, lsl #16 */
static const Word sig64[] = {
    {0x79400f99u, 0xffffffffu},
    {0xf940d660u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x121d7aa8u, 0xffffffffu},
    {0x7100051fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x36000017u, 0xfff8001fu},
    {0x52800188u, 0xffffffffu},
    {0x90000009u, 0x9f00001fu},
};
/* 65: LDO gate -> mask test: b.ne #<target> -> nop */
static const Word sig65[] = {
    {0xf940d660u, 0xffffffffu},
    {0x94000000u, 0xfc000000u},
    {0x121d7aa8u, 0xffffffffu},
    {0x7100051fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x36000017u, 0xfff8001fu},
    {0x52800188u, 0xffffffffu},
    {0x90000009u, 0x9f00001fu},
    {0x91000129u, 0xffc003ffu},
};
/* 66: LDO main anchor: mov w24, #0x2c2 */
static const Word sig66[] = {
    {0xf90003e9u, 0xffffffffu},
    {0x90000000u, 0x9f00001fu},
    {0x91000000u, 0xffc003ffu},
    {0x94000000u, 0xfc000000u},
    {0x52805858u, 0xffffffffu},
    {0x72bc0018u, 0xffffffffu},
    {0x710082bfu, 0xffffffffu},
    {0x54000008u, 0xff00001fu},
    {0x2a1503fau, 0xffffffffu},
};
/* 67: LDO normal path anchor: cbz w27, #<target> */
static const Word sig67[] = {
    {0x52800023u, 0xffffffffu},
    {0xd63f0120u, 0xffffffffu},
    {0xaa0003f8u, 0xffffffffu},
    {0x35000000u, 0xff00001fu},
    {0x3400001bu, 0xff00001fu},
    {0xf9400268u, 0xffffffffu},
    {0xf942e508u, 0xffffffffu},
    {0x9100bfe2u, 0xffffffffu},
    {0xaa1303e0u, 0xffffffffu},
};
/* 68: LDO option path anchor: tbz w23, #0, #<target> */
static const Word sig68[] = {
    {0x94000000u, 0xfc000000u},
    {0x121d7aa8u, 0xffffffffu},
    {0x7100051fu, 0xffffffffu},
    {0x54000001u, 0xff00001fu},
    {0x36000017u, 0xfff8001fu},
    {0x52800188u, 0xffffffffu},
    {0x90000009u, 0x9f00001fu},
    {0x91000129u, 0xffc003ffu},
    {0x9b082748u, 0xffffffffu},
};
/* 69: LDO table ADRP anchor: adrp x10, #<target> */
static const Word sig69[] = {
    {0x72bc0018u, 0xffffffffu},
    {0x710082bfu, 0xffffffffu},
    {0x54000008u, 0xff00001fu},
    {0x2a1503fau, 0xffffffffu},
    {0x9000000au, 0x9f00001fu},
    {0x9100014au, 0xffc003ffu},
    {0x52800188u, 0xffffffffu},
    {0x9ba82abcu, 0xffffffffu},
    {0x34000016u, 0xff00001fu},
};
static Rule rules[] = {
    {"GPIO geometry / transfer", sig0, COUNT(sig0), 4, 0x7101501fu, 1, 0},
    {"GPIO geometry / transfer", sig1, COUNT(sig1), 4, 0x52812c81u, 1, 0},
    {"GPIO geometry / transfer", sig2, COUNT(sig2), 4, 0x52812c81u, 1, 0},
    {"GPIO geometry / transfer", sig3, COUNT(sig3), 4, 0x528002a3u, 1, 0},
    {"GPIO geometry / transfer", sig4, COUNT(sig4), 4, 0xf100551fu, 1, 0},
    {"GPIO geometry / transfer", sig5, COUNT(sig5), 4, 0x528002a2u, 1, 0},
    {"GPIO geometry / transfer", sig6, COUNT(sig6), 4, 0x528002a3u, 1, 0},
    {"GPIO geometry / transfer", sig7, COUNT(sig7), 4, 0x528002a3u, 1, 0},
    {"GPIO geometry / transfer", sig8, COUNT(sig8), 4, 0xf100571fu, 1, 0},
    {"GPIO geometry / transfer", sig9, COUNT(sig9), 4, 0x528002a3u, 1, 0},
    {"GPIO geometry / transfer", sig10, COUNT(sig10), 4, 0xf100551fu, 1, 0},
    {"GPIO geometry / transfer", sig11, COUNT(sig11), 4, 0x528002a2u, 1, 0},
    {"GPIO geometry / transfer", sig12, COUNT(sig12), 4, 0x710056dfu, 1, 0},
    {"GPIO geometry / transfer", sig13, COUNT(sig13), 4, 0x52800449u, 1, 0},
    {"GPIO geometry / transfer", sig14, COUNT(sig14), 4, 0x52800443u, 1, 0},
    {"GPIO geometry / transfer", sig15, COUNT(sig15), 4, 0xf100451fu, 1, 0},
    {"GPIO geometry / transfer", sig16, COUNT(sig16), 4, 0x52800236u, 1, 0},
    {"GPIO geometry / transfer", sig17, COUNT(sig17), 4, 0xf10056dfu, 1, 0},
    {"GPIO geometry / transfer", sig18, COUNT(sig18), 4, 0x7100443fu, 1, 0},
    {"GPIO geometry / transfer", sig19, COUNT(sig19), 4, 0x1123014au, 1, 0},
    {"GPIO geometry / transfer", sig20, COUNT(sig20), 4, 0x7100503fu, 1, 0},
    {"GPIO geometry / transfer", sig21, COUNT(sig21), 4, 0x710056ffu, 1, 0},
    {"GPIO geometry / transfer", sig22, COUNT(sig22), 4, 0x52800449u, 1, 0},
    {"GPIO geometry / transfer", sig23, COUNT(sig23), 4, 0x52800443u, 1, 0},
    {"GPIO geometry / transfer", sig24, COUNT(sig24), 4, 0xf100451fu, 1, 0},
    {"GPIO geometry / transfer", sig25, COUNT(sig25), 4, 0x52800443u, 1, 0},
    {"GPIO geometry / transfer", sig26, COUNT(sig26), 4, 0x52800235u, 1, 0},
    {"GPIO geometry / transfer", sig27, COUNT(sig27), 4, 0xf10056bfu, 1, 0},
    {"PMU event / mask geometry", sig28, COUNT(sig28), 4, 0x52800329u, 1, 0},
    {"PMU event / mask geometry", sig29, COUNT(sig29), 4, 0xf100691fu, 1, 0},
    {"PMU event / mask geometry", sig30, COUNT(sig30), 4, 0x52800323u, 1, 0},
    {"PMU event / mask geometry", sig31, COUNT(sig31), 4, 0x52826021u, 1, 0},
    {"PMU event / mask geometry", sig32, COUNT(sig32), 4, 0x5284c029u, 1, 0},
    {"PMU event / mask geometry", sig33, COUNT(sig33), 4, 0x5284c00au, 1, 0},
    {"PMU event / mask geometry", sig34, COUNT(sig34), 4, 0x52801301u, 1, 0},
    {"PMU event / mask geometry", sig35, COUNT(sig35), 4, 0xf100651fu, 1, 0},
    {"PMU event / mask geometry", sig36, COUNT(sig36), 4, 0xf10066ffu, 1, 0},
    {"PMU event / mask geometry", sig37, COUNT(sig37), 4, 0x52800323u, 1, 0},
    {"PMU event / mask geometry", sig38, COUNT(sig38), 4, 0x52800323u, 1, 0},
    {"PMU event / mask geometry", sig39, COUNT(sig39), 4, 0x52800323u, 1, 0},
    {"PMU event / mask geometry", sig40, COUNT(sig40), 4, 0x52800323u, 1, 0},
    {"PMU event / mask geometry", sig41, COUNT(sig41), 4, 0x52800322u, 1, 0},
    {"PMU event / mask geometry", sig42, COUNT(sig42), 4, 0x52800322u, 1, 0},
    {"PMU event / mask geometry", sig43, COUNT(sig43), 4, 0x52800323u, 1, 0},
    {"PMU event / mask geometry", sig44, COUNT(sig44), 4, 0x52800322u, 1, 0},
    {"PMU event / mask geometry", sig45, COUNT(sig45), 4, 0x52800323u, 1, 0},
    {"PMU event / mask geometry", sig46, COUNT(sig46), 4, 0x52800322u, 1, 0},
    {"PMU event / mask geometry", sig47, COUNT(sig47), 4, 0xf10066dfu, 1, 0},
    {"PMU event / mask geometry", sig48, COUNT(sig48), 4, 0xf10066bfu, 1, 0},
    {"Shutdown interrupt mask size", sig49, COUNT(sig49), 4, 0x52800323u, 1, 0},
    {"25-byte external interrupt mask copy", sig50, COUNT(sig50), 4, 0x3cc09020u, 1, 0},
    {"25-byte external interrupt mask copy", sig51, COUNT(sig51), 4, 0x3c8093e0u, 1, 0},
    {"25-byte external interrupt mask copy", sig52, COUNT(sig52), 4, 0x3cc09020u, 1, 0},
    {"25-byte external interrupt mask copy", sig53, COUNT(sig53), 4, 0x3c8093e0u, 1, 0},
    {"LDO index bound", sig54, COUNT(sig54), 4, 0x710072bfu, 1, 0},
    {"LDO fixed rail mask", sig55, COUNT(sig55), 4, 0x52810008u, 1, 0},
    {"LDO fixed rail mask", sig56, COUNT(sig56), 4, 0x72a3e008u, 1, 0},
    {"LDO fixed rail mask high word", sig57, COUNT(sig57), 4, 0xd503201fu, 1, 0},
    {"LDO programmable rail mask", sig58, COUNT(sig58), 4, 0x72a01fe8u, 1, 0},
    {"LDO debug entry -> main", sig59, COUNT(sig59), 4, 0xd503201fu, 1, 0},
    {"LDO alternate-enable mask test", sig60, COUNT(sig60), 4, 0x9ada2508u, 1, 0},
    {"LDO alternate-enable false -> normal", sig61, COUNT(sig61), 4, 0xd503201fu, 1, 0},
    {"LDO alternate-enable true -> option test", sig62, COUNT(sig62), 4, 0xd503201fu, 1, 0},
    {"LDO alternate-enable rails 1,5,14,21", sig63, COUNT(sig63), 4, 0x52880448u, 1, 0},
    {"LDO alternate-enable rails 1,5,14,21", sig64, COUNT(sig64), 4, 0x72a00408u, 1, 0},
    {"LDO gate -> mask test", sig65, COUNT(sig65), 4, 0xd503201fu, 1, 0},
    {"LDO main anchor", sig66, COUNT(sig66), 4, 0x52805858u, 0, 0},
    {"LDO normal path anchor", sig67, COUNT(sig67), 4, 0x340004fbu, 0, 0},
    {"LDO option path anchor", sig68, COUNT(sig68), 4, 0x36000237u, 0, 0},
    {"LDO table ADRP anchor", sig69, COUNT(sig69), 4, 0xb0ff6f2au, 0, 0},
};
static const Jump jumps[] = {
    {59, 66, 0},
    {61, 67, 1},
    {62, 68, 0},
    {65, 60, 0},
};
#define LDO_REFERENCE_RULE 69
static const unsigned char ldo_before[] = {
    0xb0,0x04,0x05,0xff,0xff,0x00,0x00,0x21,0x0b,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x03,0x00,0x22,0x0c,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x00,0x00,0x23,0x0d,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x00,0x00,0x24,0x0e,0x03,0x01,0x00,
    0x60,0x09,0x05,0xff,0xff,0x00,0x00,0x25,0x0f,0x03,0x01,0x00,
    0xc4,0x09,0x19,0x7f,0x7f,0x03,0x00,0x26,0x10,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x00,0x00,0x27,0x11,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x00,0x00,0x28,0x12,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x00,0x00,0x29,0x13,0x03,0x01,0x00,
    0x58,0x02,0x05,0xff,0xff,0x00,0x00,0x2a,0x14,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x00,0x00,0x2b,0x15,0x03,0x01,0x00,
    0x08,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x00,0x00,0x2d,0x16,0x03,0x01,0x00,
    0x58,0x02,0x05,0xff,0xff,0x00,0x00,0x2e,0x17,0x03,0x01,0x00,
    0x58,0x02,0x05,0xff,0xff,0x00,0x00,0x2f,0x18,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x00,0x00,0x30,0x19,0x03,0x01,0x00,
    0xc2,0x01,0x05,0x00,0x00,0x00,0x01,0x10,0x00,0x03,0x01,0x00,
    0xc2,0x01,0x05,0x00,0x00,0x00,0x01,0x11,0x01,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x12,0x02,0x03,0x01,0x00,
    0x4c,0x04,0x05,0x00,0x00,0x00,0x01,0x13,0x03,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x14,0x04,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x15,0x05,0x03,0x01,0x00,
    0x08,0x07,0x05,0x00,0x00,0x00,0x01,0x16,0x06,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x17,0x07,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x18,0x08,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1f,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x21,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x23,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1a,0x03,0x01,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x00,0x36,0x1b,0x03,0x01,0x00,
    0x88,0x13,0x32,0x1f,0x1f,0x00,0x00,0x32,0x1c,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x03,0x0e,0x00,
};
static const unsigned char ldo_after[] = {
    0x60,0x09,0x05,0xff,0xff,0x00,0x00,0x21,0x09,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x02,0x00,0x22,0x0a,0x03,0x01,0x00,
    0x60,0x09,0x05,0xff,0xff,0x00,0x00,0x23,0x0b,0x03,0x01,0x00,
    0x58,0x02,0x05,0xff,0xff,0x00,0x00,0x24,0x0c,0x03,0x01,0x00,
    0x60,0x09,0x05,0xff,0xff,0x00,0x00,0x25,0x0d,0x03,0x01,0x00,
    0xb0,0x04,0x19,0x7f,0x7f,0x02,0x00,0x26,0x0e,0x03,0x01,0x00,
    0x60,0x09,0x05,0xff,0xff,0x00,0x00,0x27,0x0f,0x03,0x01,0x00,
    0x60,0x09,0x05,0xff,0xff,0x00,0x00,0x28,0x10,0x03,0x01,0x00,
    0x60,0x09,0x05,0xff,0xff,0x00,0x00,0x29,0x11,0x03,0x01,0x00,
    0x58,0x02,0x05,0xff,0xff,0x00,0x00,0x2a,0x12,0x03,0x01,0x00,
    0x60,0x09,0x05,0xff,0xff,0x00,0x00,0x2b,0x13,0x03,0x01,0x00,
    0x08,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x60,0x09,0x05,0xff,0xff,0x00,0x00,0x2d,0x14,0x03,0x01,0x00,
    0x58,0x02,0x05,0xff,0xff,0x00,0x00,0x2e,0x15,0x03,0x01,0x00,
    0xb0,0x04,0x05,0xff,0xff,0x02,0x00,0x2f,0x16,0x03,0x01,0x00,
    0xf4,0x01,0x05,0x00,0x00,0x00,0x01,0x10,0x00,0x03,0x01,0x00,
    0xf4,0x01,0x05,0x00,0x00,0x00,0x01,0x11,0x01,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x12,0x02,0x03,0x01,0x00,
    0x4c,0x04,0x05,0x00,0x00,0x00,0x01,0x13,0x03,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x14,0x04,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x15,0x05,0x03,0x01,0x00,
    0x4c,0x04,0x05,0x00,0x00,0x08,0x01,0x16,0x06,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x17,0x07,0x03,0x01,0x00,
    0x58,0x02,0x05,0x00,0x00,0x00,0x01,0x18,0x08,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x19,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1a,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1b,0x03,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0e,0x03,0x0e,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};
static void discover_rules(size_t start,size_t size) {
    for (size_t i=0;i<COUNT(rules);i++) {
        Rule *r=&rules[i]; size_t hits=0;
        if (r->count>size/4 || r->at>=r->count) fail("bad signature dimensions");
        for (size_t j=0;j<=size-r->count*4;j+=4) {
            size_t k;
            for (k=0;k<r->count;k++)
                if ((r32(start+j+4*k)&r->sig[k].mask)!=r->sig[k].value) break;
            if (k==r->count) {r->found=start+j+4*r->at;hits++;}
        }
        if (hits!=1) {
            fprintf(stderr,"pmuhax: rule %zu (%s): expected 1 match, got %zu; no output\n",i,r->name,hits);
            exit(1);
        }
    }
}
static uint64_t adrp_add(size_t at,uint64_t pc) {
    uint32_t a=r32(at),b=r32(at+4);
    if ((a&0x9f000000)!=0x90000000 || (b&0xffc00000)!=0x91000000 ||
        (a&31)!=((b>>5)&31)) fail("invalid table address reference");
    int64_t imm=(int64_t)(((a>>5)&0x7ffff)<<2 | ((a>>29)&3));
    if (imm&(1<<20)) imm-=1<<21;
    return (pc&~UINT64_C(4095))+(uint64_t)(imm*4096)+((b>>10)&4095);
}
static void prepare_jumps(void) {
    for (size_t i=0;i<COUNT(jumps);i++) {
        const Jump *j=&jumps[i]; Rule *s=&rules[j->source],*t=&rules[j->target];
        int64_t d=(int64_t)t->found-(int64_t)s->found;
        if (d%4 || (j->test_bit ? (d < -32768 || d > 32764) :
                    (d < -134217728 || d > 134217724))) fail("branch out of range");
        s->replacement=j->test_bit ? 0x36000008u | (((uint32_t)(d/4)&0x3fff)<<5) :
                                                   0x14000000u | ((uint32_t)(d/4)&0x3ffffff);
    }
}
static const Word guard_hook_sig[] = {
{0xaa0003f7u,0xffffffffu},
{0xf9400008u,0xffffffffu},
{0xf9408d08u,0xffffffffu},
{0x52800001u,0xffffffffu},
{0xd63f0100u,0xffffffffu},
{0xaa0003f8u,0xffffffffu},
{0xf9400008u,0xffffffffu},
{0xf9401108u,0xffffffffu},
{0xd63f0100u,0xffffffffu},
{0xf94002e8u,0xffffffffu},
{0xf9401508u,0xffffffffu},
{0xaa1703e0u,0xffffffffu},
{0xd63f0100u,0xffffffffu},
{0xf9400268u,0xffffffffu},
{0xf9407508u,0xffffffffu},
{0xaa1303e0u,0xffffffffu},
{0xaa1803e1u,0xffffffffu},
{0xd63f0100u,0xffffffffu},
{0xf9400308u,0xffffffffu},
{0xf9401508u,0xffffffffu},
{0xaa1803e0u,0xffffffffu},
{0xd63f0100u,0xffffffffu},
{0xb5000018u,0xff00001fu},
{0x14000000u,0xfc000000u},
{0xb4000018u,0xff00001fu},
};
static const Word guard_cleanup_sig[] = {
{0xf9400268u,0xffffffffu},
{0xf9401508u,0xffffffffu},
{0xaa1303e0u,0xffffffffu},
{0xd63f0100u,0xffffffffu},
{0xd2800013u,0xffffffffu},
{0xaa1303e0u,0xffffffffu},
{0xa9467bfdu,0xffffffffu},
{0xa9454ff4u,0xffffffffu},
{0xa94457f6u,0xffffffffu},
{0xa9435ff8u,0xffffffffu},
{0xa94267fau,0xffffffffu},
{0x9101c3ffu,0xffffffffu},
{0xd65f03c0u,0xffffffffu},
};
/* Mandatory AppleARMPMU sample guard. Runs inside the native method's existing
 * frame: LR is already saved by that method and restored by native cleanup.
 * The temporary sample array (x23) is released exactly once on NULL; native
 * failure cleanup releases the accumulated array (x19) and returns NULL.
 * Non-NULL resumes before retain(), without changing flags or stack. */
static size_t guard_hook,guard_cave,guard_cleanup;
static uint32_t guard_words[8],guard_redirect;
static size_t guard_match(size_t start,size_t size,const Word *sig,size_t count,const char *label) {
    size_t hits=0,result=0;
    if(count>size/4)fail("guard executable section too small");
    for(size_t o=0;o<=size-count*4;o+=4) {
        size_t j=0;for(;j<count;j++)if((r32(start+o+j*4)&sig[j].mask)!=sig[j].value)break;
        if(j==count){hits++;result=start+o;}
    }
    if(hits!=1){fprintf(stderr,"pmuhax: %s: expected one match, got %zu\n",label,hits);exit(1);}
    return result;
}
static uint32_t guard_branch(uint64_t from,uint64_t to) {
    int64_t delta=(int64_t)to-(int64_t)from;
    if(delta%4 || delta/4<-(INT64_C(1)<<25) || delta/4>=(INT64_C(1)<<25))fail("guard branch out of range");
    return 0x14000000u|((uint32_t)(delta/4)&0x3ffffff);
}
static void prepare_guard(Image *kernel,Segment *pt) {
    Image armpmu={0};size_t candidates=0;
    static const char cls[]="\0site.AppleARMPMUCharger";
    for(size_t p=(size_t)pt->offset;p+32<=pt->offset+pt->size;p+=4) {
        if(r32(p)!=0xfeedfacf)continue;
        Image im;if(!parse(p,&im,0))continue;
        Segment *t=segment(&im,"__TEXT"),*x=segment(&im,"__TEXT_EXEC");
        if(!t||!x||!t->size||!x->size)continue;
        if(t->va<pt->va||t->va-pt->va>=pt->size||t->size>pt->size-(t->va-pt->va))continue;
        size_t at=map(kernel,t->va,(size_t)t->size),hits;
        if(at!=p)continue;
        find_bytes(at,(size_t)t->size,cls,sizeof(cls),&hits);
        if(hits==1){armpmu=im;candidates++;}
    }
    if(candidates!=1)fail("guard requires one AppleARMPMU image");
    Segment *x=segment(&armpmu,"__TEXT_EXEC");
    size_t start=map(kernel,x->va,(size_t)x->size);
    size_t context=guard_match(start,(size_t)x->size,guard_hook_sig,COUNT(guard_hook_sig),"PMU getObject(0)/retain context");
    guard_hook=context+5*4;
    guard_cleanup=guard_match(start,(size_t)x->size,guard_cleanup_sig,COUNT(guard_cleanup_sig),"PMU native failure cleanup");
    /* The native cast-failure branch, following sample release, must reach
     * the independently matched accumulated-array cleanup. */
    size_t cbz=context+24*4;uint32_t w=r32(cbz);
    if((w&0xff00001f)!=0xb4000018)fail("guard cleanup branch opcode changed");
    int64_t displacement=(w>>5)&0x7ffff;
    if(displacement&(1<<18))displacement-=1<<19;
    if((int64_t)cbz+displacement*4!=(int64_t)guard_cleanup)fail("guard native cleanup target mismatch");
    /* Find main-kernel executable trailing padding from section boundaries.
     * Do not treat arbitrary runs of zero bytes inside code as free space. */
    Segment *maintext=segment(kernel,"__TEXT_EXEC");
    if(!maintext||maintext->size<sizeof(guard_words))fail("guard needs executable padding");
    uint64_t section_end=maintext->va;size_t p=32;
    for(uint32_t i=0;i<r32(16);i++) {
        uint32_t cmd=r32(p),sz=r32(p+4);
        if(cmd==0x19 && !memcmp(data+p+8,"__TEXT_EXEC\0",12)) {
            if(!(r32(p+60)&4))fail("guard padding segment not executable");
            for(uint32_t j=0;j<r32(p+64);j++) {
                size_t q=p+72+(size_t)j*80;uint64_t a=r64(q+32),n=r64(q+40);
                if(a<maintext->va || a-maintext->va>maintext->size || n>maintext->size-(a-maintext->va))fail("guard section extent invalid");
                if(a+n>section_end)section_end=a+n;
            }
        }
        p+=sz;
    }
    uint64_t caveva=(section_end+3)&~UINT64_C(3);
    if(caveva<maintext->va||caveva-maintext->va>maintext->size||sizeof(guard_words)>maintext->size-(caveva-maintext->va))fail("no executable guard padding");
    guard_cave=map(kernel,caveva,sizeof(guard_words));
    for(size_t j=0;j<sizeof(guard_words);j++)if(data[guard_cave+j])fail("guard executable padding is occupied");
    uint64_t hookva=x->va+guard_hook-start,failva=x->va+guard_cleanup-start;
    guard_words[0]=0xaa0003f8; /* replay mov x24,x0 */
    guard_words[1]=0xb4000040; /* cbz x0, local empty path (two words ahead) */
    guard_words[2]=guard_branch(caveva+8,hookva+4);
    guard_words[3]=0xaa1703e0; /* mov x0,x23 */
    guard_words[4]=0xf9400008; /* ldr x8,[x0] */
    guard_words[5]=0xf9401508; /* ldr x8,[x8,#0x28] */
    guard_words[6]=0xd63f0100; /* blr x8: release temporary array */
    guard_words[7]=guard_branch(caveva+28,failva);
    guard_redirect=guard_branch(hookva,caveva);
}
static void apply_guard(void) {
    for(size_t j=0;j<COUNT(guard_words);j++)w32(guard_cave+j*4,guard_words[j]);
    w32(guard_hook,guard_redirect);
    printf("GUARD hook file +0x%zx; stub +0x%zx; native cleanup +0x%zx. Empty sample -> release temporary array and return NULL. Hardware testing pending.\n",guard_hook,guard_cave,guard_cleanup);
}
static void save(const char *path) {
    size_t n=strlen(path);
    if (n>SIZE_MAX-16) fail("output path too long");
    char *temp=malloc(n+16); if (!temp) fail("out of memory");
    snprintf(temp,n+16,"%s.tmp.XXXXXX",path);
    int fd=mkstemp(temp); if (fd<0) {perror("pmuhax: output temporary file");exit(1);}
    size_t done=0; int error=0;
    while (done<length) {
        size_t chunk=length-done; if (chunk>1048576) chunk=1048576;
        ssize_t wrote=write(fd,data+done,chunk);
        if (wrote<0 && errno==EINTR) continue;
        if (wrote<=0) {error=errno?errno:EIO;break;}
        done+=(size_t)wrote;
    }
    if (!error && fsync(fd)<0) error=errno;
    if (close(fd)<0 && !error) error=errno;
    /* link is atomic and refuses existing destinations, including the input. */
    if (!error && link(temp,path)<0) error=errno;
    unlink(temp); free(temp);
    if (error) {errno=error;perror("pmuhax: writing output");exit(1);}
}
int main(int argc,char **argv) {
    if(argc!=3 && (argc!=4 || strcmp(argv[3],"--guard-approach"))) {
        fprintf(stderr,"usage: %s [input kernel] [output kernel]\n",argv[0]);return 2;
    }
    /* The legacy guard flag is redundant; guard behavior is unconditional. */
    FILE *f=fopen(argv[1],"rb"); if (!f) {perror("pmuhax: input");return 1;}
    struct stat st;
    if (fstat(fileno(f),&st) || !S_ISREG(st.st_mode) || st.st_size<32 ||
        (uintmax_t)st.st_size>SIZE_MAX) fail("invalid input file size/type");
    length=(size_t)st.st_size; data=malloc(length);
    if (!data) fail("out of memory");
    if (fread(data,1,length,f)!=length) fail("input read failed");
    if (fclose(f)) fail("input close failed");
    Image kernel,kext={0};
    if (!parse(0,&kernel,1)) fail("expected a raw ARM64 Mach-O kernel (decompress IM4P/kernelcache first)");
    Segment *pt=segment(&kernel,"__PRELINK_TEXT"),*pi=segment(&kernel,"__PRELINK_INFO");
    if (!pt || !pi) fail("unsupported kernel layout: prelinked text/info required");
    size_t candidates=0;
    static const char classname[]="\0AppleD2365PMU";
    for (size_t p=(size_t)pt->offset;p+32<=pt->offset+pt->size;p+=4) {
        if (r32(p)!=0xfeedfacf) continue;
        Image candidate;
        if (!parse(p,&candidate,0)) continue;
        Segment *t=segment(&candidate,"__TEXT"),*x=segment(&candidate,"__TEXT_EXEC");
        if (!t || !x || !t->size || !x->size) continue;
        if (t->va<pt->va || t->va-pt->va>=pt->size || t->size>pt->size-(t->va-pt->va)) continue;
        size_t to=map(&kernel,t->va,(size_t)t->size),hits;
        if (to!=p) continue;
        find_bytes(to,(size_t)t->size,classname,sizeof(classname),&hits);
        if (hits==1) {kext=candidate;candidates++;}
    }
    if (candidates!=1) fail("expected one embedded AppleD2365PMU image");
    Segment *kt=segment(&kext,"__TEXT"),*kx=segment(&kext,"__TEXT_EXEC");
    size_t text=map(&kernel,kt->va,(size_t)kt->size);
    size_t exec=map(&kernel,kx->va,(size_t)kx->size);
    if (exec%4 || kx->size%4) fail("unaligned PMU code");
    static const char bundle[]="<key>CFBundleName</key><string>AppleD2365PMU</string>";
    size_t bs=unique((size_t)pi->offset,(size_t)pi->size,bundle,sizeof(bundle)-1,"PMU metadata");
    /* Bound the personality search by the next bundle name. */
    static const char next[]="<key>CFBundleName</key>";
    size_t end=(size_t)(pi->offset+pi->size);
    for (size_t p=bs+sizeof(bundle)-1;p+sizeof(next)-1<=end;p++)
        if (!memcmp(data+p,next,sizeof(next)-1)) {end=p;break;}
    static const char binding[]="<key>IONameMatch</key><string>pmu,d2365</string>";
    size_t bind=unique(bs,end-bs,binding,sizeof(binding)-1,"unmodified PMU IONameMatch");
    discover_rules(exec,(size_t)kx->size);
    size_t table=unique(text,(size_t)kt->size,ldo_before,sizeof(ldo_before),"D2365 LDO descriptor table");
    size_t ref=rules[LDO_REFERENCE_RULE].found;
    uint64_t tableva=adrp_add(ref,kx->va+(ref-exec));
    if (map(&kernel,tableva,sizeof(ldo_before))!=table) fail("LDO code does not reference matched descriptor table");
    static const unsigned char shutdown_before[30]={
        255,255,254,255,255,240,255,255,255,252,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};
    size_t shutdown=unique(text,(size_t)kt->size,shutdown_before,sizeof(shutdown_before),"shutdown IRQ mask");
    prepare_jumps();
    prepare_guard(&kernel,pt);
    /* All discovery/validation completes before the first mutation. */
    for (size_t i=0;i<COUNT(rules);i++) if (rules[i].change) {
        printf("%02zu  file +0x%zx  %-42s %08x -> %08x\n",i,rules[i].found,
               rules[i].name,r32(rules[i].found),rules[i].replacement);
        w32(rules[i].found,rules[i].replacement);
    }
    memcpy(data+table,ldo_after,sizeof(ldo_after));
    data[shutdown+9]=255;
    memcpy(data+bind,binding,sizeof(binding)-1);
    const char *chip=strstr(binding,"d2365");
    memcpy(data+bind+(size_t)(chip-binding),"d2255",5);
    apply_guard();
    save(argv[2]); free(data);
    printf("Wrote %s (%zu bytes). IONameMatch: pmu,d2255. Hardware validation pending.\n",argv[2],length);
    return 0;
}
