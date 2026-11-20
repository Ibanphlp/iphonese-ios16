/*
 * kextport - graft prelinked kexts between arm64 kernelcaches
 *
 * Copies AppleChestnutDisplayPMU, ApplePinotLCD and AppleSN2400Charger from a source
 * (iPhone SE 1) kernelcache into a destination (iPad 5) kernelcache,
 * finding free zero-filled space dynamically. No kernel offsets or UUID gates.
 * Cross-build private imports use unique masked instruction windows, xrefs,
 * metaclass reference records and base-vtable checks. Unsupported/ambiguous
 * inputs fail without emitting a kernel. The receiver's length never changes.
 * Build: cc -O2 -Wall -Wextra -Werror kextport.c -o kextport
 *
 * Usage: ./kextport <dst_kernel> <src_kernel> <output>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Mach-O constants */
#define MH_MAGIC_64      0xfeedfacf
#define LC_SEGMENT_64    0x19
#define LC_SYMTAB        0x02

#pragma pack(push, 1)
struct mach_header_64 {
    uint32_t magic, cputype, cpusubtype, filetype;
    uint32_t ncmds, sizeofcmds, flags, reserved;
};

struct load_command {
    uint32_t cmd, cmdsize;
};

struct segment_command_64 {
    uint32_t cmd, cmdsize;
    char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
};

struct section_64 {
    char sectname[16], segname[16];
    uint64_t addr, size;
    uint32_t offset, align, reloff, nreloc, flags;
    uint32_t reserved1, reserved2, reserved3;
};

struct symtab_command {
    uint32_t cmd, cmdsize;
    uint32_t symoff, nsyms, stroff, strsize;
};
#pragma pack(pop)

/* kmod_info offsets (arm64, packed struct) */
#define KMOD_NAME_OFF    0x10
#define KMOD_VERS_OFF    0x50
#define KMOD_ID_OFF      0x08
#define KMOD_REFCOUNT_OFF 0x90
#define KMOD_REFLIST_OFF 0x94
#define KMOD_ADDR_OFF    0x9c
#define KMOD_SIZE_OFF    0xa4
#define KMOD_HDRSIZE_OFF 0xac
#define KMOD_START_OFF   0xb4
#define KMOD_STOP_OFF    0xbc

#define MAX_SEGS  32
#define MAX_SECTS 32
#define MAX_GAPS  512
#define MAX_KEXTS 256

struct seg_info {
    char name[17];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t nsects;
    struct {
        char name[17];
        uint64_t addr, size;
        uint32_t offset;
    } sects[MAX_SECTS];
};

struct kext_seg {
    struct seg_info seg;
};

struct kext_info {
    char bundle_id[256];
    uint64_t load_addr;
    uint64_t size;
    uint64_t source_addr;
    uint64_t kmod_info_addr;
    int nseg;
    struct seg_info segs[8];
};

struct gap {
    uint64_t vmaddr;
    uint64_t fileoff;
    uint64_t size;
};

struct kernel {
    uint8_t *data;
    size_t len;
    int nseg;
    struct seg_info segs[MAX_SEGS];
    uint32_t symoff, nsyms, stroff, strsize;
};

/* ---- helpers ---- */

static int seg_by_name(struct kernel *k, const char *name) {
    for (int i = 0; i < k->nseg; i++)
        if (strcmp(k->segs[i].name, name) == 0) return i;
    return -1;
}

static int64_t vm_to_fileoff(struct kernel *k, uint64_t vm) {
    for (int i = 0; i < k->nseg; i++) {
        struct seg_info *s = &k->segs[i];
        if (vm >= s->vmaddr && vm < s->vmaddr + s->filesize)
            return (int64_t)(vm - s->vmaddr + s->fileoff);
    }
    return -1;
}

static void parse_kernel(struct kernel *k) {
    struct mach_header_64 *mh = (struct mach_header_64 *)k->data;
    if (k->len < 32 || mh->magic != MH_MAGIC_64 || mh->cputype != 0x0100000c || (mh->cpusubtype & 0xffffff) != 0 ||
        mh->sizeofcmds > k->len - 32) {
        fprintf(stderr, "Not a Mach-O 64 file\n");
        exit(1);
    }
    uint32_t off = 32;
    k->nseg = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (off > k->len || k->len - off < 8) { fprintf(stderr,"Truncated load command\n"); exit(1); }
        struct load_command *lc = (struct load_command *)(k->data + off);
        if (lc->cmdsize < 8 || lc->cmdsize > k->len - off || off + lc->cmdsize > 32ULL + mh->sizeofcmds) { fprintf(stderr,"Invalid load command size\n"); exit(1); }
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sc = (struct segment_command_64 *)(k->data + off);
            if (k->nseg == MAX_SEGS || sc->cmdsize < sizeof(*sc) || sc->nsects > MAX_SECTS ||
                sc->nsects * sizeof(struct section_64) > sc->cmdsize - sizeof(*sc) ||
                sc->fileoff > k->len || sc->filesize > k->len - sc->fileoff) {
                fprintf(stderr,"Invalid outer segment\n"); exit(1);
            }
            struct seg_info *si = &k->segs[k->nseg++];
            memset(si, 0, sizeof(*si));
            memcpy(si->name, sc->segname, 16); si->name[16] = 0;
            si->vmaddr = sc->vmaddr;
            si->vmsize = sc->vmsize;
            si->fileoff = sc->fileoff;
            si->filesize = sc->filesize;
            si->nsects = sc->nsects;
            struct section_64 *sec = (struct section_64 *)(k->data + off + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < sc->nsects && j < MAX_SECTS; j++) {
                memcpy(si->sects[j].name, sec[j].sectname, 16);
                si->sects[j].name[16] = 0;
                si->sects[j].addr = sec[j].addr;
                si->sects[j].size = sec[j].size;
                si->sects[j].offset = sec[j].offset;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            if (lc->cmdsize < sizeof(struct symtab_command)) exit(1);
            struct symtab_command *st = (struct symtab_command *)(k->data + off);
            k->symoff = st->symoff;
            k->nsyms = st->nsyms;
            k->stroff = st->stroff;
            k->strsize = st->strsize;
        }
        off += lc->cmdsize;
    }
    if (!k->nsyms || k->symoff > k->len || k->nsyms > (k->len-k->symoff)/16 ||
        k->stroff > k->len || k->strsize > k->len-k->stroff) {
        fprintf(stderr,"Missing or invalid symbol table\n"); exit(1);
    }
    for (uint32_t i=0;i<k->nsyms;i++) {
        uint32_t name; memcpy(&name,k->data+k->symoff+i*16,4);
        if(name>=k->strsize || !memchr(k->data+k->stroff+name,0,k->strsize-name)) {
            fprintf(stderr,"Invalid symbol name\n");exit(1);
        }
    }
}

static void parse_kext_segs(struct kernel *k, uint64_t load_addr, struct kext_info *ki) {
    int64_t fo = vm_to_fileoff(k, load_addr);
    if (fo < 0 || k->len-(uint64_t)fo<32) return;
    struct mach_header_64 *mh = (struct mach_header_64 *)(k->data + fo);
    if (mh->magic != MH_MAGIC_64 || mh->sizeofcmds>k->len-(uint64_t)fo-32) return;
    uint32_t off = (uint32_t)fo + 32;
    ki->nseg = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (off > k->len || k->len - off < 8) { fprintf(stderr,"Truncated load command\n"); exit(1); }
        struct load_command *lc = (struct load_command *)(k->data + off);
        if (lc->cmdsize < 8 || lc->cmdsize > k->len - off || off+lc->cmdsize>(uint64_t)fo+32+mh->sizeofcmds) { fprintf(stderr,"Invalid load command size\n"); exit(1); }
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sc = (struct segment_command_64 *)(k->data + off);
            if (ki->nseg == 8 || sc->cmdsize < sizeof(*sc) || sc->nsects > MAX_SECTS ||
                sc->nsects * sizeof(struct section_64) > sc->cmdsize - sizeof(*sc)) {
                fprintf(stderr,"Invalid kext segment\n"); exit(1);
            }
            struct seg_info *si = &ki->segs[ki->nseg++];
            memset(si, 0, sizeof(*si));
            memcpy(si->name, sc->segname, 16); si->name[16] = 0;
            si->vmaddr = sc->vmaddr;
            si->vmsize = sc->vmsize;
            si->fileoff = sc->fileoff;
            si->filesize = sc->filesize;
            si->nsects = sc->nsects;
            int64_t backing=vm_to_fileoff(k,si->vmaddr);
            if(si->vmsize<si->filesize || (si->filesize &&
                (backing<0 || si->filesize>k->len-(uint64_t)backing))) {
                fprintf(stderr,"Kext segment has no backing\n");exit(1);
            }
            struct section_64 *sec = (struct section_64 *)(k->data + off + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < sc->nsects && j < MAX_SECTS; j++) {
                memcpy(si->sects[j].name, sec[j].sectname, 16);
                si->sects[j].name[16] = 0;
                si->sects[j].addr = sec[j].addr;
                si->sects[j].size = sec[j].size;
                si->sects[j].offset = sec[j].offset;
            }
        }
        off += lc->cmdsize;
    }
}

static void protect_slide_slots(struct kernel *, const struct seg_info *, uint8_t *);

/* Only allocate outside every embedded kext's declared VM ranges.
 * Zero bytes inside a live segment include BSS, vtables and reserved storage. */
static int find_gaps(struct kernel *k, const char *segname, uint64_t min_size,
                     struct gap *gaps, int max_gaps)
{
    int si = seg_by_name(k, segname), pt = seg_by_name(k, "__PRELINK_TEXT");
    if (si < 0 || pt < 0) return 0;
    struct seg_info *s = &k->segs[si], *headers = &k->segs[pt];
    uint8_t *busy = calloc(s->filesize, 1);
    protect_slide_slots(k,s,busy);
    if (!strcmp(segname,"__DATA") || !strcmp(segname,"__DATA_CONST") || !strcmp(segname,"__TEXT_EXEC")) {
        /* Main-kernel pool fallback: protect every declared section, including
         * zerofill and typed-allocation storage. Nonzero patch bytes are also
         * excluded by the subsequent scan. */
        for (uint32_t j=0;j<s->nsects;j++) {
            uint64_t lo=s->sects[j].addr, hi=lo+s->sects[j].size;
            if (lo<s->vmaddr) lo=s->vmaddr;
            if (hi>s->vmaddr+s->filesize) hi=s->vmaddr+s->filesize;
            if (hi>lo) memset(busy+lo-s->vmaddr,1,hi-lo);
        }
    }
    for (uint64_t pos = 0; pos + 32 <= headers->filesize; pos += 4) {
        uint64_t fo = headers->fileoff + pos;
        struct mach_header_64 mh;
        memcpy(&mh, k->data + fo, sizeof(mh));
        if (mh.magic != MH_MAGIC_64 || mh.cputype != 0x0100000c) continue;
        if (mh.sizeofcmds > headers->filesize - pos - 32) {
            fprintf(stderr, "Invalid embedded Mach-O header\n"); exit(1);
        }
        if (si == pt) memset(busy + pos, 1, 32 + mh.sizeofcmds);
        /* KPI pseudoextensions contain overlapping, stripped headers and no VM storage. */
        struct segment_command_64 *first = (void *)(k->data + fo + 32);
        if (first->cmd == LC_SEGMENT_64 && !strncmp(first->segname, "__LINKEDIT",16) && !first->vmaddr) continue;
        uint64_t off = fo + 32, end = off + mh.sizeofcmds;
        for (uint32_t j = 0; j < mh.ncmds; j++) {
            struct load_command *lc = (void *)(k->data + off);
            if (off + 8 > end || lc->cmdsize < 8 || lc->cmdsize > end - off) {
                fprintf(stderr, "Invalid embedded load command at header %llx cmd %u ncmds %u size %u\n", (unsigned long long)fo, j, mh.ncmds, mh.sizeofcmds); exit(1);
            }
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *sc = (void *)lc;
                uint64_t lo = sc->vmaddr > s->vmaddr ? sc->vmaddr : s->vmaddr;
                uint64_t hi = sc->vmaddr + sc->vmsize;
                if (hi > s->vmaddr + s->filesize) hi = s->vmaddr + s->filesize;
                if (hi > lo) memset(busy + lo - s->vmaddr, 1, hi - lo);
            }
            off += lc->cmdsize;
        }
    }
    int n = 0;
    for (uint64_t i = 0; i < s->filesize;) {
        if (busy[i] || k->data[s->fileoff + i]) { i++; continue; }
        uint64_t start = i;
        while (i < s->filesize && !busy[i] && !k->data[s->fileoff + i]) i++;
        /* Eight-byte alignment also keeps GOT loads encodable. */
        start = (start + 7) & ~7ULL;
        if (i >= start && i - start >= min_size) {
            if (n == max_gaps) { fprintf(stderr, "Too many free gaps\n"); exit(1); }
            gaps[n++] = (struct gap){s->vmaddr + start, s->fileoff + start, i - start};
        }
    }
    free(busy);
    return n;
}

/* Find a gap that fits 'needed' bytes, prefer smallest fit */
static struct gap *find_best_gap(struct gap *gaps, int ngap, uint64_t needed,
                                 uint64_t *used_addrs, int nused)
{
    struct gap *best = NULL;
    for (int i = 0; i < ngap; i++) {
        if (gaps[i].size < needed) continue;
        /* skip if overlaps a used region */
        bool ok = true;
        for (int j = 0; j < nused; j++) {
            if (gaps[i].vmaddr == used_addrs[j]) { ok = false; break; }
        }
        if (!ok) continue;
        if (!best || gaps[i].size < best->size) best = &gaps[i];
    }
    static struct gap selected;
    if (!best) return NULL;
    selected = *best;
    uint64_t take = (needed + 7) & ~7ULL;
    if (take > best->size) take = needed;
    best->vmaddr += take; best->fileoff += take; best->size -= take;
    return &selected;
}

/* ---- XML plist helpers ---- */

static char *find_prelink_info(struct kernel *k, uint64_t *offset, uint64_t *max_size) {
    int si = seg_by_name(k, "__PRELINK_INFO");
    if (si < 0) return NULL;
    struct seg_info *s = &k->segs[si];
    if (!memchr(k->data + s->fileoff,0,s->filesize)) {
        fprintf(stderr,"Unterminated prelink plist\n"); exit(1);
    }
    *offset = s->fileoff;
    *max_size = s->filesize;
    return (char *)(k->data + s->fileoff);
}

static char *extract_kext_dict(const char *, const char *);
static char *expand_xml(const char *, const char *, int);

/* Find a kext entry in the plist by bundle ID, return its load addr + kmod addr */
static bool find_kext_in_plist(const char *plist, const char *bundle_id,
                               uint64_t *load_addr, uint64_t *size,
                               uint64_t *source_addr, uint64_t *kmod_info)
{
    char *raw = extract_kext_dict(plist,bundle_id);
    if (!raw) return false;
    char *entry = expand_xml(raw,plist,0); free(raw);
    const char *keys[] = {"_PrelinkExecutableLoadAddr", "_PrelinkExecutableSize",
                          "_PrelinkExecutableSourceAddr", "_PrelinkKmodInfo"};
    uint64_t *values[] = {load_addr,size,source_addr,kmod_info};
    for (int i=0;i<4;i++) {
        char needle[128]; snprintf(needle,sizeof(needle),"<key>%s</key>",keys[i]);
        const char *q=strstr(entry,needle);
        if (!q || !(q=strstr(q,"<integer")) || !(q=strchr(q,'>'))) { free(entry); return false; }
        *values[i]=strtoull(q+1,NULL,0);
    }
    free(entry); return true;
}

/* Find AppleARMPlatform load addr in a kernel's plist */
static uint64_t find_arm_platform_addr(struct kernel *k) {
    uint64_t off, maxsz;
    char *plist = find_prelink_info(k, &off, &maxsz);
    if (!plist) return 0;
    uint64_t la = 0, sz = 0, sa = 0, km = 0;
    if (find_kext_in_plist(plist, "com.apple.driver.AppleARMPlatform", &la, &sz, &sa, &km))
        return la;
    return 0;
}

/* ---- KASLR offset table ---- */

struct kaslr_table {
    uint64_t plist_data_fileoff;  /* file offset of the base64 <data> content start */
    uint64_t base64_len;
    uint32_t *offsets;
    uint32_t count;
    uint64_t prelink_text_base;
};

/* Simple base64 decoder */
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static uint8_t *b64_decode(const char *in, size_t in_len, size_t *out_len) {
    uint8_t *out = malloc(in_len);
    size_t oi = 0;
    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        int v = b64_val(in[i]);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[oi++] = (buf >> bits) & 0xff;
        }
    }
    *out_len = oi;
    return out;
}

/* Simple base64 encoder */
static const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *in, size_t in_len, size_t *out_len) {
    size_t olen = 4 * ((in_len + 2) / 3);
    char *out = malloc(olen + 1);
    size_t oi = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t n = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) n |= (uint32_t)in[i+1] << 8;
        if (i + 2 < in_len) n |= (uint32_t)in[i+2];
        out[oi++] = b64_chars[(n >> 18) & 0x3f];
        out[oi++] = b64_chars[(n >> 12) & 0x3f];
        out[oi++] = (i + 1 < in_len) ? b64_chars[(n >> 6) & 0x3f] : '=';
        out[oi++] = (i + 2 < in_len) ? b64_chars[n & 0x3f] : '=';
    }
    out[oi] = 0;
    *out_len = oi;
    return out;
}

static bool parse_kaslr_table(struct kernel *k, struct kaslr_table *kt) {
    uint64_t pi_off, pi_max;
    char *plist = find_prelink_info(k, &pi_off, &pi_max);
    if (!plist) return false;

    int si = seg_by_name(k, "__PRELINK_TEXT");
    if (si < 0) return false;
    kt->prelink_text_base = k->segs[si].vmaddr;

    const char *key = strstr(plist, "_PrelinkLinkKASLROffsets");
    if (!key) return false;
    const char *data_start = strstr(key, "<data");
    if (!data_start) return false;
    data_start = strchr(data_start, '>');
    if (!data_start) return false;
    data_start++;
    const char *data_end = strstr(data_start, "</data>");
    if (!data_end) return false;

    kt->plist_data_fileoff = pi_off + (data_start - plist);
    kt->base64_len = data_end - data_start;

    size_t decoded_len;
    uint8_t *decoded = b64_decode(data_start, data_end - data_start, &decoded_len);
    if (decoded_len < 4) { free(decoded); return false; }

    memcpy(&kt->count, decoded, 4);
    if (kt->count > (decoded_len-4)/4) { free(decoded); return false; }

    kt->offsets = malloc(kt->count * 4);
    memcpy(kt->offsets, decoded + 4, kt->count * 4);
    free(decoded);
    return true;
}

/* A tracked slot remains live even if it happens to contain zero and lies
 * outside an embedded segment. Never allocate across it. */
static void protect_slide_slots(struct kernel *k,const struct seg_info *s,uint8_t *busy) {
    struct kaslr_table table={0};
    if(!parse_kaslr_table(k,&table)) { fprintf(stderr,"Invalid receiver slide table\n");exit(1); }
    for(uint32_t j=0;j<table.count;j++) {
        uint64_t a=table.prelink_text_base+table.offsets[j];
        if(a>UINT64_MAX-8)exit(1);
        uint64_t z=a+8;
        if(a<s->vmaddr)a=s->vmaddr;
        if(z>s->vmaddr+s->filesize)z=s->vmaddr+s->filesize;
        if(z>a)memset(busy+a-s->vmaddr,1,z-a);
    }
    free(table.offsets);
}

/* ---- The main grafting logic ---- */

struct placement {
    uint64_t text_vm, text_fo;       /* __TEXT (Mach-O header) */
    uint64_t texec_vm, texec_fo;     /* __TEXT_EXEC */
    uint64_t data_vm, data_fo;       /* __DATA */
    uint64_t dconst_vm, dconst_fo;   /* __DATA_CONST */
};

static void copy_and_fixup_segment(uint8_t *dst, struct kernel *src_k,
                                   struct seg_info *src_seg,
                                   uint64_t dst_fo, uint64_t dst_vm)
{
    (void)dst_vm;
    if (src_seg->filesize == 0) return;
    int64_t src_fo = vm_to_fileoff(src_k, src_seg->vmaddr);
    if (src_fo < 0) {
        /* Segment lives in inner Mach-O with fileoff=0, compute from parent */
        return;
    }
    memcpy(dst + dst_fo, src_k->data + src_fo, src_seg->filesize);
}

/* Rewrite the kext's inner Mach-O header to reflect new addresses */
static void rewrite_kext_header(uint8_t *out, uint64_t header_fo,
                                struct kext_info *ki, struct placement *pl, bool runtime_offsets)
{
    (void)ki;
    struct mach_header_64 *mh = (struct mach_header_64 *)(out + header_fo);
    if (mh->magic != MH_MAGIC_64) return;

    uint32_t off = (uint32_t)header_fo + 32;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)(out + off);
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sc = (struct segment_command_64 *)(out + off);
            uint64_t new_vm = 0, new_fo = 0;

            if (strncmp(sc->segname, "__TEXT", 6) == 0 && sc->segname[6] == 0) {
                new_vm = pl->text_vm; new_fo = pl->text_fo;
            } else if (strncmp(sc->segname, "__TEXT_EXEC", 11) == 0) {
                new_vm = pl->texec_vm; new_fo = pl->texec_fo;
            } else if (strncmp(sc->segname, "__DATA_CONST", 12) == 0) {
                new_vm = pl->dconst_vm; new_fo = pl->dconst_fo;
            } else if (strncmp(sc->segname, "__DATA", 6) == 0 && sc->segname[6] == 0) {
                new_vm = pl->data_vm; new_fo = pl->data_fo;
            } else if (strncmp(sc->segname, "__LINKEDIT", 10) == 0) {
                if (sc->vmsize || sc->filesize) { fprintf(stderr,"Nonempty kext LINKEDIT unsupported\n"); exit(1); }
                sc->vmaddr = 0; sc->fileoff = 0;
                /* No donor linkedit storage survives in the receiver. */
                off += lc->cmdsize;
                continue;
            }

            if (new_vm) {
                /* Native KCGEN embedded offsets describe the runtime image.
                 * Charger mode also uses storage earlier in the physical file. */
                uint64_t relative=runtime_offsets?new_vm-pl->text_vm:new_fo-header_fo;
                if ((runtime_offsets?new_vm<pl->text_vm:new_fo<header_fo) || relative > UINT32_MAX) {
                    fprintf(stderr,"Kext segment cannot be represented relative to header\n"); exit(1);
                }
                uint64_t old_vm = sc->vmaddr;
                uint64_t old_fo = sc->fileoff;

                /* Update sections */
                struct section_64 *sec = (struct section_64 *)(out + off + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < sc->nsects; j++) {
                    uint64_t sect_delta = sec[j].addr - old_vm;
                    sec[j].addr = new_vm + sect_delta;
                    if (sec[j].size > 0 && sec[j].offset != 0) {
                        sec[j].offset = (uint32_t)(relative + (sec[j].offset - old_fo));
                    }
                }
                sc->vmaddr = new_vm;
                sc->fileoff = relative;
            }
        }
        off += lc->cmdsize;
    }
}

/* Fix up KASLR-tracked pointers in DATA and DATA_CONST regions */
static uint64_t placed_base(const char *name, const struct placement *p) {
    if (!strcmp(name, "__TEXT")) return p->text_vm;
    if (!strcmp(name, "__TEXT_EXEC")) return p->texec_vm;
    if (!strcmp(name, "__DATA")) return p->data_vm;
    if (!strcmp(name, "__DATA_CONST")) return p->dconst_vm;
    return 0;
}

/* Cross-build private bindings: compare unique instruction windows in the
 * dependency, masking only PC-relative operands and ADRP consumer offsets.
 * Both source and receiver must contain the window exactly once. Independent
 * windows and data xrefs must agree. No UUIDs or segment-relative guesses. */
struct code_image { uint64_t base; size_t count; uint32_t *raw, *norm; };
struct dependency { struct code_image code[2];struct kext_info image[2]; };
static struct dependency dependencies[3];static unsigned dependency_count;
static struct dependency *dependency_for(uint64_t value) {
    for(unsigned i=0;i<dependency_count;i++)for(int j=0;j<dependencies[i].image[0].nseg;j++) {
        struct seg_info *s=&dependencies[i].image[0].segs[j];
        if(value>=s->vmaddr && value-s->vmaddr<s->filesize)return &dependencies[i];
    }
    return NULL;
}
static struct { uint64_t src,dst; } bindings[256];
static unsigned nbindings;
static uint32_t u32(const void *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t u64(const void *p) { uint64_t v; memcpy(&v,p,8); return v; }
static int64_t sx(uint64_t v,unsigned b) { return (int64_t)(v^(1ULL<<(b-1)))-(int64_t)(1ULL<<(b-1)); }
static bool pagepair(uint32_t a,uint32_t b) {
    return (a&0x9f000000)==0x90000000 && ((b>>5)&31)==(a&31) &&
        ((b&0xffc00000)==0x91000000 || (b&0xffc00000)==0xf9400000);
}
static uint64_t pair_target(struct code_image *c,size_t i) {
    uint32_t a=c->raw[i],b=c->raw[i+1];
    return ((c->base+i*4)&~4095ULL) + sx(((a>>5&0x7ffff)<<2)|(a>>29&3),21)*4096 +
        ((uint64_t)(b>>10&4095) << ((b&0xffc00000)==0xf9400000 ? 3:0));
}
static void init_private(struct kernel *src,struct kernel *dst) {
    const char *names[]={"com.apple.driver.AppleARMPlatform","com.apple.driver.AppleARMPMU","com.apple.driver.AppleEmbeddedTempSensor"};
    dependency_count=3;
    for(unsigned dep=0;dep<dependency_count;dep++) {
    struct code_image *ac=dependencies[dep].code;struct kext_info *ap=dependencies[dep].image;
    struct kernel *ks[]={src,dst};
    for (int k=0;k<2;k++) {
        uint64_t addr=0,sz=0,sa=0,km=0,po=0,ps=0;
        if(dep==0)addr=find_arm_platform_addr(ks[k]);
        else {char *xml=find_prelink_info(ks[k],&po,&ps);if(xml)find_kext_in_plist(xml,names[dep],&addr,&sz,&sa,&km);}
        if (!addr) { fprintf(stderr,"Missing private dependency %s\n",names[dep]); exit(1); }
        parse_kext_segs(ks[k],addr,&ap[k]);
        for(int s=0;s<ap[k].nseg;s++) {
            struct seg_info *seg=&ap[k].segs[s];
            if(strcmp(seg->name,"__TEXT_EXEC"))continue;
            struct code_image *c=&ac[k]; c->base=seg->vmaddr; c->count=seg->filesize/4;
            int64_t fo=vm_to_fileoff(ks[k],c->base);
            if(fo<0 || seg->filesize>ks[k]->len-(uint64_t)fo)exit(1);
            c->raw=malloc(c->count*4); c->norm=malloc(c->count*4);
            memcpy(c->raw,ks[k]->data+fo,c->count*4);
            for(size_t j=0;j<c->count;j++) {
                uint32_t w=c->raw[j],n=w;
                if((w&0x9f000000)==0x90000000 || (w&0x9f000000)==0x10000000)n&=~0x60ffffe0U;
                else if((w&0x7c000000)==0x14000000)n&=0xfc000000;
                else if((w&0xff000010)==0x54000000 || (w&0x7e000000)==0x34000000 ||
                        (w&0x3b000000)==0x18000000)n&=~0xffffe0U;
                else if((w&0x7e000000)==0x36000000)n&=~0x7ffe0U;
                c->norm[j]=n;
            }
            for(size_t j=0;j<c->count;j++)if((c->raw[j]&0x9f000000)==0x90000000)
                for(size_t t=j+1;t<c->count && t<j+6;t++)if(pagepair(c->raw[j],c->raw[t])) {
                    c->norm[t]&=~(4095U<<10);break;
                }
        }
        if(!ac[k].count)exit(1);
    }
    }
}
static void agree(uint64_t *result,uint64_t candidate) {
    if(*result && *result!=candidate) { fprintf(stderr,"Conflicting private binding evidence\n");exit(1); }
    *result=candidate;
}
static uint64_t match_code(uint64_t addr) {
    struct dependency *dep=dependency_for(addr);if(!dep)return 0;
    struct code_image *s=&dep->code[0],*d=&dep->code[1];
    if(addr<s->base || addr-s->base>=s->count*4 || (addr-s->base)%4)return 0;
    size_t idx=(addr-s->base)/4; uint64_t result=0;
    unsigned sizes[]={64,48,32,24,16,12};
    for(unsigned nidx=0;nidx<6;nidx++) {
        size_t n=sizes[nidx],before[]={0,n/2,n-1};
        for(int q=0;q<3;q++) {
            if(idx<before[q])continue;
            size_t start=idx-before[q]; if(start+n>s->count)continue;
            size_t hits=0,where=0;
            for(size_t j=0;j+n<=s->count;j++)if(!memcmp(s->norm+start,s->norm+j,n*4))hits++;
            if(hits!=1)continue;
            hits=0;
            for(size_t j=0;j+n<=d->count;j++)if(!memcmp(s->norm+start,d->norm+j,n*4)) {hits++;where=j;}
            if(hits==1)agree(&result,d->base+(where+before[q])*4);
        }
    }
    return result;
}
static uint64_t named_symbol(struct kernel *src,struct kernel *dst,uint64_t value) {
    uint64_t result=0;
    for(uint32_t i=0;i<src->nsyms;i++) {
        const uint8_t *s=src->data+src->symoff+i*16;
        if(u64(s+8)!=value)continue;
        const char *name=(char *)src->data+src->stroff+u32(s);
        for(uint32_t j=0;j<dst->nsyms;j++) {
            const uint8_t *d=dst->data+dst->symoff+j*16;
            if(u64(d+8) && !strcmp(name,(char *)dst->data+dst->stroff+u32(d)))agree(&result,u64(d+8));
        }
    }
    return result;
}
/* Check the base-class ABI before accepting a vtable/metaclass record.
 * Exported slots must retain exact symbol identity and all private slots with
 * matching code must retain their indices. Private implementations can change
 * across releases; these remain at the same slot between the named anchors. */
static void check_vtable(struct kernel *src,struct kernel *dst,uint64_t a,uint64_t b) {
    int64_t af=vm_to_fileoff(src,a),bf=vm_to_fileoff(dst,b);
    if(af<0 || bf<0 || src->len-(uint64_t)af<16 || dst->len-(uint64_t)bf<16 ||
       u64(src->data+af) || u64(src->data+af+8) || u64(dst->data+bf) || u64(dst->data+bf+8))exit(1);
    unsigned named=0,private=0,changed=0;
    for(unsigned j=2;j<512;j++) {
        if(src->len-(uint64_t)af<(j+1ULL)*8 || dst->len-(uint64_t)bf<(j+1ULL)*8)exit(1);
        uint64_t x=u64(src->data+af+j*8),y=u64(dst->data+bf+j*8);
        if(!x || !y) {
            if(x!=y || named<8) { fprintf(stderr,"Base vtable length mismatch\n");exit(1); }
            printf("  Base ABI: %u slots, %u named, %u private matches, %u changed private implementations\n",j-2,named,private,changed);
            return;
        }
        uint64_t mapped=named_symbol(src,dst,x);
        if(mapped)named++;
        else { mapped=match_code(x);if(mapped)private++;else changed++; }
        if(mapped && mapped!=y) { fprintf(stderr,"Base vtable slot mismatch at +%x\n",j*8);exit(1); }
    }
    fprintf(stderr,"Unterminated base vtable\n");exit(1);
}

static uint64_t resolve_private(struct kernel *src,struct kernel *dst,uint64_t value,unsigned depth) {
    for(unsigned i=0;i<nbindings;i++)if(bindings[i].src==value)return bindings[i].dst;
    if(depth>3)return 0;
    uint64_t result=named_symbol(src,dst,value);
    if(!result)result=match_code(value);
    struct dependency *dep=dependency_for(value);
    struct code_image *ac=dep?dep->code:NULL;
    struct kext_info *ap=dep?dep->image:NULL;
    bool in_data=false;
    for(int j=0;ap && j<ap[0].nseg;j++)if(strcmp(ap[0].segs[j].name,"__TEXT_EXEC") &&
        value>=ap[0].segs[j].vmaddr && value-ap[0].segs[j].vmaddr<ap[0].segs[j].filesize)in_data=true;
    if(!result && in_data) {
        for(size_t j=0;j+1<ac[0].count;j++) {
            if(!pagepair(ac[0].raw[j],ac[0].raw[j+1]) || pair_target(&ac[0],j)!=value)continue;
            uint64_t pc=match_code(ac[0].base+j*4); if(!pc)continue;
            size_t dj=(pc-ac[1].base)/4;
            if(dj+1>=ac[1].count || !pagepair(ac[1].raw[dj],ac[1].raw[dj+1]))continue;
            agree(&result,pair_target(&ac[1],dj));
        }
        /* Metaclass reference records: [private metaclass, exported base class]. */
        int64_t fo=vm_to_fileoff(src,value);
        if(!result && fo>=0 && src->len-(uint64_t)fo>=32) {
            uint64_t first=u64(src->data+fo),second=u64(src->data+fo+8);
            uint64_t base=named_symbol(src,dst,second);
            if(first && base && !u64(src->data+fo+16) && !u64(src->data+fo+24)) {
                uint64_t meta=resolve_private(src,dst,first,depth+1);
                if(meta)for(int j=0;j<ap[1].nseg;j++) {
                    struct seg_info *seg=&ap[1].segs[j];
                    if(strcmp(seg->name,"__DATA_CONST"))continue;
                    int64_t df=vm_to_fileoff(dst,seg->vmaddr);if(df<0)continue;
                    for(uint64_t n=0;n+32<=seg->filesize;n+=8)
                        if(u64(dst->data+df+n)==meta && u64(dst->data+df+n+8)==base &&
                           !u64(dst->data+df+n+16) && !u64(dst->data+df+n+24))agree(&result,seg->vmaddr+n);
                }
            }
            /* Itanium ABI vtable header: two zero words followed by its address
             * point. Only map the header if an actual code xref maps +16. */
            if(!result && !first && !second && u64(src->data+fo+16)) {
                uint64_t point=resolve_private(src,dst,value+16,depth+1);
                int64_t df=point ? vm_to_fileoff(dst,point-16):-1;
                if(df>=0 && !u64(dst->data+df) && !u64(dst->data+df+8))result=point-16;
            }
        }
    }
    if(result && in_data) {
        int64_t sf=vm_to_fileoff(src,value),df=vm_to_fileoff(dst,result);
        if(sf<0 || df<0)exit(1);
        if(src->len-(uint64_t)sf>=32 && dst->len-(uint64_t)df>=32) {
            if(!u64(src->data+sf) && !u64(src->data+sf+8) && u64(src->data+sf+16))
                check_vtable(src,dst,value,result);
            else if(u64(src->data+sf) && named_symbol(src,dst,u64(src->data+sf+8)) &&
                    !u64(src->data+sf+16) && !u64(src->data+sf+24))
                check_vtable(src,dst,value+16,result+16);
        }
    }
    if(result) {
        if(nbindings==256)exit(1);
        bindings[nbindings].src=value;bindings[nbindings++].dst=result;
        printf("  Private binding %llx -> %llx\n",(unsigned long long)value,(unsigned long long)result);
    }
    return result;
}

/* Resolve by identity, never by nearest-symbol guesses or one global delta. */
static uint64_t translate(struct kernel *src, struct kernel *dst,
                          struct kext_info *ki, struct placement *pl, uint64_t value) {
    for (int i = 0; i < ki->nseg; i++) {
        struct seg_info *s = &ki->segs[i];
        uint64_t base = placed_base(s->name, pl);
        if (base && value >= s->vmaddr && value - s->vmaddr < s->vmsize)
            return base + value - s->vmaddr;
    }
    uint64_t exported = named_symbol(src,dst,value);
    if (exported) return exported;
    uint64_t private_value = resolve_private(src,dst,value,0);
    if (private_value) return private_value;
    fprintf(stderr, "Unresolved source address %llx in %s; refusing output\n",
            (unsigned long long)value, ki->bundle_id);
    exit(1);
}

static int64_t sign_extend(uint64_t n, unsigned bits) {
    return (int64_t)(n ^ (1ULL << (bits - 1))) - (int64_t)(1ULL << (bits - 1));
}
static uint32_t read32(const uint8_t *p) { uint32_t n; memcpy(&n,p,4); return n; }
static void write32(uint8_t *p, uint32_t n) { memcpy(p,&n,4); }
static uint32_t encode_delta(uint32_t ins, int64_t delta, unsigned bits,
                             unsigned shift, unsigned field) {
    int64_t unit = 1LL << shift;
    if (delta % unit || delta / unit < -(1LL << (bits - 1)) ||
        delta / unit >= (1LL << (bits - 1))) {
        fprintf(stderr, "PC-relative relocation out of range/alignment\n"); exit(1);
    }
    uint32_t mask = ((1U << bits) - 1);
    return (ins & ~(mask << field)) | (((uint32_t)(delta / unit) & mask) << field);
}

/* Supported ADRP pairs consume/overwrite the page register immediately.
 * Reject unfamiliar sequences rather than silently emitting broken code. */
static void fixup_instructions(uint8_t *out, struct kernel *src, struct kernel *dst,
                               struct kext_info *ki, struct placement *pl) {
    unsigned pairs = 0, relatives = 0;
    for (int si = 0; si < ki->nseg; si++) {
        struct seg_info *s = &ki->segs[si];
        if (strcmp(s->name,"__TEXT_EXEC")) continue;
        int64_t sf = vm_to_fileoff(src,s->vmaddr);
        for (uint64_t i = 0; i + 4 <= s->filesize; i += 4) {
            uint32_t w = read32(src->data + sf + i), patched = w;
            uint64_t pc = s->vmaddr + i, npc = pl->texec_vm + i;
            if ((w & 0x9f000000) == 0x90000000) {
                if (i + 8 > s->filesize) { fprintf(stderr,"Truncated ADRP pair\n"); exit(1); }
                uint32_t next = read32(src->data + sf + i + 4), rd = w & 31;
                bool add = (next & 0xffc00000) == 0x91000000;
                bool load = (next & 0xffc00000) == 0xf9400000;
                if ((!add && !load) || ((next >> 5) & 31) != rd || (next & 31) != rd) {
                    fprintf(stderr,"Unsupported ADRP consumer at %llx\n",(unsigned long long)pc); exit(1);
                }
                int64_t imm = sign_extend(((w >> 5 & 0x7ffff) << 2) | (w >> 29 & 3),21);
                uint64_t target = (pc & ~4095ULL) + imm * 4096 +
                    ((next >> 10 & 4095) << (load ? 3 : 0));
                uint64_t mapped = translate(src,dst,ki,pl,target);
                int64_t pages = ((int64_t)(mapped & ~4095ULL) - (int64_t)(npc & ~4095ULL))/4096;
                if (pages < -(1<<20) || pages >= (1<<20) || (load && (mapped & 7))) {
                    fprintf(stderr,"Unencodable ADRP target\n"); exit(1);
                }
                uint32_t imm21 = (uint32_t)pages & 0x1fffff;
                patched = (w & ~0x60ffffe0U) | ((imm21 & 3) << 29) | ((imm21 >> 2) << 5);
                next = (next & ~(4095U << 10)) | (((mapped & 4095) >> (load ? 3 : 0)) << 10);
                write32(out + pl->texec_fo + i,patched);
                write32(out + pl->texec_fo + i + 4,next);
                pairs++; i += 4; continue;
            }
            if ((w & 0x9f000000) == 0x10000000) {
                int64_t imm = sign_extend(((w >> 5 & 0x7ffff) << 2) | (w >> 29 & 3),21);
                int64_t delta = (int64_t)translate(src,dst,ki,pl,pc + imm) - (int64_t)npc;
                if (delta < -(1<<20) || delta >= (1<<20)) { fprintf(stderr,"ADR out of range\n"); exit(1); }
                uint32_t im = (uint32_t)delta & 0x1fffff;
                patched = (w & ~0x60ffffe0U) | ((im & 3) << 29) | ((im >> 2) << 5);
                relatives++;
            } else {
                unsigned bits = 0, field = 0;
                if ((w & 0x7c000000) == 0x14000000) bits = 26;
                else if ((w & 0xff000010) == 0x54000000 ||
                         (w & 0x7e000000) == 0x34000000 ||
                         (w & 0x3b000000) == 0x18000000) { bits = 19; field = 5; }
                else if ((w & 0x7e000000) == 0x36000000) { bits = 14; field = 5; }
                if (bits) {
                    int64_t off = sign_extend((w >> field) & ((1U << bits)-1),bits)*4;
                    uint64_t mapped = translate(src,dst,ki,pl,pc + off);
                    patched = encode_delta(w,(int64_t)mapped-(int64_t)npc,bits,2,field);
                    relatives++;
                }
            }
            write32(out + pl->texec_fo + i,patched);
        }
    }
    printf("  Relocated %u ADRP pairs and %u other PC-relative instructions\n",pairs,relatives);
}

/* Iterate relocation records, including pointers aligned to four bytes. */
static int fixup_pointers(uint8_t *out, struct kernel *src_k, struct kernel *dst_k,
                          struct kext_info *ki, struct placement *pl,
                          struct kaslr_table *src_kt, struct kaslr_table *dst_kt,
                          uint64_t arm_platform_delta,
                          uint32_t **new_kaslr_offsets, int *new_kaslr_count) {
    (void)arm_platform_delta;
    *new_kaslr_count = 0;
    *new_kaslr_offsets = malloc((src_kt->count + 1ULL) * sizeof(uint32_t));
    for (uint32_t r = 0; r < src_kt->count; r++) {
        uint64_t loc = src_kt->prelink_text_base + src_kt->offsets[r];
        for (int i = 0; i < ki->nseg; i++) {
            struct seg_info *s = &ki->segs[i];
            uint64_t base = placed_base(s->name,pl), fo = 0;
            if (!base || loc < s->vmaddr || loc - s->vmaddr + 8 > s->filesize) continue;
            if (!strcmp(s->name,"__DATA")) fo = pl->data_fo;
            else if (!strcmp(s->name,"__DATA_CONST")) fo = pl->dconst_fo;
            else { fprintf(stderr,"Unexpected relocation in %s\n",s->name); exit(1); }
            uint64_t off = loc - s->vmaddr, ptr;
            int64_t sf = vm_to_fileoff(src_k,loc);
            memcpy(&ptr,src_k->data + sf,8);
            ptr = translate(src_k,dst_k,ki,pl,ptr);
            memcpy(out + fo + off,&ptr,8);
            (*new_kaslr_offsets)[(*new_kaslr_count)++] = (uint32_t)(base+off-dst_kt->prelink_text_base);
        }
    }
    return *new_kaslr_count;
}

/* Fix kmod_info structure */
static void fixup_kmod_info(uint8_t *out, uint64_t kmod_fo, struct placement *pl,
                            uint64_t old_text_vm, uint64_t old_text_exec_vm,
                            uint64_t text_size)
{
    (void)old_text_vm; (void)old_text_exec_vm; (void)text_size;
    /* kmod_info.address = kext __TEXT base */
    memcpy(out + kmod_fo + KMOD_ADDR_OFF, &pl->text_vm, 8);

    /* kmod_info.size stays the same (total kext size, doesn't change) */

    /* kmod_info.start and stop are function pointers into __TEXT_EXEC,
       they're KASLR-tracked and handled by the pointer fixup */
}

/* ---- PRELINK_INFO plist manipulation ---- */

/* XML fragments here use Apple's serialized plist grammar (ID/IDREF).
 * Expand donor references before insertion to avoid colliding with receiver IDs. */
static const char *xml_end(const char *start) {
    char tag[64]; size_t n = 0;
    const char *p = start + 1;
    while (*p && *p != '>' && *p != ' ' && *p != '/' && n < sizeof(tag)-1) tag[n++] = *p++;
    tag[n] = 0;
    const char *gt = strchr(p,'>');
    if (!n || !gt) { fprintf(stderr,"Invalid plist XML element\n"); exit(1); }
    if (gt[-1] == '/') return gt+1;
    int depth = 1; p = gt+1;
    while ((p = strchr(p,'<'))) {
        bool close = p[1]=='/'; const char *name = p+1+close;
        if (!strncmp(name,tag,n) && (name[n]=='>' || name[n]==' ' || name[n]=='/')) {
            const char *e = strchr(name,'>');
            if (!e) break;
            if (close) depth--; else if (e[-1]!='/') depth++;
            if (!depth) return e+1;
        }
        p++;
    }
    fprintf(stderr,"Unterminated plist element\n"); exit(1);
}
static char *extract_kext_dict(const char *plist, const char *bundle_id) {
    char needle[512]; snprintf(needle,sizeof(needle),"<key>CFBundleIdentifier</key><string>%s</string>",bundle_id);
    const char *match = strstr(plist,needle);
    if (!match) return NULL;
    const char *stack[128]; int depth = 0;
    for (const char *p=plist; p<match; p++) {
        if (!strncmp(p,"<dict>",6)) { if (depth==128) exit(1); stack[depth++]=p; }
        else if (!strncmp(p,"</dict>",7)) depth--;
    }
    if (depth<=0) return NULL;
    const char *start = stack[depth-1], *end=xml_end(start);
    size_t size=end-start; char *out=malloc(size+1);
    memcpy(out,start,size); out[size]=0; return out;
}
static char *expand_xml(const char *fragment, const char *source, int depth) {
    if (depth > 32) { fprintf(stderr,"Cyclic plist reference\n"); exit(1); }
    size_t cap=1024, n=0; char *result=malloc(cap);
    for (const char *p=fragment; *p;) {
        const char *end=p+1; char *owned=NULL; const char *chunk=p; size_t count=1;
        if (*p=='<') {
            const char *gt=strchr(p,'>'); if (!gt) exit(1);
            const char *ref=strstr(p," IDREF=\"");
            if (ref && ref<gt) {
                const char *id=ref+8, *q=strchr(id,'"');
                char needle[128]; if (!q || q-id>80) exit(1);
                snprintf(needle,sizeof(needle)," ID=\"%.*s\"",(int)(q-id),id);
                const char *def=strstr(source,needle); if (!def) { fprintf(stderr,"Missing XML ID\n"); exit(1); }
                while (def>source && *def!='<') def--;
                const char *de=xml_end(def); char *tmp=malloc(de-def+1);
                memcpy(tmp,def,de-def); tmp[de-def]=0;
                owned=expand_xml(tmp,source,depth+1); free(tmp);
                chunk=owned; count=strlen(owned); end=xml_end(p);
            } else {
                const char *id=strstr(p," ID=\"");
                end=gt+1;
                if (id && id<gt) {
                    const char *q=strchr(id+5,'"'); if (!q || q>gt) exit(1);
                    owned=malloc(end-p+1); size_t head=id-p;
                    memcpy(owned,p,head); memcpy(owned+head,q+1,end-q-1);
                    count=head+end-q-1; owned[count]=0; chunk=owned;
                } else count=end-p;
            }
        }
        if (n+count+1>cap) { cap=(n+count+1)*2; result=realloc(result,cap); }
        memcpy(result+n,chunk,count); n+=count; free(owned); p=end;
    }
    result[n]=0; return result;
}
static char *set_xml_address(char *entry,const char *key,uint64_t address) {
    char needle[128]; snprintf(needle,sizeof(needle),"<key>%s</key>",key);
    char *p=strstr(entry,needle); if (!p) { fprintf(stderr,"Missing %s\n",key); exit(1); }
    p+=strlen(needle); while (*p==' '||*p=='\n'||*p=='\t') p++;
    const char *end=xml_end(p); char value[128];
    int n=snprintf(value,sizeof(value),"<integer size=\"64\">0x%llx</integer>",(unsigned long long)address);
    size_t head=p-entry, tail=strlen(end);
    char *out=malloc(head+n+tail+1); memcpy(out,entry,head); memcpy(out+head,value,n);
    memcpy(out+head+n,end,tail+1); free(entry); return out;
}

/* XNU's early KCGEN allocator walks this SECTION, not the plist. Headers
 * must form an unbroken chain advancing by round_up(__TEXT.filesize,64).
 * Constants can share the enclosing segment, but must be outside this section. */
static struct section_64 *header_section(struct kernel *k) {
    struct mach_header_64 *mh=(void *)k->data; uint64_t off=32;
    for(uint32_t i=0;i<mh->ncmds;i++) {
        struct load_command *lc=(void *)(k->data+off);
        if(lc->cmd==LC_SEGMENT_64) {
            struct segment_command_64 *seg=(void *)lc;
            if(!strncmp(seg->segname,"__PRELINK_TEXT",16)) {
                struct section_64 *sec=(void *)(seg+1);
                for(uint32_t j=0;j<seg->nsects;j++)
                    if(!strncmp(sec[j].sectname,"__text",16))return &sec[j];
            }
        }
        off+=lc->cmdsize;
    }
    fprintf(stderr,"Missing prelink header section\n");exit(1);
}
static uint64_t walk_headers(struct kernel *k) {
    struct section_64 *section=header_section(k);
    uint64_t cur=section->addr,end=cur+section->size;
    while(cur<end) {
        int64_t f=vm_to_fileoff(k,cur);
        if(f<0 || end-cur<32 || k->len-(uint64_t)f<32){ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); }
        struct mach_header_64 *mh=(void *)(k->data+f);
        if(!mh->magic) {
            int64_t tail=vm_to_fileoff(k,end-1);
            if(tail<0 || (uint64_t)(tail-f)+1!=end-cur){ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); }
            for(uint64_t j=0;j<end-cur;j++)if(k->data[f+j]) {
                fprintf(stderr,"Nonzero data after prelink header chain\n");{ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); }
            }
            return cur;
        }
        if(mh->magic!=MH_MAGIC_64 || mh->sizeofcmds>end-cur-32) {
            fprintf(stderr,"Invalid sequential prelink header at %llx\n",(unsigned long long)cur);{ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); }
        }
        uint64_t off=f+32,limit=off+mh->sizeofcmds,text=0;bool split=false;
        for(uint32_t j=0;j<mh->ncmds;j++) {
            if(off+8>limit){ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); }
            struct load_command *lc=(void *)(k->data+off);
            if(lc->cmdsize<8 || lc->cmdsize>limit-off){ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); }
            if(lc->cmd==0x1e)split=true;
            if(lc->cmd==LC_SEGMENT_64) {
                if(lc->cmdsize<sizeof(struct segment_command_64)){ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); }
                struct segment_command_64 *s=(void *)lc;
                /* KPI pseudoextensions have overlapping stripped commands.
                 * Their first, empty LINKEDIT identifies the no-TEXT case. */
                if(j==0 && !strncmp(s->segname,"__LINKEDIT",16) && !s->vmaddr)break;
                if(!strncmp(s->segname,"__TEXT",16))text=s->filesize;
            }
            off+=lc->cmdsize;
        }
        if(text && !split) { fprintf(stderr,"Unsupported nonsplit header chain\n");{ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); } }
        uint64_t step=text?text:mh->sizeofcmds;
        if(!step || step>UINT64_MAX-63){ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); }
        step=(step+63)&~63ULL;
        if(step>end-cur){ fprintf(stderr,"Header walk bounds failure line %d at %llx\n",__LINE__,(unsigned long long)cur);exit(1); }
        cur+=step;
    }
    return cur;
}

/* Universal wrappers use big-endian fat_arch records. Mach-O offsets inside
 * an architecture are relative to its slice, so normalize the donor before
 * reading segments, symbols or prelink metadata. */
static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
static uint64_t be64(const uint8_t *p) { return (uint64_t)be32(p)<<32 | be32(p+4); }
static void select_source_slice(struct kernel *k) {
    if(k->len<8)return;
    uint32_t magic=be32(k->data);
    if(magic!=0xcafebabe && magic!=0xcafebabf)return;
    uint32_t count=be32(k->data+4),stride=magic==0xcafebabf?32:20;
    if(!count || count>(k->len-8)/stride) { fprintf(stderr,"Invalid universal donor table\n");exit(1); }
    uint64_t offset=0,size=0;unsigned matches=0;
    for(uint32_t i=0;i<count;i++) {
        const uint8_t *arch=k->data+8+(uint64_t)i*stride;
        uint64_t a=stride==32?be64(arch+8):be32(arch+8);
        uint64_t n=stride==32?be64(arch+16):be32(arch+12);
        if(a<8+(uint64_t)count*stride || a>k->len || n>k->len-a) {
            fprintf(stderr,"Invalid universal donor slice bounds\n");exit(1);
        }
        /* These receivers are plain arm64, not arm64e/PAC. */
        if(be32(arch)==0x100000c && (be32(arch+4)&0xffffff)==0) {offset=a;size=n;matches++;}
    }
    if(matches!=1 || size<32) { fprintf(stderr,"Need exactly one plain arm64 donor slice\n");exit(1); }
    uint8_t *slice=malloc((size_t)size);if(!slice)exit(1);
    memcpy(slice,k->data+offset,(size_t)size);free(k->data);k->data=slice;k->len=(size_t)size;
    printf("Selected arm64 donor slice: %llu bytes at wrapper offset %llu\n",(unsigned long long)size,(unsigned long long)offset);
}

/* ---- main ---- */

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <dst_kernel> <src_kernel> <output>\n", argv[0]);
        return 1;
    }

    const int kext_count = 3;

    struct stat input_stat, output_stat;
    for (int i=1;i<=2;i++) {
        if (!stat(argv[i],&input_stat) && !stat(argv[3],&output_stat) &&
            input_stat.st_dev==output_stat.st_dev && input_stat.st_ino==output_stat.st_ino) {
            fprintf(stderr,"Output must not alias an input file\n"); return 1;
        }
    }
    /* Load files */
    FILE *f;
    struct kernel dst, src;
    memset(&dst, 0, sizeof(dst));
    memset(&src, 0, sizeof(src));

    f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END); dst.len = ftell(f); fseek(f, 0, SEEK_SET);
    dst.data = malloc(dst.len);
    if (dst.len < 32 || fread(dst.data, 1, dst.len, f) != dst.len) { fprintf(stderr,"Invalid destination read\n"); return 1; }
    fclose(f);

    f = fopen(argv[2], "rb");
    if (!f) { perror(argv[2]); return 1; }
    fseek(f, 0, SEEK_END); src.len = ftell(f); fseek(f, 0, SEEK_SET);
    src.data = malloc(src.len);
    if (src.len < 32 || fread(src.data, 1, src.len, f) != src.len) { fprintf(stderr,"Invalid source read\n"); return 1; }
    fclose(f);

    select_source_slice(&src);
    parse_kernel(&dst);
    parse_kernel(&src);

    printf("Dst kernel: %zu bytes, %d segments\n", dst.len, dst.nseg);
    printf("Src kernel: %zu bytes, %d segments\n", src.len, src.nseg);

    /* Make output as copy of dst */
    uint8_t *out = malloc(dst.len);
    memcpy(out, dst.data, dst.len);

    uint64_t pi_off_check, pi_size_check;
    char *existing = find_prelink_info(&dst,&pi_off_check,&pi_size_check);
    if (!existing || strstr(existing,"com.apple.driver.ApplePinotLCD</string>") ||
        strstr(existing,"com.apple.driver.AppleChestnutDisplayPMU</string>") ||
        strstr(existing,"com.apple.driver.AppleSN2400Charger</string>")) {
        fprintf(stderr,"Destination missing metadata or already contains a requested kext\n"); return 1;
    }
    /* Find source plist */
    uint64_t src_pi_off, src_pi_max;
    char *src_plist = find_prelink_info(&src, &src_pi_off, &src_pi_max);
    if (!src_plist) { fprintf(stderr, "No __PRELINK_INFO in source\n"); return 1; }

    /* Only selected kexts are required, allocated, relocated and inserted. */
    struct {
        const char *bundle_id;
        const char *short_name;
        struct kext_info ki;
    } kexts[3] = {
        { "com.apple.driver.AppleChestnutDisplayPMU", "AppleChestnutDisplayPMU", {0} },
        { "com.apple.driver.ApplePinotLCD", "ApplePinotLCD", {0} },
        { "com.apple.driver.AppleSN2400Charger", "AppleSN2400Charger", {0} }
    };

    for (int i = 0; i < kext_count; i++) {
        struct kext_info *ki = &kexts[i].ki;
        memset(ki, 0, sizeof(*ki));
        strncpy(ki->bundle_id, kexts[i].bundle_id, sizeof(ki->bundle_id) - 1);

        if (!find_kext_in_plist(src_plist, kexts[i].bundle_id,
                                &ki->load_addr, &ki->size,
                                &ki->source_addr, &ki->kmod_info_addr)) {
            fprintf(stderr, "Cannot find %s in source kernel\n", kexts[i].bundle_id);
            return 1;
        }

        parse_kext_segs(&src, ki->load_addr, ki);
        if(ki->nseg!=5) { fprintf(stderr,"Unsupported donor segment layout\n");return 1; }
        for(int j=0;j<ki->nseg;j++) {
            struct seg_info *s=&ki->segs[j];
            if(strcmp(s->name,"__TEXT") && strcmp(s->name,"__TEXT_EXEC") &&
               strcmp(s->name,"__DATA") && strcmp(s->name,"__DATA_CONST") && strcmp(s->name,"__LINKEDIT"))return 1;
        }
        char *raw=extract_kext_dict(src_plist,ki->bundle_id);
        char *entry=expand_xml(raw,src_plist,0);free(raw);
        const char *libs=strstr(entry,"<key>OSBundleLibraries</key>");
        if(!libs) { free(entry);return 1; }
        libs=strstr(libs,"<dict>"); const char *libs_end=xml_end(libs);
        for(const char *q=libs;(q=strstr(q,"<key>")) && q<libs_end;q+=5) {
            const char *end=strstr(q,"</key>");char id[256];
            if(!end || end-q-5>=255)return 1;
            snprintf(id,sizeof(id),"%.*s",(int)(end-q-5),q+5);
            char *dependency=extract_kext_dict(existing,id);
            if(!dependency) { fprintf(stderr,"Missing receiver dependency %s\n",id);return 1; }
            free(dependency);
        }
        free(entry);
        printf("\n%s: load=%llx size=%llx kmod=%llx segs=%d\n",
               kexts[i].short_name,
               (unsigned long long)ki->load_addr,
               (unsigned long long)ki->size,
               (unsigned long long)ki->kmod_info_addr,
               ki->nseg);
        for (int s = 0; s < ki->nseg; s++)
            printf("  %-16s vm=%llx vmsize=%llx filesize=%llx\n",
                   ki->segs[s].name,
                   (unsigned long long)ki->segs[s].vmaddr,
                   (unsigned long long)ki->segs[s].vmsize,
                   (unsigned long long)ki->segs[s].filesize);
    }

    /* Find free gaps in dst kernel */
    struct gap te_gaps[MAX_GAPS], pt_gaps[MAX_GAPS], pd_gaps[MAX_GAPS], pdc_gaps[MAX_GAPS];
    struct gap kernel_code[MAX_GAPS],kernel_const[MAX_GAPS];
    int nkcode=find_gaps(&dst,"__TEXT_EXEC",0x100,kernel_code,MAX_GAPS);
    int nkconst=find_gaps(&dst,"__DATA_CONST",0x100,kernel_const,MAX_GAPS);
    int n_te = find_gaps(&dst, "__PLK_TEXT_EXEC", 0x100, te_gaps, MAX_GAPS);
    int n_pt = find_gaps(&dst, "__PRELINK_TEXT", 0x40, pt_gaps, MAX_GAPS);
    int n_pd = find_gaps(&dst, "__PRELINK_DATA", 0x40, pd_gaps, MAX_GAPS);
    int n_pdc = find_gaps(&dst, "__PLK_DATA_CONST", 0x40, pdc_gaps, MAX_GAPS);

    printf("\nFree gaps: TEXT_EXEC=%d, PRELINK_TEXT=%d, PRELINK_DATA=%d, DATA_CONST=%d\n",
           n_te, n_pt, n_pd, n_pdc);

    init_private(&src,&dst);
    int64_t arm_delta = 0;

    /* Parse KASLR tables */
    struct kaslr_table src_kt, dst_kt;
    if (!parse_kaslr_table(&src, &src_kt)) {
        fprintf(stderr, "Failed to parse source KASLR table\n"); return 1;
    }
    if (!parse_kaslr_table(&dst, &dst_kt)) {
        fprintf(stderr, "Failed to parse dst KASLR table\n"); return 1;
    }
    printf("KASLR offsets: src=%u dst=%u\n", src_kt.count, dst_kt.count);

    /* Place kexts */
    uint64_t used_te[4] = {0}, used_pt[8] = {0}, used_pd[4] = {0};
    uint64_t used_kcode[4]={0},used_kconst[4]={0};int nused_kcode=0,nused_kconst=0;
    int nused_te = 0, nused_pt = 0, nused_pd = 0;

    struct placement placements[3] = {0};
    uint64_t chain_end=walk_headers(&dst),header_bytes=0;
    for(int i=0;i<kext_count;i++)for(int j=0;j<kexts[i].ki.nseg;j++)
        if(!strcmp(kexts[i].ki.segs[j].name,"__TEXT"))
            header_bytes+=(kexts[i].ki.segs[j].filesize+63)&~63ULL;
    struct gap *header_gap=NULL;
    for(int i=0;i<n_pt;i++)if(chain_end>=pt_gaps[i].vmaddr &&
        chain_end-pt_gaps[i].vmaddr<=pt_gaps[i].size &&
        header_bytes<=pt_gaps[i].size-(chain_end-pt_gaps[i].vmaddr))header_gap=&pt_gaps[i];
    if(!header_gap) { fprintf(stderr,"No free tail at the sequential header-chain end\n");return 1; }
    uint64_t skip=chain_end-header_gap->vmaddr;
    header_gap->vmaddr+=skip;header_gap->fileoff+=skip;header_gap->size-=skip;
    for(int i=0;i<kext_count;i++) {
        uint64_t size=0;
        for(int j=0;j<kexts[i].ki.nseg;j++)if(!strcmp(kexts[i].ki.segs[j].name,"__TEXT"))size=kexts[i].ki.segs[j].filesize;
        size=(size+63)&~63ULL;
        placements[i].text_vm=header_gap->vmaddr;placements[i].text_fo=header_gap->fileoff;
        header_gap->vmaddr+=size;header_gap->fileoff+=size;header_gap->size-=size;
    }
    uint64_t new_header_end=chain_end+header_bytes;
    /* Preserve the enclosing mapping; only bound the header walker to headers.
     * The remaining mapped zero tail can hold the constant payloads. */
    struct kernel output_view=dst;output_view.data=out;
    struct section_64 *section=header_section(&output_view);
    section->size=new_header_end-section->addr;
    for(int i=0;i<n_pt;i++)if(pt_gaps[i].vmaddr<new_header_end)pt_gaps[i].size=0;
    uint32_t *all_new_kaslr = malloc(((uint64_t)kext_count * src_kt.count + 1) * sizeof(uint32_t));
    int total_new_kaslr = 0;

    for (int i = 0; i < kext_count; i++) {
        struct kext_info *ki = &kexts[i].ki;
        struct placement *pl = &placements[i];

        /* Find __TEXT header size */
        uint64_t text_size = 0, texec_size = 0, data_size = 0, dconst_size = 0;
        for (int s = 0; s < ki->nseg; s++) {
            if (strcmp(ki->segs[s].name, "__TEXT") == 0) text_size = ki->segs[s].filesize;
            else if (strcmp(ki->segs[s].name, "__TEXT_EXEC") == 0) texec_size = ki->segs[s].filesize;
            else if (strcmp(ki->segs[s].name, "__DATA") == 0) data_size = ki->segs[s].vmsize;
            else if (strcmp(ki->segs[s].name, "__DATA_CONST") == 0) dconst_size = ki->segs[s].filesize;
        }

        printf("\n--- Placing %s ---\n", kexts[i].short_name);
        printf("  Need: TEXT=%llx TEXT_EXEC=%llx DATA=%llx DATA_CONST=%llx\n",
               (unsigned long long)text_size, (unsigned long long)texec_size,
               (unsigned long long)data_size, (unsigned long long)dconst_size);

        struct gap *g;
        printf("  __TEXT -> sequential header slot %llx\n",(unsigned long long)pl->text_vm);

        /* __TEXT_EXEC */
        g = find_best_gap(te_gaps, n_te, texec_size, used_te, nused_te);
        if(!g) {
            g=find_best_gap(kernel_code,nkcode,texec_size,used_kcode,nused_kcode);
            if(g) {used_kcode[nused_kcode++]=g->vmaddr;printf("  Using unsectioned kernel RX padding\n");}
        }
        if (!g) { fprintf(stderr, "No gap for %s __TEXT_EXEC\n", kexts[i].short_name); return 1; }
        pl->texec_vm = g->vmaddr;
        pl->texec_fo = g->fileoff;
        used_te[nused_te++] = g->vmaddr;
        printf("  __TEXT_EXEC -> gap at %llx (size %llx)\n",
               (unsigned long long)g->vmaddr, (unsigned long long)g->size);

        /* __DATA */
        g = find_best_gap(pd_gaps, n_pd, data_size, used_pd, nused_pd);
        if (!g) { fprintf(stderr, "No gap for %s __DATA\n", kexts[i].short_name); return 1; }
        pl->data_vm = g->vmaddr;
        pl->data_fo = g->fileoff;
        used_pd[nused_pd++] = g->vmaddr;
        printf("  __DATA -> gap at %llx\n", (unsigned long long)g->vmaddr);

        /* __DATA_CONST */
        g = NULL;
        g=find_best_gap(kernel_const,nkconst,dconst_size,used_kconst,nused_kconst);
        if(g) {used_kconst[nused_kconst++]=g->vmaddr;printf("  Using unsectioned kernel constant padding\n");}
        if (!g) { fprintf(stderr, "No gap for %s __DATA_CONST\n", kexts[i].short_name); return 1; }
        pl->dconst_vm = g->vmaddr;
        pl->dconst_fo = g->fileoff;
        used_pt[nused_pt++] = g->vmaddr;
        printf("  __DATA_CONST -> gap at %llx\n", (unsigned long long)g->vmaddr);

        /* Copy segment data from source */
        for (int s = 0; s < ki->nseg; s++) {
            struct seg_info *seg = &ki->segs[s];
            uint64_t dst_fo = 0;

            if (strcmp(seg->name, "__TEXT") == 0) {
                /* Copy the kext Mach-O header from source */
                int64_t src_fo = vm_to_fileoff(&src, seg->vmaddr);
                if (src_fo >= 0 && seg->filesize > 0)
                    memcpy(out + pl->text_fo, src.data + src_fo, seg->filesize);
            } else if (strcmp(seg->name, "__TEXT_EXEC") == 0) {
                dst_fo = pl->texec_fo;
                copy_and_fixup_segment(out, &src, seg, dst_fo, pl->texec_vm);
            } else if (strcmp(seg->name, "__DATA") == 0) {
                dst_fo = pl->data_fo;
                /* DATA filesize might be less than vmsize (bss/common) */
                int64_t src_fo = vm_to_fileoff(&src, seg->vmaddr);
                if (src_fo >= 0 && seg->filesize > 0)
                    memcpy(out + dst_fo, src.data + src_fo, seg->filesize);
            } else if (strcmp(seg->name, "__DATA_CONST") == 0) {
                dst_fo = pl->dconst_fo;
                copy_and_fixup_segment(out, &src, seg, dst_fo, pl->dconst_vm);
            }
        }

        fixup_instructions(out, &src, &dst, ki, pl);

        /* Rewrite inner Mach-O header */
        rewrite_kext_header(out, pl->text_fo, ki, pl, true);

        /* Fix up pointers */
        uint32_t *new_offsets;
        int new_count;
        int fixed = fixup_pointers(out, &src, &dst, ki, pl,
                                   &src_kt, &dst_kt, arm_delta,
                                   &new_offsets, &new_count);
        printf("  Fixed %d KASLR-tracked pointers\n", fixed);

        /* Accumulate new KASLR offsets */
        for (int j = 0; j < new_count; j++)
            all_new_kaslr[total_new_kaslr++] = new_offsets[j];
        free(new_offsets);

        /* Fix kmod_info */
        int64_t kmod_fo = -1;
        /* kmod_info is in __DATA, compute its file offset in the output */
        for (int s = 0; s < ki->nseg; s++) {
            if (strcmp(ki->segs[s].name, "__DATA") == 0) {
                if(ki->kmod_info_addr<ki->segs[s].vmaddr ||
                   ki->kmod_info_addr-ki->segs[s].vmaddr>ki->segs[s].filesize ||
                   ki->segs[s].filesize-(ki->kmod_info_addr-ki->segs[s].vmaddr)<196) {
                    fprintf(stderr,"Invalid donor kmod_info\n");return 1;
                }
                uint64_t kmod_inner_off = ki->kmod_info_addr - ki->segs[s].vmaddr;
                kmod_fo = (int64_t)(pl->data_fo + kmod_inner_off);
                break;
            }
        }
        if (kmod_fo >= 0) {
            fixup_kmod_info(out, kmod_fo, pl,
                            ki->segs[0].vmaddr, 0, text_size);

            uint64_t start_ptr, stop_ptr;
            memcpy(&start_ptr, out + kmod_fo + KMOD_START_OFF, 8);
            memcpy(&stop_ptr, out + kmod_fo + KMOD_STOP_OFF, 8);
            printf("  kmod_info at fo=%llx, addr=%llx start=%llx stop=%llx\n",
                   (unsigned long long)kmod_fo,
                   (unsigned long long)pl->text_vm,
                   (unsigned long long)start_ptr,
                   (unsigned long long)stop_ptr);
        }
    }

    /* ---- Update KASLR offset table ---- */
    printf("\nUpdating KASLR table: adding %d new offsets to %u existing\n",
           total_new_kaslr, dst_kt.count);

    /* Build new offset array: existing + new, sorted */
    uint32_t new_total = dst_kt.count + total_new_kaslr;
    uint32_t *merged = malloc(new_total * 4);
    memcpy(merged, dst_kt.offsets, dst_kt.count * 4);
    memcpy(merged + dst_kt.count, all_new_kaslr, total_new_kaslr * 4);

    /* Preserve the original unsorted table; append only distinct locations. */
    new_total = dst_kt.count;
    for (int i = 0; i < total_new_kaslr; i++) {
        bool exists = false;
        for (uint32_t j = 0; j < new_total; j++)
            if (merged[j] == all_new_kaslr[i]) { exists = true; break; }
        if (!exists) merged[new_total++] = all_new_kaslr[i];
    }

    /* Encode new table */
    size_t new_table_size = 4 + new_total * 4;
    uint8_t *new_table = malloc(new_table_size);
    memcpy(new_table, &new_total, 4);
    memcpy(new_table + 4, merged, new_total * 4);

    size_t new_b64_len;
    char *new_b64 = b64_encode(new_table, new_table_size, &new_b64_len);

    /* Find and replace the base64 data in the output plist */
    uint64_t dst_pi_off, dst_pi_max;
    find_prelink_info(&dst, &dst_pi_off, &dst_pi_max);

    char *kaslr_key = strstr((char *)(out + dst_pi_off), "_PrelinkLinkKASLROffsets");
    if (!kaslr_key) { fprintf(stderr, "Cannot find KASLR key in dst plist\n"); return 1; }
    char *data_tag = strstr(kaslr_key, "<data");
    char *data_content = strchr(data_tag, '>') + 1;
    char *data_end = strstr(data_content, "</data>");

    size_t old_b64_len = data_end - data_content;

    /* For safety, ensure it fits. KASLR addition is small (few hundred bytes of b64) */
    if (new_b64_len <= old_b64_len) {
        memcpy(data_content, new_b64, new_b64_len);
        /* Pad remainder with spaces (valid in XML) */
        memset(data_content + new_b64_len, ' ', old_b64_len - new_b64_len);
    } else {
        /* Need to expand - shift everything after </data> forward */
        size_t expand = new_b64_len - old_b64_len;
        size_t pi_end_off = dst_pi_off + dst_pi_max;
        size_t data_end_abs = (data_end - (char *)out);
        size_t tail_len = pi_end_off - data_end_abs;

        /* Check we have space (null padding at end of __PRELINK_INFO) */
        size_t null_at_end = 0;
        for (size_t i = pi_end_off - 1; i > dst_pi_off; i--) {
            if (out[i] != 0) break;
            null_at_end++;
        }
        if (expand > null_at_end) {
            fprintf(stderr, "Not enough space in __PRELINK_INFO for expanded KASLR table\n");
            return 1;
        }

        memmove(data_end + expand, data_end, tail_len - expand);
        memcpy(data_content, new_b64, new_b64_len);
    }

    free(new_b64);
    free(new_table);
    free(merged);

    /* ---- Inject kext entries into PRELINK_INFO plist ---- */
    printf("\nInjecting PRELINK_INFO entries...\n");

    /* Locate the top-level kext array, allowing nested personality arrays. */
    char *pi_ptr = (char *)(out + dst_pi_off);
    size_t pi_len = 0;
    /* Find actual content length (before null padding) */
    for (size_t i = dst_pi_max - 1; i > 0; i--) {
        if (pi_ptr[i] != 0) { pi_len = i + 1; break; }
    }

    const char *array_key = strstr(pi_ptr,"<key>_PrelinkInfoDictionary</key>");
    const char *array_start = array_key ? strstr(array_key,"<array") : NULL;
    char *last_array_end = array_start ? (char *)xml_end(array_start)-8 : NULL;

    if (!last_array_end) {
        fprintf(stderr, "Cannot find </array> in dst plist\n");
        return 1;
    }

    size_t total_insert = 0;
    char *insert_text = calloc(1,1);
    for (int i = 0; i < kext_count; i++) {
        struct kext_info *ki = &kexts[i].ki;
        struct placement *pl = &placements[i];
        char *orig = extract_kext_dict(src_plist,kexts[i].bundle_id);
        if (!orig) { fprintf(stderr,"Cannot extract donor metadata\n"); return 1; }
        char *entry = expand_xml(orig,src_plist,0); free(orig);
        entry = set_xml_address(entry,"_PrelinkExecutableLoadAddr",pl->text_vm);
        entry = set_xml_address(entry,"_PrelinkExecutableSourceAddr",pl->text_vm);
        uint64_t kmod = 0;
        for (int j=0;j<ki->nseg;j++)
            if (!strcmp(ki->segs[j].name,"__DATA"))
                kmod=pl->data_vm+ki->kmod_info_addr-ki->segs[j].vmaddr;
        entry = set_xml_address(entry,"_PrelinkKmodInfo",kmod);
        size_t n = strlen(entry);
        insert_text = realloc(insert_text,total_insert+n+1);
        memcpy(insert_text+total_insert,entry,n+1);
        total_insert+=n; free(entry);
    }

    /* Check space */
    size_t space_after = dst_pi_max - pi_len;
    if (total_insert >= space_after) {
        fprintf(stderr, "Not enough space in __PRELINK_INFO for kext entries (%zu needed, %zu available)\n",
                total_insert, space_after);
        return 1;
    }

    /* Insert before </array> */
    size_t tail_from_array = pi_len - (last_array_end - pi_ptr);
    memmove(last_array_end + total_insert, last_array_end, tail_from_array);
    memcpy(last_array_end, insert_text, total_insert);

    free(insert_text);
    free(all_new_kaslr);
    free(src_kt.offsets);
    free(dst_kt.offsets);

    printf("Injected %zu bytes of plist entries\n", total_insert);

    if(walk_headers(&output_view)!=new_header_end) {
        fprintf(stderr,"Output failed sequential header verification\n");return 1;
    }
    /* Write output */
    int outfd = open(argv[3], O_WRONLY|O_CREAT|O_EXCL, 0644);
    if (outfd < 0) { perror(argv[3]); return 1; }
    f = fdopen(outfd, "wb");
    if (!f) { perror(argv[3]); return 1; }
    if (fwrite(out, 1, dst.len, f) != dst.len) { perror("write output"); fclose(f); unlink(argv[3]); return 1; }
    if (fclose(f)) { perror("close output"); unlink(argv[3]); return 1; }

    printf("\nOutput written to %s (%zu bytes)\n", argv[3], dst.len);
    printf("\nPlacement summary:\n");
    for (int i = 0; i < kext_count; i++) {
        struct placement *pl = &placements[i];
        printf("  %s:\n", kexts[i].short_name);
        printf("    __TEXT       = %llx (fo %llx)\n", (unsigned long long)pl->text_vm, (unsigned long long)pl->text_fo);
        printf("    __TEXT_EXEC  = %llx (fo %llx)\n", (unsigned long long)pl->texec_vm, (unsigned long long)pl->texec_fo);
        printf("    __DATA       = %llx (fo %llx)\n", (unsigned long long)pl->data_vm, (unsigned long long)pl->data_fo);
        printf("    __DATA_CONST = %llx (fo %llx)\n", (unsigned long long)pl->dconst_vm, (unsigned long long)pl->dconst_fo);
    }

    free(out);
    free(dst.data);
    free(src.data);
    return 0;
}
