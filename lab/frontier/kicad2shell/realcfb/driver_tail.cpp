
/* #line reset: lab driver below.
 *
 * REAL MS-CFB (OLE2) reader.  Unlike the realparser lane's pre-built byte
 * shim, this walks a genuine compound-file container: header -> DIFAT ->
 * FAT -> directory (UTF-16 name match) -> miniFAT -> mini stream.  The bytes
 * delivered to the VERBATIM upstream ReadProperties() and pinned
 * ParseLibHeader() are extracted from that container, not hand-assembled.
 *
 * Scope of "real": a v3 (512-byte sector) file with the FAT in the 109-entry
 * DIFAT array and no DIFAT chain is exercised; the fixture satisfies that
 * layout and olefile read-back confirms it.  wxWidgets and KiCad's own CFB
 * class are still not linked; this is a lab implementation of the CFB walk.
 */
#include <fstream>
#include <iterator>
#include <string>

static const uint32_t CFB_FREESECT = 0xFFFFFFFFu;
static const uint32_t CFB_ENDOFCHAIN = 0xFFFFFFFEu;
static const uint32_t CFB_FATSECT = 0xFFFFFFFDu;

static uint32_t rd32( const unsigned char* p )
{
    return (uint32_t) p[0] | ( (uint32_t) p[1] << 8 ) | ( (uint32_t) p[2] << 16 )
           | ( (uint32_t) p[3] << 24 );
}

struct RealCFB
{
    std::vector<unsigned char> b;
    uint32_t sectorSize = 512, miniSectorSize = 64, cutoff = 4096;
    uint32_t firstDir = 0, firstMiniFat = CFB_ENDOFCHAIN, numMiniFat = 0;
    uint32_t firstDifat = CFB_ENDOFCHAIN, numDifat = 0;
    std::vector<uint32_t> fat;
    std::vector<unsigned char> miniStream;
    std::string err;

    const unsigned char* sector( uint32_t id ) const
    {
        size_t off = 512u + (size_t) id * sectorSize;
        if( id >= CFB_FREESECT || off + sectorSize > b.size() ) return nullptr;
        return b.data() + off;
    }

    std::vector<uint32_t> chain( uint32_t start ) const
    {
        std::vector<uint32_t> out;
        uint32_t s = start;
        while( s < CFB_ENDOFCHAIN && out.size() < fat.size() + 1 )
        {
            out.push_back( s );
            s = s < fat.size() ? fat[s] : CFB_FREESECT;
        }
        return out;
    }

    bool load( const char* path )
    {
        std::ifstream f( path, std::ios::binary );
        if( !f ) { err = "open failed"; return false; }
        b.assign( std::istreambuf_iterator<char>( f ), std::istreambuf_iterator<char>() );
        static const unsigned char sig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
        if( b.size() < 512 || std::memcmp( b.data(), sig, 8 ) ) { err = "bad signature"; return false; }
        auto u16 = [&]( size_t o ) { return (uint32_t) b[o] | ( (uint32_t) b[o + 1] << 8 ); };
        auto u32 = [&]( size_t o ) { return rd32( b.data() + o ); };
        sectorSize = 1u << u16( 30 );
        miniSectorSize = 1u << u16( 32 );
        uint32_t numFat = u32( 44 );
        firstDir = u32( 48 );
        cutoff = u32( 56 );
        firstMiniFat = u32( 60 );
        numMiniFat = u32( 64 );
        firstDifat = u32( 68 );
        numDifat = u32( 72 );
        if( sectorSize < 128 || sectorSize > 4096 ) { err = "bad sector shift"; return false; }

        std::vector<uint32_t> fatSecs;
        for( int i = 0; i < 109; ++i )
        {
            uint32_t s = u32( 76 + 4 * i );
            if( s < CFB_ENDOFCHAIN ) fatSecs.push_back( s );
        }
        uint32_t d = firstDifat;
        for( uint32_t i = 0; i < numDifat && d < CFB_ENDOFCHAIN; ++i )
        {
            const unsigned char* p = sector( d );
            if( !p ) { err = "bad DIFAT sector"; return false; }
            for( uint32_t j = 0; j + 1 < sectorSize / 4; ++j )
            {
                uint32_t s = rd32( p + 4 * j );
                if( s < CFB_ENDOFCHAIN ) fatSecs.push_back( s );
            }
            d = rd32( p + sectorSize - 4 );
        }
        if( fatSecs.size() < numFat ) { err = "short DIFAT"; return false; }
        fatSecs.resize( numFat );
        for( uint32_t s : fatSecs )
        {
            const unsigned char* p = sector( s );
            if( !p ) { err = "bad FAT sector"; return false; }
            for( uint32_t j = 0; j < sectorSize / 4; ++j ) fat.push_back( rd32( p + 4 * j ) );
        }
        return true;
    }

    // Directory entry fields: name at 0, name length at 64, type at 66,
    // start at 116, 8-byte size at 120.
    bool findStream( const char* name, uint32_t& start, uint64_t& size, int& type ) const
    {
        std::wstring wname( name, name + std::strlen( name ) );
        for( uint32_t s : chain( firstDir ) )
        {
            const unsigned char* p = sector( s );
            if( !p ) return false;
            for( uint32_t e = 0; e < sectorSize / 128; ++e )
            {
                const unsigned char* de = p + e * 128;
                uint32_t nameLen = (uint32_t) de[64] | ( (uint32_t) de[65] << 8 );
                int otype = de[66];
                if( otype == 0 || nameLen < 2 || nameLen > 64 ) continue;
                bool match = nameLen == wname.size() * 2 + 2;
                if( match )
                {
                    for( size_t k = 0; k < wname.size() && match; ++k )
                    {
                        uint32_t c = (uint32_t) wname[k];
                        if( de[2 * k] != (unsigned char) ( c & 0xff )
                            || de[2 * k + 1] != (unsigned char) ( c >> 8 ) ) match = false;
                    }
                }
                if( match )
                {
                    start = rd32( de + 116 );
                    size = (uint64_t) rd32( de + 120 ) | ( (uint64_t) rd32( de + 124 ) << 32 );
                    type = otype;
                    return true;
                }
            }
        }
        return false;
    }

    bool loadMiniStream()
    {
        // Root entry's start sector and size are the mini-stream container.
        for( uint32_t s : chain( firstDir ) )
        {
            const unsigned char* p = sector( s );
            if( !p ) return false;
            if( p[66] != 5 ) continue;
            uint32_t start = rd32( p + 116 );
            uint64_t size = (uint64_t) rd32( p + 120 ) | ( (uint64_t) rd32( p + 124 ) << 32 );
            for( uint32_t sec : chain( start ) )
            {
                const unsigned char* q = sector( sec );
                if( !q ) return false;
                size_t take = std::min<size_t>( sectorSize, (size_t) std::min<uint64_t>( size, size ) );
                miniStream.insert( miniStream.end(), q, q + take );
                if( size >= sectorSize ) size -= sectorSize; else size = 0;
                if( size == 0 ) break;
            }
            return true;
        }
        return false;
    }

    bool readStream( const char* name, std::vector<unsigned char>& out )
    {
        uint32_t start = 0; uint64_t size = 0; int type = 0;
        if( !findStream( name, start, size, type ) ) { err = "stream not found"; return false; }
        if( size < cutoff )
        {
            if( miniStream.empty() && !loadMiniStream() ) { err = "no mini stream"; return false; }
            std::vector<uint32_t> mfat;
            for( uint32_t s : chain( firstMiniFat ) )
            {
                const unsigned char* p = sector( s );
                if( !p ) { err = "bad miniFAT"; return false; }
                for( uint32_t j = 0; j < sectorSize / 4; ++j ) mfat.push_back( rd32( p + 4 * j ) );
            }
            uint32_t m = start;
            while( m < CFB_ENDOFCHAIN && out.size() < size )
            {
                size_t off = (size_t) m * miniSectorSize;
                if( off + miniSectorSize > miniStream.size() ) { err = "mini sector OOB"; return false; }
                size_t take = std::min<size_t>( miniSectorSize, (size_t) size - out.size() );
                out.insert( out.end(), miniStream.begin() + off, miniStream.begin() + off + take );
                m = m < mfat.size() ? mfat[m] : CFB_FREESECT;
            }
        }
        else
        {
            for( uint32_t s : chain( start ) )
            {
                const unsigned char* p = sector( s );
                if( !p ) { err = "bad stream sector"; return false; }
                size_t take = std::min<size_t>( sectorSize, (size_t) size - out.size() );
                out.insert( out.end(), p, p + take );
                if( out.size() >= size ) break;
            }
        }
        if( out.size() != size ) { err = "short stream"; return false; }
        return true;
    }
};

int main( int argc, char** argv )
{
    setvbuf( stdout, nullptr, _IONBF, 0 );
    const char* path = argc > 1 ? argv[1] : "fixtures/FileHeader-attackz.SchLib";

    RealCFB cfb;
    if( !cfb.load( path ) )
    {
        std::fprintf( stderr, "cfb-load-failed: %s\n", cfb.err.c_str() );
        return 2;
    }
    std::vector<unsigned char> stream;
    if( !cfb.readStream( "FileHeader", stream ) )
    {
        std::fprintf( stderr, "cfb-stream-failed: %s\n", cfb.err.c_str() );
        return 2;
    }
    g_streamBytes.assign( stream.begin(), stream.end() );

    std::printf( "cfb: file=%s sectors=%zu fat=%zu mini_stream=%zu stream=%zu\n",
                 path, cfb.b.size() / 512 - 1, cfb.fat.size(), cfb.miniStream.size(), stream.size() );

    /* Diagnostic first read with the real parser on the extracted bytes. */
    std::unique_ptr<char[]> bytes( new char[stream.size()] );
    std::memcpy( bytes.get(), stream.data(), stream.size() );
    ALTIUM_BINARY_PARSER reader( bytes, stream.size() );
    std::map<wxString, wxString> props = reader.ReadProperties();
    std::printf( "real-reader: bytes=%zu props=%zu parse_error=%d\n",
                 stream.size(), props.size(), (int) reader.HasParsingError() );
    for( const auto& kv : props )
        if( kv.first.s.rfind( "SIZE", 0 ) == 0 )
            std::printf( "real-key: %s=%s\n", kv.first.s.c_str(), kv.second.s.c_str() );

    volatile int* guard = new int[8];
    for( int i = 0; i < 8; ++i ) guard[i] = 0x11111111;

    std::vector<int> fontSizes;
    ALTIUM_COMPOUND_FILE lib;
    SCH_IO_ALTIUM sch;
    try { sch.ParseLibHeader( lib, fontSizes ); }
    catch( ... ) { delete[] guard; std::printf( "THREW\n" ); return 3; }

    std::printf( "rc=0 size=%zu first=%d GUARD7=%08x\n", fontSizes.size(),
                 fontSizes.empty() ? -1 : fontSizes[0], (unsigned) guard[7] );
    delete[] guard;
    return 0;
}
