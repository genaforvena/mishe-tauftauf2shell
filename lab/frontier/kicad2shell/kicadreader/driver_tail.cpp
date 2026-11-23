
/* #line reset: lab driver below.
 *
 * Delivery boundary is KiCad's OWN compound-file reader: the verbatim
 * 10.0.6 thirdparty/compoundfilereader/compoundfilereader.h is included by
 * stubs.hpp, and the lab ALTIUM_COMPOUND_FILE wrapper uses its EnumFiles,
 * IsStream and ReadFile on the REAL CFB::COMPOUND_FILE_ENTRY.  The verbatim
 * upstream ALTIUM_BINARY_PARSER constructors and ReadProperties() and the
 * pinned ParseLibHeader slice then run unchanged over those bytes.
 *
 * Still absent: wxWidgets, KiCad's ALTIUM_COMPOUND_FILE wrapper itself,
 * a full eeschema build, and any downstream consumer of aFontSizes.
 */
int main( int argc, char** argv )
{
    setvbuf( stdout, nullptr, _IONBF, 0 );
    const char* path = argc > 1 ? argv[1] : "../realcfb/fixtures/FileHeader-attackz.SchLib";

    ALTIUM_COMPOUND_FILE lib( path );
    const CFB::COMPOUND_FILE_ENTRY* entry = lib.FindStream( { "FileHeader" } );
    if( entry == nullptr )
    {
        std::fprintf( stderr, "kicad-cfb: FileHeader not found\n" );
        return 2;
    }

    const size_t streamSize = static_cast<size_t>( entry->size );
    std::unique_ptr<char[]> bytes( new char[streamSize] );
    lib.GetCompoundFileReader().ReadFile( entry, 0, bytes.get(), streamSize );
    std::printf( "kicad-cfb: file=%s stream=%zu\n", path, streamSize );

    /* Diagnostic first read with the verbatim parser on the reader's bytes. */
    ALTIUM_BINARY_PARSER reader( bytes, streamSize );
    std::map<wxString, wxString> props = reader.ReadProperties();
    std::printf( "real-reader: bytes=%zu props=%zu parse_error=%d\n",
                 streamSize, props.size(), (int) reader.HasParsingError() );
    for( const auto& kv : props )
        if( kv.first.s.rfind( "SIZE", 0 ) == 0 )
            std::printf( "real-key: %s=%s\n", kv.first.s.c_str(), kv.second.s.c_str() );

    volatile int* guard = new int[8];
    for( int i = 0; i < 8; ++i ) guard[i] = 0x11111111;

    std::vector<int> fontSizes;
    SCH_IO_ALTIUM sch;
    try { sch.ParseLibHeader( lib, fontSizes ); }
    catch( ... ) { delete[] guard; std::printf( "THREW\n" ); return 3; }

    std::printf( "rc=0 size=%zu first=%d GUARD7=%08x\n", fontSizes.size(),
                 fontSizes.empty() ? -1 : fontSizes[0], (unsigned) guard[7] );
    delete[] guard;
    return 0;
}
