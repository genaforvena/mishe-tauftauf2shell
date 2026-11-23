/* Lab stubs for the wxWidgets/KiCad support types used by the verbatim
 * upstream ALTIUM_BINARY_PARSER class and ReadProperties() body.  Only the
 * methods reached by this harness are modelled; no upstream code is altered.
 */
#ifndef KICAD2SHELL_REALPARSER_STUBS_HPP
#include <algorithm>
#define KICAD2SHELL_REALPARSER_STUBS_HPP

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

struct wxCSConv { int id; };
static wxCSConv wxConvISO8859_1{ 1 };
static wxCSConv wxConvUTF8{ 2 };
struct wxMBConvUTF16LE {};
struct wxScopedCharBuffer
{
    char*  p = nullptr;
    size_t n = 0;
    static wxScopedCharBuffer CreateOwned( char* a, size_t b ) { return { a, b }; }
};

#define wxT(x) x
#define wxS(x) x
#define _(x) x
#define wxLogTrace(...) ((void) 0)
#define THROW_IO_ERROR(x) do { (void) sizeof(x); throw std::runtime_error( "lab io error" ); } while(0)

struct wxString
{
    std::string s;
    wxString() : s() {}
    wxString( const char* p ) : s( p ? p : "" ) {}
    wxString( const std::string& x ) : s( x ) {}
    wxString( const char* p, const wxCSConv& ) : s( p ? p : "" ) {}
    wxString( const char* p, const wxMBConvUTF16LE&, size_t n ) : s( p ? std::string( p, n ) : std::string() ) {}
    wxString( const wxScopedCharBuffer& b, const wxCSConv& ) : s( b.p ? std::string( b.p, b.n ) : std::string() ) {}
    bool empty() const { return s.empty(); }
    bool operator<( const wxString& o ) const { return s < o.s; }
    bool operator==( const wxString& o ) const { return s == o.s; }
    bool operator==( const char* o ) const { return s == ( o ? o : "" ); }
    bool operator!=( const wxString& o ) const { return s != o.s; }
    bool operator!=( const char* o ) const { return s != ( o ? o : "" ); }
    wxString Upper() const
    {
        wxString r;
        for( char c : s ) r.s += ( c >= 'a' && c <= 'z' ) ? (char) ( c - 32 ) : c;
        return r;
    }
    wxString MakeUpper() const { return Upper(); }
    wxString Trim( bool fromRight = true ) const
    {
        size_t a = 0, b = s.size();
        if( !fromRight )
        {
            while( a < b && ( s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n' ) ) ++a;
        }
        else
        {
            while( b > a && ( s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r' || s[b-1] == '\n' ) ) --b;
        }
        return wxString( s.substr( a, b - a ) );
    }
    bool StartsWith( const char* prefix, wxString* rest = nullptr ) const
    {
        const size_t n = std::strlen( prefix );
        if( s.compare( 0, n, prefix ) != 0 ) return false;
        if( rest ) *rest = wxString( s.substr( n ) );
        return true;
    }
    bool StartsWith( const wxString& prefix ) const { return StartsWith( prefix.s.c_str() ); }
    wxString& Replace( const wxString& a, const wxString& b )
    {
        if( a.s.empty() ) return *this;
        size_t pos = 0;
        while( ( pos = s.find( a.s, pos ) ) != std::string::npos )
        {
            s.replace( pos, a.s.size(), b.s );
            pos += b.s.size();
        }
        return *this;
    }
    int CmpNoCase( const char* other ) const
    {
        std::string a = s, b = other ? other : "";
        for( char& c : a ) if( c >= 'A' && c <= 'Z' ) c = (char) ( c + 32 );
        for( char& c : b ) if( c >= 'A' && c <= 'Z' ) c = (char) ( c + 32 );
        return a.compare( b );
    }
};

static int wxAtoi( const wxString& x ) { return std::atoi( x.s.c_str() ); }

static wxString AltiumPropertyToKiCadString( const wxString& a ) { return a; }

namespace ALTIUM_PROPS_UTILS
{
    static int32_t ConvertToKicadUnit( int32_t v ) { return v; }
    static wxString ReadString( std::map<wxString, wxString>& p, const char* key, const char* def )
    {
        auto it = p.find( wxString( key ) );
        return it == p.end() ? wxString( def ) : it->second;
    }
}

struct VECTOR2I { int x; int y; };

static std::vector<char> g_streamBytes;

namespace CFB { struct COMPOUND_FILE_ENTRY { int64_t size = 0; }; }

struct ALTIUM_COMPOUND_FILE
{
    struct CompoundReaderStub
    {
        void ReadFile( const CFB::COMPOUND_FILE_ENTRY*, size_t offset, char* dest, size_t len ) const
        {
            if( offset >= g_streamBytes.size() ) return;
            size_t n = std::min( len, g_streamBytes.size() - offset );
            std::memcpy( dest, g_streamBytes.data() + offset, n );
        }
    };
    CompoundReaderStub GetCompoundFileReader() const { return CompoundReaderStub(); }
    CFB::COMPOUND_FILE_ENTRY* FindStream( std::initializer_list<const char*> ) const
    {
        static CFB::COMPOUND_FILE_ENTRY entry;
        entry.size = (int64_t) g_streamBytes.size();
        return &entry;
    }
};

struct SchIUScaleStub { int MilsToIU( double v ) const { return (int) v; } };
static SchIUScaleStub schIUScale;

static std::map<wxString, wxString> g_properties;

struct SCH_IO_ALTIUM
{
    void ParseLibHeader( const ALTIUM_COMPOUND_FILE&, std::vector<int>& );
};

#endif
