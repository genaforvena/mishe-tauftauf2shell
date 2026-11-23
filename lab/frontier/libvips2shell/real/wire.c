/* W14 bounded loopback-wire observation for CVE-2026-69242.
 *
 * One-shot HTTP/1.0 server on an ephemeral 127.0.0.1 port. The POST body is
 * handed verbatim to vips_image_new_from_buffer() with header-only sequential
 * access, the same header-only path the W2 file probe used with
 * vips_image_new_from_file(). No pixel decode, no paint, no command, no marker.
 * The client is a separate process; the request crosses a real loopback socket.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vips/vips.h>

#define MAXREQ (1 << 20)

int
main(int argc, char **argv)
{
	int fd, cfd, one = 1;
	struct sockaddr_in addr;
	socklen_t alen = sizeof(addr);
	unsigned char *buf;
	size_t used = 0, hlen = 0, clen = 0;
	int hdr_done = 0;
	char *term;
	VipsImage *im;
	int sane;

	(void) argc; (void) argv;
	buf = malloc(MAXREQ);
	if (!buf)
		return 2;

	if (vips_init("wire"))
		return 2;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return 2;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
		listen(fd, 1) < 0)
		return 2;
	if (getsockname(fd, (struct sockaddr *) &addr, &alen) < 0)
		return 2;
	printf("WIRE_BIND 127.0.0.1 port=%d\n", ntohs(addr.sin_port));
	fflush(stdout);

	cfd = accept(fd, NULL, NULL);
	if (cfd < 0)
		return 2;

	for (;;) {
		ssize_t n = read(cfd, buf + used, MAXREQ - used);
		if (n > 0)
			used += (size_t) n;
		if (!hdr_done) {
			term = memmem(buf, used, "\r\n\r\n", 4);
			if (term) {
				hdr_done = 1;
				hlen = (size_t) (term - (char *) buf) + 4;
				{
					char *c = memmem(buf, hlen, "Content-Length:", 15);
					if (c)
						clen = (size_t) strtoul(c + 15, NULL, 10);
				}
			}
		}
		if (hdr_done && used >= hlen + clen)
			break;
		if (n <= 0 || used == MAXREQ)
			break;
	}

	printf("WIRE_REQ body=%zu content_length=%zu\n", used - hlen, clen);
	fflush(stdout);

	im = vips_image_new_from_buffer(buf + hlen, used - hlen, "",
		"access", VIPS_ACCESS_SEQUENTIAL, NULL);
	if (!im) {
		printf("WIRE_HDR=ERR msg=%s\n", vips_error_buffer());
		vips_error_clear();
	} else {
		printf("WIRE_HDR Xsize=%d Ysize=%d Bands=%d BandFmt=%d "
			"sizeof_line=%" G_GUINT64_FORMAT "\n",
			im->Xsize, im->Ysize, im->Bands, im->BandFmt,
			VIPS_IMAGE_SIZEOF_LINE(im));
		sane = vips_object_sanity(VIPS_OBJECT(im));
		printf("WIRE_SANITY=%d msg=%s\n", sane, vips_error_buffer());
		vips_error_clear();
		g_object_unref(im);
	}

	close(cfd);
	close(fd);
	vips_shutdown();
	free(buf);
	return 0;
}
