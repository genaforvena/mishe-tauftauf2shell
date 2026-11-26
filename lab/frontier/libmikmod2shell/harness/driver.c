/* Local driver: calls the pinned, unmodified libmikmod loader with a DSM file.
   No network, no audio device: only the nosound driver is registered. */
#include <stdio.h>
#include <stdlib.h>
#include "mikmod.h"

int main(int argc, char **argv)
{
	MODULE *m;
	int err;

	/* No audio device: register only the pinned nosound driver and give it
	   explicit, ordinary mixer settings (defaults are all zero). */
	md_device = 1;
	md_mixfreq = 44100;
	md_mode = DMODE_SOFT_MUSIC | DMODE_16BITS | DMODE_STEREO;
	if (argc != 2) {
		fprintf(stderr, "usage: %s FILE.dsm\n", argv[0]);
		return 2;
	}
	MikMod_RegisterDriver(&drv_nos);
	MikMod_RegisterAllLoaders();
	if (MikMod_Init("") != 0) {
		fprintf(stderr, "MikMod_Init failed: %s\n", MikMod_strerror(MikMod_errno));
		return 2;
	}
	m = Player_Load(argv[1], 64, 0);
	err = MikMod_errno;
	printf("load=%p errno=%d (%s)\n", (void *)m, err, MikMod_strerror(err));
	if (m) {
		printf("channels=%u patterns=%u tracks=%u samples=%u\n",
		       (unsigned)m->numchn, (unsigned)m->numpat,
		       (unsigned)m->numtrk, (unsigned)m->numsmp);
		Player_Free(m);
	}
	MikMod_Exit();
	return m ? 0 : 1;
}
