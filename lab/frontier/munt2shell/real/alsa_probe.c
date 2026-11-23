// Bounded consumer-behavior probe: can the host's ALSA sequencer deliver a
// single oversized (40001-byte) SND_SEQ_EVENT_SYSEX to a local listener?
// Loopback only: client sends to its own port through the kernel sequencer.
#include <alsa/asoundlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	unsigned int len = argc > 1 ? (unsigned int)strtoul(argv[1], NULL, 10) : 40001u;
	snd_seq_t *seq = NULL;
	if (snd_seq_open(&seq, "default", SND_SEQ_OPEN_DUPLEX, 0) < 0) {
		printf("open=FAIL\n");
		return 2;
	}
	snd_seq_set_client_name(seq, "munt2shell-probe");
	snd_seq_set_client_pool_output(seq, 131072);
	snd_seq_set_client_pool_input(seq, 131072);
	int port = snd_seq_create_simple_port(seq, "loopback",
		SND_SEQ_PORT_CAP_READ | SND_SEQ_PORT_CAP_WRITE |
		SND_SEQ_PORT_CAP_SUBS_READ | SND_SEQ_PORT_CAP_SUBS_WRITE,
		SND_SEQ_PORT_TYPE_MIDI_GENERIC);
	if (port < 0) { printf("port=FAIL\n"); return 2; }
	snd_seq_addr_t self = { (unsigned char)snd_seq_client_id(seq), (unsigned char)port };
	snd_seq_port_subscribe_t *sub = NULL;
	snd_seq_port_subscribe_alloca(&sub);
	snd_seq_port_subscribe_set_sender(sub, &self);
	snd_seq_port_subscribe_set_dest(sub, &self);
	int rc = snd_seq_subscribe_port(seq, sub);
	printf("subscribe rc=%d client=%d port=%d\n", rc, self.client, self.port);

	unsigned char *buf = malloc(len);
	if (!buf) return 2;
	buf[0] = 0xF0;
	memset(buf + 1, 0x5a, len - 1);

	snd_seq_event_t ev;
	snd_seq_ev_clear(&ev);
	snd_seq_ev_set_source(&ev, port);
	snd_seq_ev_set_subs(&ev);
	snd_seq_ev_set_direct(&ev);
	snd_seq_ev_set_variable(&ev, len, buf);
	ev.type = SND_SEQ_EVENT_SYSEX;
	rc = snd_seq_event_output_direct(seq, &ev);
	printf("send len=%u rc=%d\n", len, rc);
	snd_seq_drain_output(seq);

	snd_seq_event_t *in = NULL;
	rc = snd_seq_event_input(seq, &in);
	if (rc < 0) {
		printf("receive rc=%d\n", rc);
	} else {
		printf("receive rc=%d type=%d ext.len=%u first=%02x last=%02x\n",
			rc, in->type, in->data.ext.len,
			in->data.ext.len ? ((unsigned char *)in->data.ext.ptr)[0] : 0,
			in->data.ext.len ? ((unsigned char *)in->data.ext.ptr)[in->data.ext.len - 1] : 0);
		snd_seq_free_event(in);
	}
	snd_seq_close(seq);
	free(buf);
	return 0;
}
