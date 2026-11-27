// UxPlay GHSA-479c-ww7g-wgp8 — pinned /pair-setup-pin memcpy sink.
// The declaration and memcpy call are verbatim from pinned v1.73.6
// lib/raop_handlers.h:354-366; FIXED is the verbatim v1.73.7:370 hunk.
// The plist/wire parser, SRP validator and logger are stubbed: the harness
// feeds the same pointer+length pair the pinned handler hands to memcpy.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
// The harness pads the stub source to 128 bytes so the fixed arm's
// sizeof(proof) copy cannot over-read: only the destination overflow is
// measured. client_proof_len still carries the attacker-chosen length.
static void plist_get_data_val_stub(char** out, uint64_t* out_len,
                                    const std::string& data)
{
	*out = static_cast<char*>(calloc(128, 1));
	memcpy(*out, data.data(), data.size());
	*out_len = data.size();
}

static void handler_pin(const std::string& proof_data)
{
	// Verbatim pinned locals (v1.73.6:354-358).
	char *client_proof = NULL;
	unsigned char proof[64] = { '\0' };
	memset(proof, 0, sizeof(proof));
	uint64_t client_proof_len = 0;

	plist_get_data_val_stub(&client_proof, &client_proof_len, proof_data);

#ifdef FIXED
	// Verbatim fixed hunk (v1.73.7:370).
	memcpy(proof, client_proof, sizeof(proof));
#else
	// Verbatim vulnerable statement (v1.73.6:366).
	memcpy(proof, client_proof, (int) client_proof_len);
#endif

	// Consume the destination so the compiler keeps the stack object.
	volatile unsigned char sink = proof[0] ^ proof[63];
	(void) sink;
	free(client_proof);
}

int main(int argc, char** argv)
{
	const char* mode = argc > 1 ? argv[1] : "attack";
	size_t n = 20;
	unsigned char fill = 0x43;
	if (strcmp(mode, "attack") == 0) { n = 128; fill = 0x43; }
	else if (strcmp(mode, "rip") == 0) { n = 80; fill = 0x43; }
	else if (strcmp(mode, "safe") == 0) { n = 20; fill = 0x41; }
	std::string data(n, static_cast<char>(fill));
	handler_pin(data);
	std::cout << "proof_len=" << n << "\n";
	return 0;
}
