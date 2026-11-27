/* Minimal real-wire caller for CVE-2026-29972: pinned library, unmodified
 * Linux platform transport, one TCP connect to 127.0.0.1, one FC3 read.
 * The two-register destination lives in a small frame so the 250-byte
 * response can reach the saved return address in a no-canary build.
 */
#include <unistd.h>
#include <stdio.h>

#include "nanomodbus.h"
#include "platform.h"

static void marker(void) {
    const char msg[] = "BENIGN_MARKER\n";
    (void) write(1, msg, sizeof(msg) - 1);
    _exit(0);
}
static void read_two(nmbs_t* nmbs) {
    uint16_t regs[2] = {0, 0};
    nmbs_error err = nmbs_read_holding_registers(nmbs, 26, 2, regs);
    printf("READ_RC %d REG0 %04x REG1 %04x\n", err, regs[0], regs[1]);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: client-wire [address] [port]\n");
        return 2;
    }
    void* conn = connect_tcp(argv[1], argv[2]);
    if (!conn) {
        fprintf(stderr, "Error connecting to server\n");
        return 2;
    }
    nmbs_platform_conf pc;
    nmbs_platform_conf_create(&pc);
    pc.transport = NMBS_TRANSPORT_TCP;
    pc.read = read_fd_linux;
    pc.write = write_fd_linux;
    pc.arg = conn;

    nmbs_t nmbs;
    nmbs_error err = nmbs_client_create(&nmbs, &pc);
    if (err != NMBS_ERROR_NONE) {
        fprintf(stderr, "Error creating client\n");
        return 2;
    }
    nmbs_set_read_timeout(&nmbs, 1000);
    read_two(&nmbs);
    disconnect(conn);
    return 0;
}
