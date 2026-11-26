/* W28: standalone lab probe of the fixed-address vsyscall page.
 *
 * The pinned vulnerable call site passes the wire-controlled data length in
 * RAX at its indirect callback call (objdump -d --disassemble=channel_rcv_data
 * real_wire-plain-sw-vuln: "mov %eax,%ecx; call *0x10(%rsp)"). A raw
 * "syscall" instruction at a fixed, callable address would therefore be an
 * ASLR-independent callee with a wire-chosen syscall number. This probe
 * checks whether any of the three fixed vsyscall entries, or an offset inside
 * one of their stubs, behaves as a raw syscall gadget: each child sets RAX=39
 * (getpid), calls the candidate address, and reports whether the result is
 * its own pid. No target, no network, no libssh code involved.
 *
 * Build/run: clang -O0 -g w28-vsyscall-probe.c -o w28-vsyscall-probe &&
 *            ./w28-vsyscall-probe
 * Expected on this host (6.8.0-149-generic): only "sweep done", no gadget.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdint.h>

static long fixed_syscall(unsigned long gadget, unsigned long nr,
                          unsigned long a1, unsigned long a2, unsigned long a3)
{
    long rc;
    __asm__ volatile(
        "push %[gadget]\n\t"
        "mov %[nr], %%rax\n\t"
        "mov %[a1], %%rdi\n\t"
        "mov %[a2], %%rsi\n\t"
        "mov %[a3], %%rdx\n\t"
        "call *(%%rsp)\n\t"
        "add $8, %%rsp\n\t"
        : "=a"(rc)
        : [gadget] "r"(gadget), [nr] "r"(nr), [a1] "r"(a1),
          [a2] "r"(a2), [a3] "r"(a3)
        : "rcx", "r11", "memory");
    return rc;
}


int main(void)
{
    unsigned long bases[] = {0xffffffffff600000UL, 0xffffffffff600400UL,
                             0xffffffffff600800UL};
    for (unsigned b = 0; b < 3; b++) {
        for (unsigned off = 0; off < 32; off++) {
            unsigned long addr = bases[b] + off;
            pid_t pid = fork();
            if (pid == 0) {
                unsigned long expect = (unsigned long)getpid();
                long rc = fixed_syscall(addr, 39, 0, 0, 0); /* getpid */
                _exit(rc == (long)expect ? 42 : 0);
            }
            int st = 0;
            waitpid(pid, &st, 0);
            if (WIFEXITED(st) && WEXITSTATUS(st) == 42)
                printf("RAW_SYSCALL_GADGET addr=0x%lx base=0x%lx off=%u\n",
                       addr, bases[b], off);
        }
    }
    printf("sweep done\n");
    return 0;
}
