set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/cjose2shell/w2/w219/evidence/gdb-w220-ident.log
set logging overwrite on
set logging enabled on

# W220: identify the object whose pointer fields at cek+0x80..0xa8 W219b
# overwrote, using watchpoints in the stable gdb (ASLR-off) heap layout.
# W220 uses hardware watchpoints on the two pointer-shaped words, not a
# broad malloc FinishBreakpoint (that stalled gdb in W219 during OpenSSL key
# setup). Watchpoints are armed when the bearer request enters validation.
set $w220_armed = 0

python
import gdb

TARGETS = (0x5555556671f0, 0x555555667210)
HITS = {}

class WatchBP(gdb.Breakpoint):
    def __init__(self, addr):
        super(WatchBP, self).__init__("*(unsigned long *)%#x" % addr,
                                      gdb.BP_WATCHPOINT, gdb.WP_WRITE,
                                      internal=True)
        self.addr = addr
        HITS[addr] = 0

    def stop(self):
        try:
            if int(gdb.parse_and_eval("$w220_armed")) != 1:
                return False
            HITS[self.addr] += 1
            if HITS[self.addr] <= 6:
                val = int(gdb.parse_and_eval("*(unsigned long *)%#x" % self.addr))
                gdb.write("W220_WATCH addr=%#x n=%d val=%#x\n" %
                          (self.addr, HITS[self.addr], val))
                gdb.execute("bt 8")
        except Exception as e:
            gdb.write("W220_WATCH_ERR %s\n" % e)
        return False

for _a in TARGETS:
    WatchBP(_a)
gdb.write("W220_IDENT_ARMED targets=%s\n" % ",".join(hex(a) for a in TARGETS))
end

break oidc_oauth_validate_jwt_access_token
commands
 silent
 set $w220_armed = 1
 printf "W220_VALIDATE_REACHED\n"
 continue
end
break _cjose_jwe_decrypt_ek_aes_kw
commands
 silent
 printf "W220_KW_DECRYPT raw_len=%lu cek_len=%lu jwk_kty=%d\n", (unsigned long)recipient->enc_key.raw_len, (unsigned long)jwe->cek_len, (int)jwk->kty
 continue
end
break jwe.c:595
commands
 silent
 printf "W220_PRE_UNWRAP cek=%p target=%p\n", jwe->cek, (char *)jwe->cek + 0x80
 x/16gx jwe->cek + 0x50
 continue
end
break jwe.c:602
commands
 silent
 printf "W220_POST_UNWRAP cek=%p cek_len_before=%lu\n", jwe->cek, (unsigned long)jwe->cek_len
 x/24gx jwe->cek + 0x60
 continue
end
run
bt 12
