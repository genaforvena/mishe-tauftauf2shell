set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file @LOG@
set logging overwrite on
set logging enabled on

python
import gdb

# W217's stable gdb-launched layout: cek=0x5555556672e0, chunk at cek+0x60
# (size 0x41), user pointer = cek+0x70 = 0x555555667350. gdb disables ASLR
# by default, so repeat runs of this exact config/probe keep this address.
TARGET = 0x555555667350

class MallocBP(gdb.Breakpoint):
    def stop(self):
        try:
            size = int(gdb.parse_and_eval("$rdi"))
        except Exception:
            return False
        # glibc chunk 0x41 comes from a 48..56 byte request.
        if not (48 <= size <= 56):
            return False
        try:
            caller = gdb.newest_frame().older().name() or "?"
        except Exception:
            caller = "?"
        try:
            RetBP(size, caller)
        except Exception as e:
            gdb.write("W218_RETBP_ERR %s\n" % e)
        return False

class RetBP(gdb.FinishBreakpoint):
    def __init__(self, size, caller):
        super(RetBP, self).__init__(gdb.newest_frame(), internal=True)
        self.size = size
        self.caller = caller

    def stop(self):
        try:
            p = int(self.return_value)
        except Exception:
            return False
        if p == TARGET:
            gdb.write("W218_ALLOC_TARGET ptr=%#x size=%d caller=%s\n" %
                      (p, self.size, self.caller))
            gdb.execute("bt 8")
        return False

class FreeBP(gdb.Breakpoint):
    def stop(self):
        try:
            p = int(gdb.parse_and_eval("$rdi"))
        except Exception:
            return False
        if p == TARGET:
            gdb.write("W218_FREE_TARGET ptr=%#x\n" % p)
            gdb.execute("bt 8")
        return False

MallocBP("malloc")
FreeBP("free")
gdb.write("W218_IDENT_ARMED target=%#x\n" % TARGET)
end

break _cjose_jwe_decrypt_ek_aes_kw
commands
 silent
 printf "W218_KW_DECRYPT raw_len=%lu cek_len=%lu jwk_kty=%d\n", (unsigned long)recipient->enc_key.raw_len, (unsigned long)jwe->cek_len, (int)jwk->kty
 continue
end
break jwe.c:602
commands
 silent
 printf "W218_CEK=%p target_user=%p\n", jwe->cek, (char *)jwe->cek + 0x70
 x/8gx jwe->cek + 0x60
 continue
end
run
bt 12
