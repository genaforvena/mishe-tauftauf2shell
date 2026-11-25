set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file @LOG@
set logging overwrite on
set logging enabled on

# W220 second measurement: does the hashtable whose bucket the OOB write
# corrupts belong to the jwe->hdr used after unwrap? Log the object assigned
# at compact import, the object used by decrypt_dat, and every hashtable_get.
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
                gdb.execute("bt 4")
        except Exception as e:
            gdb.write("W220_WATCH_ERR %s\n" % e)
        return False

for _a in TARGETS:
    WatchBP(_a)
gdb.write("W220_USE_ARMED\n")
end
break oidc_oauth_validate_jwt_access_token
commands
 silent
 set $w220_armed = 1
 printf "W220_VALIDATE_REACHED\n"
 continue
end
break jwe.c:1905
commands
 silent
 printf "W220_IMPORT_HDR jwe=%p hdr=%p\n", jwe, jwe->hdr
 x/12gx jwe->hdr
 continue
end
break _cjose_jwe_decrypt_ek_aes_kw
commands
 silent
 printf "W220_KW_DECRYPT raw_len=%lu cek_len=%lu jwk_kty=%d\n", (unsigned long)recipient->enc_key.raw_len, (unsigned long)jwe->cek_len, (int)jwk->kty
 continue
end
break jwe.c:602
commands
 silent
 printf "W220_POST_UNWRAP cek=%p cek_len_before=%lu hdr=%p\n", jwe->cek, (unsigned long)jwe->cek_len, jwe->hdr
 x/12gx jwe->hdr
 continue
end
break _cjose_jwe_decrypt_dat_aes_gcm
commands
 silent
 printf "W220_DECRYPT_DAT jwe=%p hdr=%p cek=%p\n", jwe, jwe->hdr, jwe->cek
 x/12gx jwe->hdr
 continue
end
break hashtable_get
commands
 silent
 printf "W220_HASHTABLE_GET ht=%p key=%s\n", hashtable, key
 x/16gx hashtable->buckets
 continue
end
break hashtable_find_pair
commands
 silent
 printf "W220_FIND_PAIR bucket=%p first=%p last=%p\n", bucket, bucket->first, bucket->last
 continue
end
break json_object_get
commands
 silent
 if json != 0
   printf "W220_JSON_GET json=%p type_word=%lu\n", json, *(unsigned long *)json
 end
 continue
end
run
bt 12
