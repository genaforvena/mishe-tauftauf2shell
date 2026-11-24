Clean-archive replay of commit a0050050 (18:29Z) scored 5 PASS / 1 FAIL.
The 128-byte case timed out at the client (rc=124): the client log stops after
"service ssh-userauth accepted", while the fresh replay server logged
`ACTIVE attempt=0 status=-41` (CRYPT_ERROR_READ), `CHANNEL poll i=100 cid=-1`
and `TERM sweep ... cid=-1`, so no channel ever opened. The two earlier cases
in the same replay logged `ACTIVE attempt=0 status=0` and passed, and the live
run of a0050050 had all three cases at status=0.

Diagnosis: the unmodified script sent SIGTERM to the previous server and
started the next one immediately; the fixed set of transcripts in this
directory shows the failure at the server activation step, not at the
pty-req parser or the getter. A port-settle wait was added to run-clientlen.sh
before and after each server start (wait until 127.0.0.1:22227 is free, then
until the new server listens). This is a tooling repair, not a change to the
vulnerability claim; the failed replay is kept here rather than erased.

The same historical pattern appears in wire/evidence/clserver-repaired-64.out
(ACTIVE -41), so this is a known transient of the probe server, not a new
property of cryptlib's TERM bound.
