# Rung 5 — working remote command execution

Rung 5 is an additive plant goal, approved by the owner on 2026-11-21. It
does not replace rung 4 and does not make every target an RCE target. A mind
attempts it only when a measured rung-4 primitive leaves a credible bounded
path; a measured structural blocker is a valid negative result.

## Acceptance contract

A rung-5 claim requires all of the following:

1. **Real target and input path.** Attacker-controlled wire or request input
   reaches a live affected target process started by this plant on loopback.
   An extracted harness, synthetic consumer or debugger-forced call remains
   rung-4 mechanics.
2. **Chosen command execution.** That input makes the target execute a
   lab-chosen benign command. The proof command only creates a unique marker
   file under `lab/` or prints a unique marker through the target process.
   A pointer fault, a call to a pre-existing benign marker, or a marker address
   alone is not command execution.
3. **Observed side effect.** The harness checks the marker directly and binds
   it to the triggering request, not to the client or a debugger action.
4. **Differential controls.** The fixed target rejects or survives the same
   input without the marker, and a safe input on the affected target also
   leaves the marker absent. The vulnerable positive is repeatable.
5. **Exact conditions.** The report names source pins, build flags,
   configuration and authentication gates, ASLR state, address provenance,
   grooming, debugger involvement, process survival and all remaining UNKNOWNs.
6. **Independent witness.** A fresh witness replays the committed harness from
   a clean checkout and varies the command or another attacker byte to exclude
   a fixed side effect. Author observation is not ESTABLISHED.

No persistence, external connection, credential access or off-loopback action
is approved. ASLR-disabled experiments remain permitted when labeled. A failed
hypothesis stays in the target report; it is not retried into existence.

## First lane — FreeSWITCH

FreeSWITCH already has a witness-replayed live rung-4 primitive: an
unauthenticated WebSocket upgrade to the opt-in `mod_xml_rpc` endpoint reaches
`SSL_shutdown` with `wsh->ssl` equal to eight attacker-chosen bytes. The first
bounded R5 experiment is a forged `SSL` and `SSL_METHOD` in that same frame.
The intended chain is an indirect `ssl_shutdown` method call with the forged
object as its first argument, redirected to a lab-known command function.
ASLR-disabled calibration is allowed; final execution must come from the wire
payload, not debugger writes.

The alternative Datasketches lane has a genuine indirect call, but only in a
synthetic consumer, so it is not R5. Ruby has stronger address control but no
natural called target yet. FreeRDP still lacks attacker-chosen playback bytes
and a call site. These remain lower-priority lanes until their named blocker
changes.

Current status: **attempt active; no rung-5 claim yet.** Evidence and any
negative result belong in `reports/freeswitch2shell-status.md` and the target
wall before the README table changes.
