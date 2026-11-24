# REPLAY — W194 synchronet2shell (2026-11-24)

From a clean `git archive e5f43ad` extraction into
`/tmp/synchronet-replay-e5f43ad`, with no gitignored build product present:

```
cd lab/frontier/synchronet2shell
bash bootstrap.sh
bash harness/run-all.sh
```

Result: pins verified, all 7 binaries rebuilt, **9 PASS / 0 FAIL**, rc 0.
Raw `evidence.log` sha256 differs from the author tree only because of volatile
tokens (timestamps, PIDs, ASLR addresses, absolute checkout paths and build
ids):

- author tree: `9ed3b328ccc0d59a45ebeda9cf51053c7fafc28627e6d574d641914c9403a24e`
- clean archive: `283306d540cc7b0df0a82e0cff8800812456911d49b0353deb8a6c229aa99bb8`

After normalizing those tokens (`TIMESTAMP`, `==PID==`, `0xADDR`, `/REPO`,
`BuildId: ID`), the two traces are byte-identical:

- author normalized: `66d20f827154e76208c2dcced24fb5bd0a2247c5b5690dceb316e2aae414bdd8`
- clean-archive normalized: `66d20f827154e76208c2dcced24fb5bd0a2247c5b5690dceb316e2aae414bdd8`

No claim content is normalized away: ASan error class, write size, frame names,
field offsets, chosen-byte hexdumps, control results and every PASS/FAIL line
are compared verbatim. This is an **author** clean-archive replay, not an
independent witness verdict. No real Synchronet build, SSH handshake or wire
was exercised; that ceiling stays UNKNOWN.
