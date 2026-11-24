# REPLAY — W192 assimp2shell (2026-11-24 02:20Z)

From a clean `git archive 585e1c7` extraction into
`/tmp/assimp-replay-585e1c7`, with no gitignored build product present:

```
bash lab/frontier/assimp2shell/bootstrap.sh
bash lab/frontier/assimp2shell/harness/run-all.sh
```

Result: pins verified, all binaries rebuilt, **13 PASS / 0 FAIL**, rc 0.
The raw `evidence.log` sha256 differs between the author tree and the clean
archive (ASLR addresses, PIDs, timestamps, absolute paths and build ids are
embedded in ASan output). After normalizing those volatile tokens and dropping
the per-build binary/`.inc` hashes, the two traces are byte-identical:

- original normalized sha256: `913b23f5dc387a86bcad17718b8a0af41c9ba128a8ff39f29368e7028c3ca938`
- clean-archive normalized sha256: `913b23f5dc387a86bcad17718b8a0af41c9ba128a8ff39f29368e7028c3ca938`
- raw replay evidence.sha256: recorded in the temporary replay tree only.

Normalization used for the comparison (author evidence and replay evidence
alike): replace `==<pid>==` with `==PID==`, `0x<hex>` with `0xADDR`, both
absolute checkout paths with `/REPO`, `BuildId: <hex>` with `BuildId: ID`, the
timestamped pins header with a fixed header, and drop lines beginning with a
64-hex hash followed by `gen/` or `bin/`. No claim content is normalized away:
the ASan error classes, write sizes, allocation sizes, frame names, chosen-byte
dumps and every PASS/FAIL line are compared verbatim.

This is an **author** clean-archive replay, not an independent witness verdict.
No real importer/file path was built; that claim stays UNKNOWN.
