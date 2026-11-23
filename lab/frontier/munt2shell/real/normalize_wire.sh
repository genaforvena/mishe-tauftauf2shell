#!/bin/sh
# Print W171 wire evidence with run-varying fields normalized:
# ephemeral TCP ports, ASan PIDs/ASLR addresses, the victim's ASLR pointer
# and the absolute checkout prefix. The intact magic and the overwritten
# 0x6a fields are left comparable.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
cat evidence/wire-results.txt
for f in evidence/wire-server-*.out evidence/wire-client-*.out; do
	sed -E \
		-e 's/127\.0\.0\.1:[0-9]+/127.0.0.1:PORT/g' \
		-e 's/port=[0-9]+/port=PORT/g' \
		-e 's/==[0-9]+==/==PID==/g' \
		-e 's/magic=0xcafebabe/MAGIC_OK/g' \
		-e 's/ptr=0x[0-9a-f]+/ptr=PTR/g' \
		-e 's@[^ ]*lab/frontier/munt2shell/@LAB/@g' \
		-e 's/0x[0-9a-f]+/0xADDR/g' \
		-e 's/BuildId: [0-9a-f]+/BuildId: ID/g' \
		"$f"
done
