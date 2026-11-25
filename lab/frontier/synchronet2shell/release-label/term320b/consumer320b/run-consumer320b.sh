#!/usr/bin/env bash
# W20: source-bound consumer chain in shipped 3.20b. The W19 overflow reaches
# savedlines.first/.last at sbbs_t+48/+56; this lane checks the pinned source
# path that initializes, overwrites, and then frees through those pointers.
set -uo pipefail
cd "$(dirname "$0")"
HERE=$PWD
EVID="$HERE/evidence"
mkdir -p "$EVID"
LOG="$EVID/evidence.log"
: > "$LOG"
SHA=db9c5d6fd37ef74b6e6ca647308d351e656de18d
BASE="https://raw.githubusercontent.com/SynchronetBBS/sbbs/$SHA"
pass=0; fail=0

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
check() {
    if [ "$2" = "$3" ]; then say "PASS $1"; pass=$((pass + 1))
    else say "FAIL $1 expected=[$2] actual=[$3]"; fail=$((fail + 1)); fi
}
line() { # file needle -> first matching line number (empty when absent)
    grep -nF "$2" "$1" | head -1 | cut -d: -f1
}
provision() { # remote path local name
    if ! grep -F "evidence/$2" "$HERE/PINS.sha256" | sha256sum --check --status 2>/dev/null; then
        curl -fsSL --max-time 60 -o "$EVID/$2" "$BASE/$1" || { say "FETCH_FAIL $2"; exit 2; }
    fi
}
provision src/sbbs3/answer.cpp       answer-320b.cpp
provision src/sbbs3/sbbs.h           sbbs-320b.h
provision src/sbbs3/telnet.h         telnet-320b.h
provision src/sbbs3/sbbsdefs.h       sbbsdefs-320b.h
provision src/xpdev/link_list.h      link_list-320b.h
provision src/sbbs3/main.cpp         main-320b.cpp
provision src/sbbs3/con_out.cpp      con_out-320b.cpp
provision src/xpdev/link_list.c      link_list-320b.c

say "run $(date -u +%FT%TZ) shipped-3.20b commit=$SHA source-bound consumer chain"
sha256sum -c "$HERE/PINS.sha256" >> "$LOG" 2>&1
check "8 pinned 3.20b source hashes" OK \
    "$(sha256sum -c "$HERE/PINS.sha256" >/dev/null 2>&1 && echo OK || echo BAD)"

getter=$(line "$EVID/answer-320b.cpp" 'cryptGetAttributeString(ssh_session, CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, terminal, &l)')
check "no-size getter at answer.cpp:520" 520 "$getter"
saved=$(line "$EVID/sbbs-320b.h" 'link_list_t savedlines{};')
term=$(line "$EVID/sbbs-320b.h" 'char	terminal[TELNET_TERM_MAXLEN+1]{};')
check "terminal field at sbbs.h:644" 644 "$term"
check "savedlines immediately after terminal+cterm_version" 646 "$saved"
first=$(line "$EVID/link_list-320b.h" 'first;')
last=$(line "$EVID/link_list-320b.h" 'last;')
check "savedlines.first is first link_list_t member" 68 "$first"
check "savedlines.last is second link_list_t member" 69 "$last"

init=$(line "$EVID/main-320b.cpp" 'listInit(&savedlines,')
answer=$(line "$EVID/main-320b.cpp" 'if(sbbs->answer())')
destructor=$(line "$EVID/main-320b.cpp" 'listFree(&savedlines);')
deleteline=$(line "$EVID/main-320b.cpp" 'delete sbbs;')
alloc=$(line "$EVID/main-320b.cpp" 'sbbs_t* new_node = new sbbs_t(')
check "savedlines initialized in sbbs_t ctor at main.cpp:3564" 3564 "$init"
check "answer() called in node_thread at main.cpp:4425" 4425 "$answer"
check "savedlines freed in destructor at main.cpp:3922" 3922 "$destructor"
check "heap sbbs_t allocated at main.cpp:5818" 5818 "$alloc"
check "node_thread deletes heap sbbs at main.cpp:4625" 4625 "$deleteline"
if [ -n "$init" ] && [ -n "$answer" ] && [ -n "$deleteline" ]; then
    check "init precedes answer, answer precedes teardown" OK \
        "$([ "$init" -lt "$answer" ] && [ "$answer" -lt "$deleteline" ] && echo OK || echo BAD)"
else
    check "init precedes answer, answer precedes teardown" OK MISSING
fi
check "saveline pushes to corrupted list at con_out.cpp:1519" 1519 \
    "$(line "$EVID/con_out-320b.cpp" 'listPushNodeData(&savedlines,')"
check "restoreline pops from corrupted list at con_out.cpp:1524" 1524 \
    "$(line "$EVID/con_out-320b.cpp" 'listPopNode(&savedlines)')"
check "listFreeNodes starts at list->first at link_list.c:76" 76 \
    "$(line "$EVID/link_list-320b.c" 'for(node=list->first; node!=NULL; node=next)')"
check "listFreeNodes frees each node at link_list.c:87" 87 \
    "$(line "$EVID/link_list-320b.c" 'free(node);')"
check "listFree calls listFreeNodes at link_list.c:107" 107 \
    "$(line "$EVID/link_list-320b.c" 'if(listFreeNodes(list))')"

say "RESULT $pass PASS / $fail FAIL"
say "scope: pinned source chain only. No 3.20b build, wire TERM, live sbbs_t object,"
say "corrupted pointer dereference, control-flow target, command, rung change or witness verdict."
[ "$fail" -eq 0 ]
