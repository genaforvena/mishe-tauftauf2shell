# Standalone libical reproducer: icalparser_clean() ownership of the returned component

Tested on v4.0.6 (9cfca65c122fa23b9680a28e0c9225a2fd015fc5) and the default 4.0 branch at f01950ce276d6140fc124787cdd4c5db7aef4b0d, checked on 2026-10-09. Platform: Linux x86_64, Clang 21.1.8.

The program shows that `icalparser_clean()` returns a parsed component that the documentation makes the caller's property, while the parser keeps the same pointer. Freeing the returned component and later calling `icalparser_free()` — both documented steps — is a heap use-after-free. A second `icalparser_clean()` returns the same pointer again.

## Build the tested library

Use a source checkout at either tested commit. For example, obtain the release:

```bash
git clone --branch v4.0.6 https://github.com/libical/libical.git libical
cmake -S libical -B libical-asan \
  -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DLIBICAL_STATIC=ON -DLIBICAL_GLIB=OFF \
  -DLIBICAL_GOBJECT_INTROSPECTION=OFF -DLIBICAL_JAVA_BINDINGS=OFF \
  -DLIBICAL_BUILD_TESTING=OFF
cmake --build libical-asan --parallel 2
```

From the directory containing this README and the C file, compile the reproducer against that checkout and build directory:

```bash
sh build-reproducers.sh /path/to/libical /path/to/libical-asan
```

Only the source/build locations in this command need to be changed. No internal structure access, extra library patch, or project-specific harness is required. Transient line buffers are released by the caller, matching the current implementation of `icalparser_parse()`.

## Run

```bash
ASAN_OPTIONS=detect_leaks=1 ./05-uaf-clean-ownership clean-free-destroy
ASAN_OPTIONS=detect_leaks=1 ./05-uaf-clean-ownership clean-inspect-twice
ASAN_OPTIONS=detect_leaks=1 ./05-uaf-clean-ownership clean-free-twice
ASAN_OPTIONS=detect_leaks=1 ./05-uaf-clean-ownership two-sessions
ASAN_OPTIONS=detect_leaks=1 ./05-uaf-clean-ownership complete
```

Each mode takes an optional input shape as a second argument: `truncated` (default; the input ends after `BEGIN:VEVENT`, with no END lines) or `unclosed-child` (`BEGIN:VCALENDAR` / `BEGIN:VEVENT` / `END:VCALENDAR`). All observations below are the same for both shapes and for both tested versions.

Observed with ASan:

- `clean-free-destroy`: `first clean returned: non-NULL, ...`; freeing that component and then the parser reports `heap-use-after-free` READ in `icalcomponent_free` (`icalcomponent.c:197`) from `icalparser_free` (`icalparser.c:117`).
- `clean-inspect-twice`: `second clean returned the same pointer: yes`; serializing the second return value reports `heap-use-after-free` READ in `icalcomponent_isa` (`icalcomponent.c:328`).
- `clean-free-twice`: `second clean returned the same pointer: yes`; freeing the second return value (as documented) reports `heap-use-after-free` in `icalcomponent_free` (`icalcomponent.c:197`), a double free.
- `two-sessions`: each session ends with `icalparser_clean()` and the caller freeing the returned component, then the parser is reused; the final `icalparser_free()` reports `heap-use-after-free` in `icalcomponent_free` (`icalcomponent.c:197`).
- `complete` (control): the completed component is returned by `icalparser_add_line()` itself and `icalparser_clean()` returns NULL; exit code 0 with no ASan, UBSan, or LeakSanitizer report.

All programs use only the public API and the ownership rules stated in `icalparser.h`.
