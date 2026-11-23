# Reproducing the full-module ASan probe

All paths are relative to the repository root. The ASan APR/APR-util/httpd
stack is reused from `lab/frontier/apache2shell/build/`; it already carries
`-fsanitize=address` in its `apxs` and `bin/httpd`. No external system is
contacted at run time — only `127.0.0.1:18090`.

## Provision (network fetch is provisioning, not testing)

```
F=lab/frontier/modauthoidc2shell/full
B=lab/frontier/apache2shell/build
mkdir -p "$F/src" "$F/prefix"

git clone -q https://github.com/OpenIDC/mod_auth_openidc.git "$F/src/mod_auth_openidc"
git -C "$F/src/mod_auth_openidc" checkout -q 4301b5364034191adcba5153e5870405855cb74e
sha256sum "$F/src/mod_auth_openidc/src/state.c"   # must equal pin in ../src/SHA256SUMS

curl -fsSL -o "$F/src/jansson-2.14.tar.gz" https://github.com/akheron/jansson/releases/download/v2.14/jansson-2.14.tar.gz
curl -fsSL -o "$F/src/cjose.tar.gz" https://github.com/cisco/cjose/archive/refs/tags/0.6.1.tar.gz
mkdir -p "$F/src/jansson-2.14" "$F/src/cjose-0.6.1"
tar -xzf "$F/src/jansson-2.14.tar.gz" -C "$F/src/jansson-2.14" --strip-components=1
tar -xzf "$F/src/cjose.tar.gz" -C "$F/src/cjose-0.6.1" --strip-components=1
```

## Build dependencies and parent module

```
P="$(pwd)/$F/prefix"; export PKG_CONFIG_PATH="$B/apr-asan-install/lib/pkgconfig:$B/apu-asan-install/lib/pkgconfig:$P/lib/pkgconfig"
cd "$F/src/jansson-2.14"
./configure --prefix="$P" CFLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address'
make -j4 && make install
cd "../cjose-0.6.1"
./configure --prefix="$P" --with-jansson="$P" --with-openssl=/usr \
  CFLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer -Wno-error=deprecated-declarations' \
  LDFLAGS="-fsanitize=address -L$P/lib" CPPFLAGS="-I$P/include" PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
make -j4 && make install
cd "../mod_auth_openidc"
./autogen.sh
./configure --with-apxs="$B/httpd-2.4.71-asanapr-install/bin/apxs" \
  CFLAGS='-O1 -g -fsanitize=address -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address'
make -j4     # yields src/.libs/mod_auth_openidc.so
```

cjose 0.6.1 needs `-Wno-error=deprecated-declarations` on this host's OpenSSL
3 headers; without it its `-Werror` build fails.

## Fixed control and run

```
git -C "$F/src/mod_auth_openidc" worktree add -q "$F/src/mod_auth_openidc-fixed" v2.4.19.4
# repeat ./autogen.sh + ./configure + make in the worktree
cd "$F" && bash run.sh
```

`run.sh` starts each module on 127.0.0.1:18090 with the matching config, sends
30 value-less and 10 well-formed requests, and prints normalized counts.
Raw evidence lands in `evidence/`. See `evidence/README.md` for the measured
result and its limits.
