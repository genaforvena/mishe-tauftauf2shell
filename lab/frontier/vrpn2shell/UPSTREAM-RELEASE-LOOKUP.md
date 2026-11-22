# Released-fixed-version lookup — 2026-11-22 ~03:44Z

Reference provisioning only: reads of upstream GitHub metadata. No probe was
sent to any target. All commands run from the repository root.

## Commands and observed output

1. `curl -sSIL --max-time 20 -o /dev/null -w '%{http_code} %{url_effective}\n' https://github.com/vrpn/vrpn/archive/refs/tags/v07.39.tar.gz`

   `404 https://codeload.github.com/vrpn/vrpn/tar.gz/refs/tags/v07.39`

2. `git ls-remote --tags https://github.com/vrpn/vrpn.git` — 35 refs total.
   Version-like tags, peeled `^{}` refs removed, `sort -V`:

   `v07.27 v07.30 v07.31 v07.32 v07.33 v07.34 v07.35 v07.36
   version07.28 version_07.27 version_07.28 version_07.29 version_07.30
   version_07.31 version_07.32 version_07.33 version_07.34 version_07.35
   version_07.36`

   Full tag list additionally contains only `V07.29`, four `debian/upstream/`
   or `upstream-07.*` names and three `wmhtgui-*`/`gooddirectshow`/`hydra-change`/
   `patches-sent-upstream` development names. No 07.37, 07.38 or 07.39 tag.

3. `curl -sS 'https://api.github.com/repos/vrpn/vrpn/releases?per_page=10' | jq -r ...`

   Published releases (tag, published_at, name):

   `v07.36  2025-06-28T21:48:19Z  Version 07.36`
   `version_07.35  2022-05-30T18:03:25Z  Version 07.35 with submodules expanded`
   `version_07.34  2018-07-14T15:11:45Z  Version 07.34 with submodules expanded`
   `v07.33  2015-04-02T21:16:53Z  version_07_33_with_submodules_updated`

4. `curl -sS https://api.github.com/repos/vrpn/vrpn/commits/<sha> | jq -r ...`
   (short SHA, author date, subject):

   `79deb000cc0b  2025-06-28T20:47:08Z  Moving CMake version to the latest non-deprecated one...`
   `0da5b0b71e06  2026-10-22T14:46:58Z  Fixes unchecked write past bounds bugs reported by Deus Rex`
   `c893b583d928  2026-10-22T14:47:45Z  Updates minor version to identify that its now has this check.`

## Disposition

As of 2026-11-22 upstream has no released tag and no published GitHub release
after v07.36. Both fix commits are untagged master commits from 2026-10-22;
`c893b583d928` changes the in-tree version cookie from `vrpn: ver. 07.38` to
`vrpn: ver. 07.39`, which identifies the intended next version, **not** a
released tarball (the v07.39 tag lookup is 404). The fixed control therefore
remains the pinned commit tarball with SHA-256 digests in `PROVENANCE.md`.
The precise released fixed version stays UNKNOWN because no fixed release
exists to name; it is not evidence that 07.37/07.38/07.39 are fixed releases.
