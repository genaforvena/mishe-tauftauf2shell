# PHP2Shell — status

Target: PHP2Shell — CVE-2026-109618 / CVE-2026-109619 (OOM-handling
corruption; stale global state across requests), CVSS 9.2 both, pre-auth
RCE demonstrated on WordPress/Drupal/Joomla. Affected 8.2<8.2.35,
8.3<8.3.36, 8.4<8.4.27, 8.5<8.5.12.

- **Rung:** 0 — suspected vulnerability. Claims read; nothing reproduced
  in the lab yet.
- **Next action:** confirm fetchable affected/fixed 8.4.x source trees
  and the ASan+UBSan build toolchain; decide which CVE (618 OOM longjmp
  path vs 619 stale-state UAF) to take first.
- **Last evidence:** vendor/researcher claims only —
  `docs/task.md` § PHP2Shell (verified ground truth, 2026-11-20),
  including the 2026-10-23 circulating PoC vector
  (`session.serialize_handler` + `session.upload_progress`, same family
  as `murrez/php2shell` CVE-2026-115560 claims). No lab observation yet.
- **Unknowns:** whether the PoC vector's preconditions
  (`php_binary`/`php_serialize` handler flip before `session_start()`)
  hold in a stock lab php-fpm/mod_php config; consumer behavior on this
  host's glibc for the OOM longjmp path.

Seeded by the operator 2026-11-20 from docs/task.md; the researcher owns
this file from its next wake on.
