# Real-consumer probe: Apache DataSketches PostgreSQL extension

All bytes fetched as provisioning from public sources; all runtime tests bound
127.0.0.1 only. No external host was contacted with a probe.

Sources:

- PostgreSQL 16.4, `https://ftp.postgresql.org/pub/source/v16.4/postgresql-16.4.tar.bz2`,
  sha256 `971766d645aa73e93b9ef4e3be44201b4f45b5477095b049125403f9f3386d6f`.
- Apache DataSketches PostgreSQL extension, master at commit
  `56d871276d32a1235041b553559143a9697f8906`,
  `https://github.com/apache/datasketches-postgresql/archive/refs/heads/master.tar.gz`,
  sha256 `010f98b702113e7b040e3f1ba86c6b6de1af733185bdd77a7a365010fa45dae3`.
- DataSketches C++ 5.2.0 tarball: the existing pinned copy under
  `lab/frontier/datasketches2shell/src/5.2.0.tar.gz` (verified by that lane's
  `SHA256SUMS`). The extension README requires C++ core 5.0.0 or later; the
  vulnerable range ends at 5.2.0, so the pinned tarball is a supported,
  affected input to this consumer.

No library source was copied, patched or shimmed. `Makefile.hll` builds only
the HLL objects of the shipped extension (the other sketch families need
unrelated Boost headers); the C/C++ adapter source is verbatim. The extension
allocates through `palloc_allocator<char>` from `src/allocator.h`, i.e. the
PostgreSQL memory context allocator, not glibc malloc.

The seed image is a genuine 5.2.0 `serialize_compact()` image of two updates
(`02010708030802002bf2fb06862ff90d`); only wire byte 6 (coupon count) and the
payload bytes differ in the crafted images.
