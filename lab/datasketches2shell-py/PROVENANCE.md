# datasketches2shell-py — CPython consumer provenance (wake 8)

The consumer is the **unmodified shipped `hll_wrapper.cpp` from
Apache DataSketches Python 5.2.0**. Its public binding at line 100 is

```cpp
.def_static("deserialize",
    [](const nb::bytes& bytes) { return hll_sketch::deserialize(bytes.c_str(), bytes.size()); },
    ...)
```

The harness compiles that file verbatim into a Python extension; only the
module entry point is reduced to `init_hll` (the other upstream wrappers are
not needed for this call). `nanobind` is the upstream build dependency. The C++
library headers are the already-pinned verbatim 5.2.0 / 5.3.0 release tarballs
from `../frontier/datasketches2shell/src/`; no library or binding source is
patched.

Pins verified by `build.sh` (`sha256sum -c` on both checksum files):

| artifact | sha256 |
| --- | --- |
| `src/datasketches-python-5.2.0.tar.gz` | `9bbc4f33261a0ef8c3dc8789a6e7eb6d66d3d742b10648a25bb679faf30fdd93` |
| `src/nanobind-3.1.0-py3-none-any.whl` | `96984dbe8154ffb86e653b1b60aaeed6985c710c5e75ad0279eb87943c66292d` |
| `../frontier/datasketches2shell/src/5.2.0.tar.gz` | `63e6bda660ee9730cc39746de87fd983118c28149e32ff9389fac98b27010a53` |
| `../frontier/datasketches2shell/src/5.3.0.tar.gz` | `9b0800207dcc5cf631a098de0c2c30385235075adb91a211fb6156f353c345fb` |

The images come from the library's own `serialize_compact()` seed (two updates,
16 bytes); only wire byte 6 (coupon count) and the payload bytes are changed.
Every probe runs in a local CPython process; there is no socket, no external
target and no network traffic.

Limits: this is a Python extension built from the shipped binding source, not
an installed upstream wheel or an application that consumes untrusted sketch
images over a network. A crash at interpreter finalisation is an observed
availability impact in a real consumer process; it is not a demonstrated
pointer value, control-flow diversion or code execution. No address leak was
used. Fixed 5.3.0 is a causal control, not a claim about deployed versions.
