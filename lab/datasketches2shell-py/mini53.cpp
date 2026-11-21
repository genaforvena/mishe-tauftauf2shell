#include <nanobind/nanobind.h>
namespace nb = nanobind;
void init_hll(nb::module_& m);
NB_MODULE(_ds2hll53, m) {
  init_hll(m);
}
