# Builds only the shipped hll_wrapper.cpp from datasketches-python 5.2.0:
# its public hll_sketch.deserialize(bytes) lambda is the real consumer entry.
# DS2_LIBVER selects the pinned C++ library headers (5.2.0 vulnerable or
# 5.3.0 fixed). No library or binding source is modified.
cmake_minimum_required(VERSION 3.16)
project(ds2py LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(DS2_LIBVER "5.2.0" CACHE STRING "Pinned DataSketches C++ version")
set(DS2_MODULE "_ds2hll" CACHE STRING "Python extension module name")
set(DS2_MINI "mini52.cpp" CACHE STRING "Module entry file")
set(DS2_ASAN OFF CACHE BOOL "Instrument with AddressSanitizer")

if(DS2_ASAN)
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address)
endif()

find_package(Python 3.8 REQUIRED COMPONENTS Interpreter Development.Module)
execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE NB_DIR)
list(APPEND CMAKE_PREFIX_PATH "${NB_DIR}")
find_package(nanobind CONFIG REQUIRED)

set(HERE "${CMAKE_CURRENT_LIST_DIR}")
nanobind_add_module(${DS2_MODULE} MODULE NB_STATIC
  "${HERE}/work/datasketches-python-5.2.0/src/hll_wrapper.cpp"
  "${HERE}/${DS2_MINI}")
target_include_directories(${DS2_MODULE} PRIVATE
  "${HERE}/work/datasketches-cpp-${DS2_LIBVER}/hll/include"
  "${HERE}/work/datasketches-cpp-${DS2_LIBVER}/common/include")
