# Install script for directory: /home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/ggml/src/cmake_install.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libggml.so.0.27.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libggml.so.0"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/bin/libggml.so.0.27.0"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/bin/libggml.so.0"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libggml.so.0.27.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libggml.so.0"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/bin:"
           NEW_RPATH "")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/bin/libggml.so")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-cpu.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-alloc.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-backend.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-blas.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-cann.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-cpp.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-cuda.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-opt.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-metal.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-rpc.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-virtgpu.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-sycl.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-vulkan.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-webgpu.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-zendnn.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/ggml-openvino.h"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin/ggml/include/gguf.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libggml-base.so.0.27.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libggml-base.so.0"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/bin/libggml-base.so.0.27.0"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/bin/libggml-base.so.0"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libggml-base.so.0.27.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libggml-base.so.0"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/bin/libggml-base.so")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/ggml" TYPE FILE FILES
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/ggml/ggml-config.cmake"
    "/home/mesh-home/mishe-tauftauf2shell/lab/frontier/llamarpc2shell/src/llama.cpp-pin-plain/ggml/ggml-config-version.cmake"
    )
endif()

