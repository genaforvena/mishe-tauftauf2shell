#ifndef SHIM_POSTGRES_H
#define SHIM_POSTGRES_H
#include <stdbool.h>
#include <stdint.h>
#define pg_attribute_printf(f,a) __attribute__((format(printf,f,a)))
typedef bool bool_t;
#endif
