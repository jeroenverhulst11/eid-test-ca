#ifndef DERDATA_H
#define DERDATA_H

#include <stdint.h>
#include <stdarg.h>

struct derdata {
	uint8_t* data;
	size_t len;
	int keepme;
};

struct derdata* der_length(size_t len);
struct derdata* der_list(uint8_t tag, struct derdata* first, va_list ap);
struct derdata* der_string(char* string);
struct derdata* der_sequence(struct derdata* first, ...);
struct derdata* der_set(struct derdata* first, ...);
struct derdata* der_bitstring(void* data, uint64_t bits);
struct derdata* der_longint(void* val, size_t len);
struct derdata* der_bitder(struct derdata* data);
struct derdata* der_setseqstr(struct derdata* object, char* string);

#endif
