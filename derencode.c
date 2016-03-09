#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "derdata.h"

#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

/* Helper functions for linked lists */
struct list {
	void* data;
	struct list* next;
};

static struct list* list_append(struct list *head, void *data) {
	struct list *ptr = head;
	struct list *tail = calloc(sizeof(struct list), 1);

	tail->data = data;
	if(!head) return tail;

	while(ptr->next) {
		ptr = ptr->next;
	}
	ptr->next = tail;
	return head;
}

static void* list_pop(struct list **head) {
	struct list *ptr = *head;
	void* retval;
	if(!head) return NULL;

	retval = (*head)->data;
	*head = (*head)->next;
	free(ptr);
	return retval;
}

/*
 * Helper functions to DER-encode data. This should really be done with
 * an ASN.1 compiler, but the only FLOSS one generates *way* too much
 * boilerplate for it to be useful in this context.
 */
struct derdata* der_length(size_t len) {
	struct derdata* retval = calloc(sizeof (struct derdata), 1);
	if(len <= 0x7F) {
		retval->data = malloc(1);
		*retval->data = (uint8_t)len;
		retval->len = 1;
		return retval;
	} 
	if(len <= 0xFF) {
		retval->data = malloc(2);
		retval->data[0] = 0x81;
		retval->data[1] = (uint8_t)len;
		retval->len = 2;
		return retval;
	}
	if(len <= 0xFFFF) {
		uint16_t val = htons(len);
		retval->data = malloc(3);
		retval->data[0] = 0x82;
		memcpy(retval->data+1, &val, 2);
		retval->len = 3;
		return retval;
	}
	assert(1 == 0); // we don't generate such long data
}

struct derdata* der_list(uint8_t tag, struct derdata* first, va_list ap) {
	struct list* members = NULL;
	struct derdata* member = first;
	struct derdata* length;
	struct derdata* retval = calloc(sizeof(struct derdata), 1);
	uint8_t* ptr;

	while(member) {
		retval->len += member->len;
		members = list_append(members, member);
		member = va_arg(ap, struct derdata*);
	}
	length = der_length(retval->len);
	retval->len += length->len + 1;
	ptr = retval->data = malloc(retval->len);
	*ptr++ = tag;
	memcpy(ptr, length->data, length->len);
	ptr += length->len;
	free(length->data);
	free(length);
	while(members) {
		member = (struct derdata*)list_pop(&members);
		memcpy(ptr, member->data, member->len);
		ptr += member->len;
		if(!member->keepme) {
			free(member->data);
			free(member);
		}
	}
	return retval;
}

struct derdata* der_string(char* string) {
	int printable = 1;
	int ia5 = 1;
	unsigned char* ptr = string;
	uint8_t tag, *uptr;
	struct derdata* retval = calloc(sizeof(struct derdata), 1);
	struct derdata* length;

	while((printable || ia5) && *ptr) {
		if(*ptr > 127) {
			printable = 0;
			ia5 = 0;
		}
		if(printable && !isalnum(*ptr)) {
			switch(*ptr) {
				case '\'':
				case '(':
				case ')':
				case '+':
				case ',':
				case '-':
				case '.':
				case '/':
				case ':':
				case '=':
				case '?':
					break;
				default:
					printable = 0;
			}
		}
		ptr++;
	}
	retval->len = strlen(string);
	length = der_length(retval->len);
	retval->len += length->len + 1;
	uptr = retval->data = calloc(retval->len, 1);
	*uptr++ = printable ? 0x13 : (ia5 ? 0x16 : 0x0c); // tag
	memcpy(uptr, length->data, length->len);
	uptr += length->len;
	strncpy(uptr, string, retval->len - 1 - length->len);
	free(length->data);
	free(length);
	return retval;
}

struct derdata* der_sequence(struct derdata* first, ...) {
	va_list ap;
	struct derdata *retval;

	va_start(ap, first);
	retval = der_list(0x30, first, ap);
	va_end(ap);
	return retval;
}

struct derdata* der_set(struct derdata* first, ...) {
	va_list ap;
	struct derdata *retval;

	va_start(ap, first);
	retval = der_list(0x31, first, ap);
	va_end(ap);
	return retval;
}

struct derdata* der_bitstring(void* data, uint64_t bits) {
	uint8_t over = bits % 8;
	size_t bytelen = bits / 8;
	size_t len;
	struct derdata *length, *retval;
	uint8_t* ptr;

	assert(bytelen * 8 + over == bits);
	if(over != 0) {
		bytelen++;
	}
	len = bytelen + 1;
	length = der_length(len);
	retval = calloc(sizeof(struct derdata), 1);
	retval->len = len + length->len + 1;
	ptr = retval->data = malloc(retval->len);
	*ptr++ = 0x03; // tag
	memcpy(ptr, length->data, length->len);
	ptr += length->len;
	free(length->data);
	free(length);
	*ptr++ = over;
	memcpy(ptr, data, bytelen);
	return retval;
}

struct derdata* der_longint(void* val, size_t len) {
	struct derdata* retval = calloc(sizeof(struct derdata), 1);
	struct derdata* length;
	uint8_t* ptr;

	length = der_length(len);
	retval->len = length->len + len + 1;
	ptr = retval->data = malloc(retval->len);
	*ptr++ = 0x02; // tag
	memcpy(ptr, length->data, length->len);
	ptr += length->len;
	free(length->data);
	free(length);
	memcpy(ptr, val, len);
	return retval;
}

struct derdata* der_bitder(struct derdata* data) {
	return der_bitstring(data->data, data->len * 8);
}

/* Produce a SET { SEQUENCE { OBJECT (foo), PRINTABLESTRING "bar" } }
 * sequence */
struct derdata* der_setseqstr(struct derdata* object, char* string) {
	return der_set(
		der_sequence(
			object,
			der_string(string),
			NULL
			),
		NULL
		);
}
