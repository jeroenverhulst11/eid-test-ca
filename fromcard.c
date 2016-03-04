#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "base64enc.h"

#ifndef WIN32
#include <unix.h>
#include <arpa/inet.h> // for htons
#else
#include <win32.h>
#include <winsock2.h> // for htons
#endif
#include <pkcs11.h>

/** CUSTOMIZE THIS **/
#define SURNAME "Geurdin"
#define GIVEN_NAMES "Altay Mergo"
#define RRN_NUMBER "39012940734"
#define DO_SHA256 1
/** END OF LINES TO CUSTOMIZE **/

#define check_rv(call) { CK_RV rv = call; if (rv != CKR_OK) { printf("E: %s failed: %d\n", #call, rv); exit(EXIT_FAILURE); } }

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
struct derdata {
	uint8_t* data;
	size_t len;
	int keepme;
};

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

/* SEQUENCE { OBJECT (rsaEncryption), NULL } */
static uint8_t rsaalg[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x01, 0x05, 0x00
};

static struct derdata rsa = { rsaalg, sizeof rsaalg, 1 };

/* OBJECT (commonName) */
static uint8_t o_cn[] = {
	0x06, 0x03, 0x55, 0x04, 0x03
};

static struct derdata cn = { o_cn, sizeof o_cn, 1 };

/* OBJECT (surname) */
static uint8_t o_sn[] = {
	0x06, 0x03, 0x55, 0x04, 0x04
};

static struct derdata sn = { o_sn, sizeof o_sn, 1 };

/* OBJECT (serialNumber) */
static uint8_t o_serial[] = {
	0x06, 0x03, 0x55, 0x04, 0x05
};

static struct derdata serial = { o_serial, sizeof o_serial, 1 };

/* OBJECT (givenName) */
static uint8_t o_gn[] = {
	0x06, 0x03, 0x55, 0x04, 0x2a
};

static struct derdata gn = { o_gn, sizeof o_gn, 1 };

/* SET { SEQUENCE { OBJECT (countryName), PRINTABLESTRING "BE" } } */
static uint8_t c_be[] = {
	0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x42, 0x45
};

static struct derdata be = { c_be, sizeof c_be, 1 };

/* INTEGER(0) -- used for version number */
static uint8_t version_d[] = {
	0x02, 0x01, 0x00
};

static struct derdata version = { version_d, sizeof version_d, 1 };

/* SEQUENCE { OBJECT(sha256WithRSAEncryption), NULL } */
static uint8_t sha256_d[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x0b, 0x05, 0x00
};

static struct derdata sha256 = { sha256_d, sizeof sha256_d, 1 };

/* SEQUENCE { OBJECT(sha1WithRSAEncryption), NULL } */
static uint8_t sha1_d[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x05, 0x05, 0x00
};

static struct derdata sha1 = { sha1_d, sizeof sha1_d, 1 };

/* Empty attributes */
static uint8_t attr_d[] = {
	0xa0, 0x00
};

static struct derdata attributes = { attr_d, sizeof attr_d, 1 };

/* Generate something based on a BeID card which OpenSSL will accept as
 * a certificate signing request.
 * No, I do not guarantee that the output is 100% conform the PKCS#10
 * standard. It may be, it may not be. There are also a number of things
 * which are hardcoded in this implementation. That's fine, since we
 * don't need to modify them anyway.
 * The point of this exercise is to get a certificate signed by a CA for
 * *testing* purposes. If you use this for anything else, and someone
 * manages to break into your infrastructure, you have only yourself to
 * blame.
 */
struct derdata* gen_csr(CK_SESSION_HANDLE session, char* type, char* sn_str, char*
		gn_str, char* rrn_str, int do_256) {
	CK_OBJECT_HANDLE key;
	CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_LABEL, type, strlen(type) },
		{ CKA_CLASS, &klass, sizeof klass }
	};
	CK_ULONG count, bits;
	char mod[256], exp[4];
	CK_ATTRIBUTE attr[] = {
		{ CKA_MODULUS, mod, sizeof mod },
		{ CKA_MODULUS_BITS, &bits, sizeof bits },
		{ CKA_PUBLIC_EXPONENT, exp, sizeof exp },
	};
	CK_MECHANISM mech;
	CK_BYTE signature[256];
	CK_ULONG siglen = sizeof(signature);
	struct derdata *csr, *csr_unsigned;
	char cn_str[1024];
	char firstname[1024];
	char *space;

	/* Get the public half of the key */
	check_rv(C_FindObjectsInit(session, tmpl, 2));
	check_rv(C_FindObjects(session, &key, 1, &count));
	if(count != 1) {
		fprintf(stderr, "E: Could not read public key with label '%s': %lu found", type, count);
		return NULL;
	}
	check_rv(C_GetAttributeValue(session, key, attr, 3));
	check_rv(C_FindObjectsFinal(session));
	/* Get a handle to the private key */
	klass = CKO_PRIVATE_KEY;
	check_rv(C_FindObjectsInit(session, tmpl, 2));
	check_rv(C_FindObjects(session, &key, 1, &count));
	check_rv(C_FindObjectsFinal(session));
	if(count != 1) {
		fprintf(stderr, "E: Could not find private key with label '%s': %lu found", type, count);
		return NULL;
	}

	strncpy(firstname, gn_str, sizeof firstname);
	if((space = strchr(firstname, ' ')) != NULL) {
		*space = '\0';
	}
	snprintf(cn_str, sizeof cn_str, "%s %s (%s)", firstname, sn_str,
			type);

	/* Build a DER-representation of a CertificationRequestInfo */
	csr_unsigned = der_sequence(
		&version,
		der_sequence( // subject
			&be,
			der_setseqstr(&cn, cn_str),
			der_setseqstr(&sn, sn_str),
			der_setseqstr(&gn, gn_str),
			der_setseqstr(&serial, rrn_str),
			NULL
			),
		der_sequence( // SubjectPublicKeyInfo
			&rsa,
			der_bitder(
				der_sequence(
					der_longint(mod, attr[0].ulValueLen),
					der_longint(exp, attr[2].ulValueLen),
					NULL
					)
				),
			NULL
			),
		attributes,
		NULL
		);

	/* Now sign the request */
	mech.mechanism = do_256 ? CKM_SHA256_RSA_PKCS : CKM_SHA1_RSA_PKCS;
	check_rv(C_SignInit(session, &mech, key));
	check_rv(C_Sign(session, csr_unsigned->data, csr_unsigned->len, signature, &siglen));
	/* combine the CertificationRequestInfo with the signature to
	 * produce a PKCS#10 CSR (or at least, something similar enough
	 * for OpenSSL to accept it) */
	csr = der_sequence(
		csr_unsigned,
		do_256 ? &sha256 : &sha1,
		der_bitstring(signature, siglen * 8),
		NULL
		);

	return csr;
}

char* pem_csr(struct derdata* csr) {
	size_t b64len = (csr->len / 3 + 1) * 4;
	size_t newlines = b64len / 65 + 2;
	char header[] = "-----BEGIN CERTIFICATE REQUEST-----\n";
	char footer[] = "-----END CERTIFICATE REQUEST-----\n";
	char *encoded = malloc(b64len + newlines + 1 + sizeof header + sizeof footer);
	char *retval = encoded;
	base64_encodestate state;
	int count;

	strcpy(encoded, header);
	encoded += sizeof header - 1;
	base64_init_encodestate(&state);
	count = base64_encode_block(csr->data, csr->len, encoded, &state);
	encoded += count;
	count = base64_encode_blockend(encoded, &state);
	encoded += count - 1;
	if(*encoded != '\n') {
		*(++encoded) = '\n';
	}
	encoded++;
	strcpy(encoded, footer);
	return retval;
}

int main(void) {
	CK_SESSION_HANDLE session;
	CK_SLOT_ID slot;
	char auth[] = "Authentication";
	char sign[] = "Signature";
	CK_ULONG count = 1;
	struct derdata* data;
	char* pem;
	int fd;

	check_rv(C_Initialize(NULL_PTR));
	check_rv(C_GetSlotList(CK_TRUE, &slot, &count));
	check_rv(C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session));
	/* This will fail if there is more than one eID card. Don't do
	 * that. We want to keep this simple. */
	data = gen_csr(session, sign, SURNAME, GIVEN_NAMES, RRN_NUMBER, DO_SHA256);
	if(!data) {
		printf("No signature key found on card, not generating a signature certificate\n");
	} else {
		pem = pem_csr(data);
		printf("%s", pem);
		free(pem);
	}
	data = gen_csr(session, auth, SURNAME, GIVEN_NAMES, RRN_NUMBER, DO_SHA256);
	if(!data) {
		printf("No authentication key found on card, not generating an authentication certificate\n");
	} else {
		pem = pem_csr(data);
		printf("%s", pem);
		free(pem);
	}
	check_rv(C_CloseAllSessions(slot));
	check_rv(C_Finalize(NULL_PTR));
}
