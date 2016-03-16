#include "signdata.h"

#include <assert.h>
#include <string.h>

#include <openssl/x509.h>

struct derdata* sign_id(struct derdata* id, int hashtype, RSA* key) {
	size_t len;
	struct derdata* retval = derdata_new(RSA_size(key));
	struct derdata* digest;
	unsigned char*(*hash)(const unsigned char*, size_t, unsigned char*);
	unsigned int retlen;

	switch(hashtype) {
		case NID_sha1:
			len = SHA_DIGEST_LENGTH;
			hash=SHA1;
			break;
		case NID_sha256:
			len = SHA256_DIGEST_LENGTH;
			hash=SHA256;
			break;
		default:
			fprintf(stderr, "E: invalid hash type %d", hashtype);
			derdata_destroy(retval);
			return NULL;
	}
	digest = derdata_new(len);
	hash(id->data, id->len, digest->data);
	RSA_sign(hashtype, digest->data, digest->len, retval->data, &retlen, key);
	assert(retlen <= retval->len);
	derdata_destroy(digest);
	return retval;
}

struct derdata* sign_address(struct derdata* idsig, struct derdata* address, int hashtype, RSA* key) {
	size_t len;
	struct derdata* digest;
	struct derdata* retval = derdata_new(RSA_size(key));
	struct derdata* message = derdata_new(idsig->len + address->len);
	unsigned char *ptr;
	unsigned char*(*hash)(const unsigned char*, size_t, unsigned char*);
	unsigned int retlen;

	switch(hashtype) {
		case NID_sha1:
			len = SHA_DIGEST_LENGTH;
			hash=SHA1;
			break;
		case NID_sha256:
			len = SHA256_DIGEST_LENGTH;
			hash=SHA256;
			break;
		default:
			fprintf(stderr, "E: invalid hash type %d", hashtype);
			derdata_destroy(retval);
			return NULL;
	}
	memcpy(message->data, address->data, address->len);
	for(ptr = message->data + address->len; *ptr == 0; ptr--);
	ptr++;
	digest = derdata_new(len);
	memcpy(ptr, idsig->data, idsig->len);
	hash(message->data, (ptr - message->data) + idsig->len, digest->data);
	derdata_destroy(message);
	RSA_sign(hashtype, digest->data, digest->len, retval->data, &retlen, key);
	assert(retlen <= retval->len);
	derdata_destroy(digest);
	return retval;
}
