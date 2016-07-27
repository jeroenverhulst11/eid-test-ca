#include "signdata.h"

#include <assert.h>
#include <stdio.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int main(int argc, char** argv) {
	assert(argc >= 6);

	char* id_fn = argv[1];
	char* sigout_fn = argv[2];
	char* address_fn = argv[3];
	char* addout_fn = argv[4];
	char* privkey_fn = argv[5];
	int hashnid;
	if(argc > 6) {
		switch(argv[6][0]) {
			case '1':
				hashnid = NID_sha1;
				break;
			case '2':
				hashnid = NID_sha256;
				break;
			default:
				fprintf(stderr, "E: Unknown hash requested");
				exit(EXIT_FAILURE);
		}
	} else {
		hashnid = NID_sha1;
	}

	FILE* f = fopen(privkey_fn, "rb");
	EVP_PKEY *evp_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
	if(!evp_key) {
		ERR_load_crypto_strings();
		unsigned long e = ERR_get_error();
		printf("error %ld: %s\n", e, ERR_error_string(e, NULL));
		exit(EXIT_FAILURE);
	}
	fclose(f);

	RSA *key_id = EVP_PKEY_get1_RSA(evp_key);
	RSA *key_address = EVP_PKEY_get1_RSA(evp_key);

	f = fopen(id_fn, "rb");
	fseek(f, 0, SEEK_END);
	size_t size = ftell(f);
	fseek(f, 0, SEEK_SET);
	struct derdata* id = derdata_new(size);
	fread(id->data, size, 1, f);
	fclose(f);

	f = fopen(address_fn, "rb");
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	struct derdata* address = derdata_new(size);
	fread(address->data, size, 1, f);
	fclose(f);

	struct derdata* id_sign = sign_id(id, hashnid, key_id);
	struct derdata* address_sign = sign_address(id_sign, address, hashnid, key_address);

	RSA_free(key_id);
	RSA_free(key_address);

	f = fopen(sigout_fn, "wb");
	fwrite(id_sign->data, id_sign->len, 1, f);
	fclose(f);

	f = fopen(addout_fn, "wb");
	fwrite(address_sign->data, address_sign->len, 1, f);
	fclose(f);
}
