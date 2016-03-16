#ifndef SIGNDATA_H
#define SIGNDATA_H

#include "derdata.h"
#include <openssl/rsa.h>

struct derdata* sign_id(struct derdata* id, int hashtype, RSA* key);
struct derdata* sign_address(struct derdata* idsig, struct derdata* address, int hashtype, RSA* key);

#endif
