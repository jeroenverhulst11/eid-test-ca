fromcard: fromcard.c cencode.c
	$(CC) -g -o $@ -I /usr/include/beid/rsaref220 -lbeidpkcs11 $^
