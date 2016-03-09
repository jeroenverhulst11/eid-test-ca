fromcard: fromcard.c cencode.c derencode.c
	$(CC) -g -O2 -o $@ -I /usr/include/beid/rsaref220 -lbeidpkcs11 $^
