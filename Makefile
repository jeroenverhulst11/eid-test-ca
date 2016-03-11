fromcard: fromcard.c derencode.c base64encode.c
	$(CC) -g -O2 -o $@ -I /usr/include/beid/rsaref220 -lbeidpkcs11 $^
