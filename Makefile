all: fromcard resign

CFLAGS := -g -O2

fromcard: fromcard.c derencode.c base64encode.c
	$(CC) $(CFLAGS) -o $@ -I /usr/include/beid/rsaref220 -lbeidpkcs11 $^

resign: derencode.c signdata.c resign.c
	$(CC) $(CFLAGS) -o $@ -I `pkg-config --cflags --libs openssl` $^

clean:
	rm fromcard resign
