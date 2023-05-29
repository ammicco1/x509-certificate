main: main.c
	gcc -I /usr/include/openssl -o main -lcrypto main.c

clean:
	rm main *.pem *.pub