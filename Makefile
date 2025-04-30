all:
	cc `pkg-config openssl --libs --cflags` -o server server.c
	cc `pkg-config openssl --libs --cflags` -o client client.c
