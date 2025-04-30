Run `make` and then `./client` and `./server` in seperate terminals.


OpenSSL for testing
```
openssl ecparam -out key.pem -name prime256v1 -genkey
openssl req -new -sha256 -key key.pem -out server.csr
openssl x509 -req -sha256 -days 365 -in server.csr -signkey key.pem -out cert.pem

// Server
openssl s_server -dtls1_2 -cert cert.pem -key key.pem -accept 1337

// Client
openssl s_client -dtls1_2 -connect 127.0.0.1:4444 -debug -cert cert.pem -key key.pem
```
