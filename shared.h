#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define PORT 1337

// Generate a Key and Sign a Certificate WebRTC uses self-signed certificates that are verified
// by the fingerprint exchanged during signaling
int set_key_and_certificate(SSL_CTX* ssl_ctx) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    if ((pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        goto cleanup;
    }


    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    if ((x509 = X509_new()) == NULL) {
        goto cleanup;
    }

    if (!X509_set_version(x509, 2)) {
        goto cleanup;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0)) {
        goto cleanup;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(x509), 31536000L)) { // 365 days in seconds
        goto cleanup;
    }

    if (!X509_set_pubkey(x509, pkey)) {
        goto cleanup;
    }


    X509_NAME *name = X509_get_subject_name(x509);
    if (name == NULL) {
        goto cleanup;
    }
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0)) {
        goto cleanup;
    }
    if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"MyOrganization", -1, -1, 0)) {
        goto cleanup;
    }

    if (!X509_set_issuer_name(x509, name)) {
        goto cleanup;
    }

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        goto cleanup;
    }

    if (!SSL_CTX_use_certificate(ssl_ctx, x509)) {
        printf("\n A \n");
        goto cleanup;
    }

    if (!SSL_CTX_use_PrivateKey(ssl_ctx, pkey)) {
        goto cleanup;
    }

    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (ret != 1)
        ERR_print_errors_fp(stderr);
    if (x509)
        X509_free(x509);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);

    return ret;
}

int openssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    return 1;
}

int create_ssl_session_and_bio(void) {
    SSL_CTX* ssl_ctx = NULL;
    SSL* ssl = NULL;
    BIO *read_BIO = NULL, *write_BIO = NULL;

    if ((ssl_ctx = SSL_CTX_new(DTLS_method())) == NULL) {
        return 0;
    }

    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, openssl_verify_callback);

    if (!set_key_and_certificate(ssl_ctx)) {
        return 0;
    }

    if (SSL_CTX_set_tlsext_use_srtp(ssl_ctx, "SRTP_AEAD_AES_256_GCM:SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")) {
        return 0;
    }

    if (!SSL_CTX_set_cipher_list(ssl_ctx, "HIGH:!aNULL:!MD5:!RC4")) {
        return 0;
    }

    if ((ssl = SSL_new(ssl_ctx)) == NULL) {
        return 0;
    }

    if ((read_BIO = BIO_new(BIO_s_mem())) == NULL) {
        return 0;
    }

    if ((write_BIO = BIO_new(BIO_s_mem())) == NULL) {
        return 0;
    }

    BIO_set_mem_eof_return(read_BIO, -1);
    BIO_set_mem_eof_return(write_BIO, -1);
    SSL_set_bio(ssl, read_BIO, write_BIO);

    return 1;
}
