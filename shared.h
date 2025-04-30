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
#include <openssl/x509.h>

#define PORT 1337

// Generate a Key and Sign a Certificate
// WebRTC uses self-signed certificates that are verified
// by the fingerprint exchanged during signaling
int generate_key_and_certificate(void) {
    int ret = 1;
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

    ret = 0;

cleanup:
    if (ret != 0)
        ERR_print_errors_fp(stderr);
    if (x509)
        X509_free(x509);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);

    return ret;
}
