#include <stdio.h>
#include <stdlib.h>
#include <openssl//x509.h>
#include <openssl/pem.h>

int main(){
    FILE *k, *p, *c;
    EVP_PKEY *key = EVP_PKEY_new(); /* allocate space for the private key, to deallocate use EVP_PKEY_free() */
    X509 *x509 = X509_new(); /* allocate space for x509 cert, for deallocate use X509_free() */
    X509_NAME *name = X509_get_subject_name(x509); /* generate information of the cert */

    key = EVP_RSA_gen(2048); /* generate rsa key */

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); /* set the cert serial number to 1 */
    
    X509_gmtime_adj(X509_get_notBefore(x509), 0);         /* set valid time, begin and end. start valid period on current time */
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);  /* stop valid time an year later */

    X509_set_pubkey(x509, key); /* set the cert public key */

    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"IT", -1, -1, 0); /* set country in the cert */
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"company", -1, -1, 0); /* set company name */
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0); /* set common name */
    X509_set_issuer_name(x509, name); /* set issuer name */

    X509_sign(x509, key, EVP_sha256()); /* sign the cert */

    k = fopen("key.pem", "wb");
    p = fopen("key.pub", "wb");
    c = fopen("cert.pem", "wb");
    
    /* save the private key to disk */
    PEM_write_PrivateKey(
        k,                                           /* write on file "f" */
        key,                                           /* set the key */
        EVP_aes_128_cbc(),                           /* cipher for encrypting the key       if dont want to encrypt the key, pass NULL here*/
        (const unsigned char *) "passfrase",        /* passphrase for decrypt the key                                                ,here*/
        9,                                          /* length of the passphrase string                                            and here*/
        NULL,                                         /* callback for requesting a password */
        NULL                                           /* data to pass to the callback */
    );

    /* save pubblic key to disk */
    PEM_write_PUBKEY(
        p, /* specify file to write */
        key  /* indicate key */
    );

    /* write the cert to disk */
    PEM_write_X509(
        c, /* write the certificate on file "f" */
        x509 /* indicate our certificate */
    );

    fclose(k);
    fclose(c);

    EVP_PKEY_free(key);
    X509_free(x509);

    return 0;
}