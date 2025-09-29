/* rsa_lab.c  -- combined example (prints hex outputs for tasks 1..5) */
#include <stdio.h>
#include <openssl/bn.h>

void printBN(const char *label, BIGNUM *a) {
    char *s = BN_bn2hex(a);
    printf("%s %s\n", label, s);
    OPENSSL_free(s);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    // --- Task1: derive private d from given p,q,e
    BIGNUM *p = BN_new(), *q = BN_new(), *e1 = BN_new();
    BIGNUM *n1 = BN_new(), *p1 = BN_new(), *q1 = BN_new(), *phi = BN_new(), *d1 = BN_new();
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e1, "0D88C3");
    BN_mul(n1, p, q, ctx);
    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());
    BN_mul(phi, p1, q1, ctx);
    BN_mod_inverse(d1, e1, phi, ctx);
    printBN("Task1 n =", n1);
    printBN("Task1 d =", d1);

    // --- Task2: encrypt "A top secret!" with public (e,n) from task2
    BIGNUM *n2 = BN_new(), *e2 = BN_new();
    BN_hex2bn(&n2, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e2, "010001");
    BIGNUM *m = BN_new(), *c = BN_new();
    BN_hex2bn(&m, "4120746F702073656372657421");
    BN_mod_exp(c, m, e2, n2, ctx);
    printBN("Task2 Ciphertext =", c);

    // --- Task3: decrypt given ciphertext using provided d (task2's d)
    BIGNUM *d2 = BN_new(), *c3 = BN_new(), *m3 = BN_new();
    BN_hex2bn(&d2, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&c3, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    BN_mod_exp(m3, c3, d2, n2, ctx);
    printBN("Task3 Decrypted (hex) =", m3);

    // --- Task4: sign "I owe you $2000." and "I owe you $3000."
    BIGNUM *msg = BN_new(), *sig = BN_new();
    BN_hex2bn(&msg, "49206F776520796F752024323030302E");
    BN_mod_exp(sig, msg, d2, n2, ctx);
    printBN("Task4 Signature($2000) =", sig);
    BN_hex2bn(&msg, "49206F776520796F752024333030302E");
    BN_mod_exp(sig, msg, d2, n2, ctx);
    printBN("Task4 Signature($3000) =", sig);

    // --- Task5: verify signature S
    BIGNUM *S = BN_new(), *ver = BN_new(), *n5 = BN_new(), *e5 = BN_new();
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&n5, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e5, "010001");
    BN_mod_exp(ver, S, e5, n5, ctx);
    printBN("Task5 Verified (hex) =", ver);

    // free
    BN_free(p); BN_free(q); BN_free(e1); BN_free(n1); BN_free(p1);
    BN_free(q1); BN_free(phi); BN_free(d1);
    BN_free(n2); BN_free(e2); BN_free(m); BN_free(c);
    BN_free(d2); BN_free(c3); BN_free(m3);
    BN_free(msg); BN_free(sig);
    BN_free(S); BN_free(ver); BN_free(n5); BN_free(e5);
    BN_CTX_free(ctx);
    return 0;
}
