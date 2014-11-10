#include <openssl/bn.h>

#define DEFAULT_KEY_LEN 1024 //in bits

/* Paillier keys */
typedef struct _pubKey {
        BIGNUM *n, *n2;
        BIGNUM *g;
} pubKey;

typedef struct _privKey {
        BIGNUM *n, *n2;
        BIGNUM *lamda, *mu;
} privKey;

typedef struct _paillierKeys {
    struct _pubKey pub;
    struct _privKey priv;
    BIGNUM *n, *n2;
} paillierKeys;
/**/

int generateRandomKeys(paillierKeys *keys, int *key_len, BN_CTX *ctx);
int dupKeys(paillierKeys *out, const paillierKeys *in);

int encryptll(BIGNUM *c, const long long plain, const pubKey *key, BN_CTX *ctx);
int encrypt(BIGNUM *c, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx);

int decrypt(BIGNUM *plain, const BIGNUM *c, const privKey *key, BN_CTX *ctx);
int decryptll(long long *plain, const BIGNUM *c, const privKey *key, BN_CTX *ctx);

int sub(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx);
int subEncPainll(BIGNUM *result, const BIGNUM *enc, const long long plain, const pubKey *key, BN_CTX *ctx);
int subEncPlain(BIGNUM *result, const BIGNUM *enc, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx);
int subllPlainEnc(BIGNUM *result, const long long plain, const BIGNUM *enc, const pubKey *key, BN_CTX *ctx);
int subPlainEnc(BIGNUM *result, const BIGNUM *plain, const BIGNUM *enc, const pubKey *key, BN_CTX *ctx);

int add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx);
int addEncPlainll(BIGNUM *result, const BIGNUM *enc, const long long plain, const pubKey *key, BN_CTX *ctx);
int addEncPlain(BIGNUM *result, const BIGNUM *enc, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx);

int mulPlainll(BIGNUM *result, const BIGNUM *a, const long long plain, const pubKey *key, BN_CTX *ctx);
int mulPlain(BIGNUM *result, const BIGNUM *a, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx);
