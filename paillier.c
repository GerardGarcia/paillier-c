#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "paillier.h"

// LCM for BIGNUMs
static int BN_lcm(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);

    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *gcd = BN_CTX_get(ctx);

    if (!BN_gcd(gcd, a, b, ctx))
        goto end;
    if (!BN_div(tmp, NULL, a, gcd, ctx))
        goto end;
    if (!BN_mul(r, b, tmp, ctx))
        goto end;

    ret = 1;
end:
    if (ret != 1)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "Error calculating lcm: %s", ERR_error_string(ERR_get_error(), NULL));
    } 

    BN_CTX_end(ctx);
    return ret;
}

// For key generation
static int L(BIGNUM *res, const BIGNUM *u, const BIGNUM *n, BN_CTX *ctx)
{
    int ret = 1;

    BIGNUM *u_cp = BN_dup(u);
    if (!BN_sub_word(u_cp, 1))
        goto end;
    if (!BN_div(res, NULL, u_cp, n, ctx))
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "Error calculating L: %s", ERR_error_string(ERR_get_error(), NULL));
    } 

    BN_free(u_cp);
    return ret;
}

int generateRandomKeys(paillierKeys *keys, int *key_len, BN_CTX *ctx)
{
    int ret = 1, final_key_l = 0;
    BIGNUM *p, *q, *tmp, *n, *n2, *g, *lamda, *mu;

    if (key_len != NULL && *key_len == 0)
    {
        *key_len = DEFAULT_KEY_LEN;
        final_key_l = *key_len;
    }
    else if (key_len != NULL)
    {
        final_key_l = *key_len;
    }
    else
    {
        final_key_l = DEFAULT_KEY_LEN;
    }

    if (final_key_l < 32)
    {
        fprintf(stderr, "Key lenght too short. Minimum lenght 32 bits");
        goto end;
    }

    BN_CTX_start(ctx);

    // Temp BIGNUMs
    p = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    // Part of the keys BIGNUMs
    n = BN_new();
    n2 = BN_new();
    g = BN_new();
    lamda = BN_new();
    mu = BN_new();

    // 1. Choose two large prime numbers
    // This numbers have to hold gcd(pq, (p-1)(q-1)) = 1
    unsigned char buffer;
    do
    {
        if (!RAND_bytes(&buffer, sizeof(buffer)))
            goto end;
        srandom((int)buffer);

        if (!BN_generate_prime_ex(p, final_key_l / 2, 0, NULL, NULL, NULL))
            goto end;
        if (!BN_generate_prime_ex(q, final_key_l / 2, 0, NULL, NULL, NULL))
            goto end;

        // 2. Compute n = pq
        if (!BN_mul(n, p, q, ctx))
            goto end;

        // Test if primes are ok
        if (!BN_sub_word(p, 1))
            goto end;
        if (!BN_sub_word(q, 1))
            goto end;
        if (!BN_mul(tmp, p, q, ctx))
            goto end;

    }
    while (BN_cmp(p, q) == 0 || BN_gcd(tmp, tmp, n, ctx) != 1);

    // and lamda = lcm(p-1,q-1)
    if (!BN_lcm(lamda, p, q, ctx))
        goto end;

    if (!BN_mul(n2, n, n, ctx))
        goto end;
    do
    {
        // 3. Select a random integer g moz n2
        do
        {
            if (!BN_rand_range(g, n2))
                goto end;
        }
        while (BN_is_zero(g));

        // 4. Ensure n divides the order of g
        if (!BN_mod_exp(tmp, g, lamda, n2, ctx))
            goto end;
        if (L(tmp, tmp, n, ctx) != 0)
            goto end;

        BN_mod_inverse(mu, tmp, n, ctx);
    }
    while (mu == NULL);

    keys->pub.n = n;
    keys->pub.n2 = n2;
    keys->pub.g = g;

    keys->priv.n = BN_dup(n);
    keys->priv.n2 = BN_dup(n2);
    keys->priv.lamda = lamda;
    keys->priv.mu = mu;

    keys->n = BN_dup(n);
    keys->n2 = BN_dup(n2);

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "Error generating keys: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int freeKeys(paillierKeys *keys)
{
    if (keys->pub.n)
        BN_free(keys->pub.n);
    if (keys->pub.g)
        BN_free(keys->pub.g);
    if (keys->pub.n2)
        BN_free(keys->pub.n2);

    if (keys->priv.lamda)
        BN_free(keys->priv.lamda);
    if (keys->priv.mu)
        BN_free(keys->priv.mu);
    if (keys->priv.n)
        BN_free(keys->priv.n);
    if (keys->priv.n2)
        BN_free(keys->priv.n2);

    return 0;
}

int encryptll(BIGNUM *c, const long long plain, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *m = BN_CTX_get(ctx);

    if (!BN_set_word(m, plain))
        goto end;
    if (encrypt(c, m, key, ctx) != 0)
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "Can't encrypt %lld: %s", plain, ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int encrypt(BIGNUM *c, const BIGNUM *m, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *r = BN_CTX_get(ctx);
    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);

    // 1. Let m be the message to be encrypted where m E Zn
    if (BN_cmp(m, key->n) >= 0)
    {
        fprintf(stderr, "Message not in Zn");
        goto end;
    }

    // 2. Select random r where r E Zn*
    do
    {
        if (!BN_rand(r, DEFAULT_KEY_LEN, 0, 0))
            goto end;
    }
    while (BN_is_zero(r));

    if (!BN_mod(r, r, key->n, ctx))
        goto end;

    // 3. Compute ciperthext as c = g^m*r^n mod n^2
    if (!BN_mod_exp(tmp1, key->g, m, key->n2, ctx))
        goto end;
    if (!BN_mod_exp(tmp2, r, key->n, key->n2, ctx))
        goto end;

    if (!BN_mod_mul(c, tmp1, tmp2, key->n2, ctx))
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "Error ecnrypting: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);

    return ret;
}

int decrypt(BIGNUM *plain, const BIGNUM *c, const privKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *tmp = BN_CTX_get(ctx);

    // 1. Let c be the ciphertext to decrypt, where c E Zn2
    if (!BN_cmp(c, key->n2) == 1)
    {
        fprintf(stderr, "Message provided not in Zn2");
        goto end;
    }

    // 2. Compute the plaintext message as: m = L(c^lamda mod n2)*mu mod n
    if (!BN_mod_exp(tmp, c, key->lamda, key->n2, ctx))
        goto end;
    if (L(tmp, tmp, key->n, ctx) != 0)
        goto end;
    if (!BN_mod_mul(plain, tmp, key->mu, key->n, ctx))
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "Can't decrypt: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}
int decryptll(long long *plain, const BIGNUM *c, const privKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);
    BIGNUM *plain_BN = BN_CTX_get(ctx);

    if (decrypt(plain_BN, c, key, ctx) != 0)
        goto end;

    *plain = BN_get_word(plain_BN);
    if (*plain == 0xffffffffL)
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "Can't decrypt: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int
sub(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX_start(ctx);

    BIGNUM *b_inv = BN_CTX_get(ctx);

    if (!BN_mod_inverse(b_inv, b, n2, ctx))
        goto end;

    if (!BN_mod_mul(result, a, b_inv, n2, ctx))
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "sub: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int
subEncPlainll(BIGNUM *result, const BIGNUM *enc, const long long plain, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *plain_enc = BN_CTX_get(ctx);

    if (encryptll(plain_enc, plain, key, ctx) != 0)
        goto end;

    if (sub(result, enc, plain_enc, key->n2, ctx) != 0)
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "subEncPlainll: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int
subEncPlain(BIGNUM *result, const BIGNUM *enc, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *plain_enc = BN_CTX_get(ctx);

    if (encrypt(plain_enc, plain, key, ctx) != 0)
        goto end;

    if (sub(result, enc, plain_enc, key->n2, ctx) != 0)
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "subEncPlain: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int
subllPlainEnc(BIGNUM *result, const long long plain, const BIGNUM *enc, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *plain_enc = BN_CTX_get(ctx);

    if (encryptll(plain_enc, plain, key, ctx) != 0)
        goto end;

    if (sub(result, plain_enc, enc, key->n2, ctx) != 0)
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "subllPlainEnc: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int
subPlainEnc(BIGNUM *result, const BIGNUM *plain, const BIGNUM *enc, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *plain_enc = BN_CTX_get(ctx);

    if (encrypt(plain_enc, plain, key, ctx) != 0)
        goto end;

    if (sub(result, plain_enc, enc, key->n2, ctx) != 0)
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "subPlainEnc: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}
int
add(BIGNUM *result, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n2, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *tmp1 = BN_CTX_get(ctx);

    if (!BN_mod_mul(tmp1, a, b, n2, ctx))
        goto end;

    BN_copy(result, tmp1);

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "add: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int
addEncPlainll(BIGNUM *result, const BIGNUM *enc, const long long plain, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *plain_enc = BN_CTX_get(ctx);

    if (encryptll(plain_enc, plain, key, ctx) != 0)
        goto end;

    if (add(result, enc, plain_enc, key->n2, ctx) != 0)
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "addEncPlainll: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int
addEncPlain(BIGNUM *result, const BIGNUM *enc, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;
    BN_CTX_start(ctx);

    BIGNUM *plain_enc = BN_CTX_get(ctx);

    if (encrypt(plain_enc, plain, key, ctx) != 0)
        goto end;

    if (add(result, enc, plain_enc, key->n2, ctx) != 0)
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "addEncPlain: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    BN_CTX_end(ctx);
    return ret;
}

int mulPlainll(BIGNUM *result, const BIGNUM *a, const long long plain, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;

    BN_CTX_start(ctx);
    BIGNUM *r = BN_CTX_get(ctx);

    if (!BN_set_word(r, plain))
        goto end;

    if (mulPlain(result, a, r, key, ctx) != 0)
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "mulPlainll: %s", ERR_error_string(ERR_get_error(), NULL));
    }
    BN_CTX_end(ctx);
    return ret;
}

int mulPlain(BIGNUM *result, const BIGNUM *a, const BIGNUM *plain, const pubKey *key, BN_CTX *ctx)
{
    int ret = 1;

    if (!BN_mod_exp(result, a, plain, key->n2, ctx))
        goto end;

    ret = 0;
end:
    if (ret)
    {
        ERR_load_crypto_strings();
        fprintf(stderr, "mulPlain: %s", ERR_error_string(ERR_get_error(), NULL));
    }

    return ret;
}

int dupKeys(paillierKeys *out, const paillierKeys *in)
{
    out->n2 = BN_dup(in->n2);
    out->n = BN_dup(in->n);

    out->pub.g = BN_dup(in->pub.g);
    out->pub.n = out->n;
    out->pub.n2 = out->n2;

    out->priv.lamda = BN_dup(in->priv.lamda);
    out->priv.mu = BN_dup(in->priv.mu);
    out->priv.n = out->n;
    out->priv.n2 = out->n2;

    return 0;
}