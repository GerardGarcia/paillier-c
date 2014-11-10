#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "paillier.h"

#define KEY_LEN 64
#define MAX_M_BITS 22

#define MAX_SUB_LEN MAX_M_BITS
#define SUB_CORRECTION_FACTOR MAX_M_BITS+1

#define MAX_MULT_FACTOR_LEN KEY_LEN - MAX_M_BITS -1

void BN_printf(BIGNUM *num) //This function is just for testing
{
        BIO *out = NULL;

        out = BIO_new(BIO_s_file());

        if (out == NULL)
                exit(1);

        BIO_set_fp(out, stdout, BIO_NOCLOSE);

        BN_print(out, num);
        printf("\n");

        BIO_free(out);
        CRYPTO_mem_leaks(out);
}

int main(int argc, char const *argv[])
{
        int ret = 1, len = 0;
        long long decrypted = 0;

        BN_CTX *ctx = BN_CTX_new();

        BIGNUM *random = BN_CTX_get(ctx);
        BIGNUM *encrypted_random = BN_CTX_get(ctx);
        BIGNUM *decrypted_random = BN_CTX_get(ctx);

        BIGNUM *random_op = BN_CTX_get(ctx);
        BIGNUM *random_op_sub = BN_CTX_get(ctx);

        BIGNUM *mul_factor = BN_CTX_get(ctx);
        BIGNUM *correction_factor = BN_CTX_get(ctx);

        BIGNUM *tmp_result = BN_CTX_get(ctx);
        BIGNUM *tmp2_result = BN_CTX_get(ctx);

        if (!BN_rand(random, MAX_M_BITS, 0, 0))
                goto end;

        paillierKeys keys;

        len = 2048;
        if ((ret = generateRandomKeys(&keys, &len, ctx)) != 0)
                goto end;

        printf("Random number: ");
        BN_printf(random);

        decrypted = 0;

        ///////////// Encryption test
        if (encrypt(encrypted_random, random, &keys.pub, ctx) != 0)
                goto end;
        if (decrypt(decrypted_random, encrypted_random, &keys.priv, ctx) != 0)
                goto end;

        printf("Decrypted: ");
        BN_printf(decrypted_random);

        if (BN_cmp(decrypted_random, random) == 0) {
                printf("Decrytpion OK!\n");
        } else {
                printf("Decrytpion ERROR!\n");
        }
        ///////////// OK!

        // Generate random number to be subtracted and added
        if (!BN_rand(random_op, MAX_SUB_LEN, 0, 0))
                goto end;

        // Set correction factor to avoid negative results
        if (!BN_rand(correction_factor, SUB_CORRECTION_FACTOR, 0, 0))
                goto end;

        printf("Sub/add var: ");
        BN_printf(random_op);

        ///////////// Subtraction test
        if (subEncPlain(tmp_result, encrypted_random, random_op, &keys.pub, ctx) != 0)
                goto end;

        /* Apply correction factor */
        if (addEncPlain(tmp_result, tmp_result, correction_factor, &keys.pub, ctx) != 0)
                goto end;
        /**/

        if (decrypt(tmp_result, tmp_result, &keys.priv, ctx) != 0)
                goto end;

        /* Revert correction factor*/
        if (!BN_sub(tmp2_result, tmp_result, correction_factor))
                goto end;
        /**/

        printf("Subtraction result: ");
        BN_printf(tmp2_result);

        if (!BN_sub(random_op_sub, decrypted_random, random_op))
                goto end;

        if (BN_cmp(tmp2_result, random_op_sub) == 0) {
                printf("Subtraction OK!\n");
        } else {
                printf("Subtraction ERROR!\n");
                printf("Expected result: ");
                BN_printf(random_op_sub);
        }
        /////////////


        ///////////// Addition test
        if (addEncPlain(tmp_result, encrypted_random, random_op, &keys.pub, ctx) != 0)
                goto end;

        if (decrypt(tmp_result, tmp_result, &keys.priv, ctx) != 0)
                goto end;

        printf("Addition result: ");
        BN_printf(tmp_result);

        if (!BN_add(tmp2_result, decrypted_random, random_op))
                goto end;

        if (BN_cmp(tmp_result, tmp2_result) == 0 ) {
                printf("Addition OK!\n");
        } else {
                printf("Addition ERROR!\n");
                printf("Expected result: ");
                BN_printf(tmp2_result);
        }
        /////////////

        ///////////// Multi. test
        if (!BN_rand(mul_factor, MAX_MULT_FACTOR_LEN, 0, 0))
                goto end;

        printf("Mult. factor: ");
        BN_printf(mul_factor);

        if (mulPlain(tmp_result, encrypted_random, mul_factor, &keys.pub, ctx) != 0)
                goto end;

        if (decrypt(tmp_result, tmp_result, &keys.priv, ctx) != 0)
                goto end;

        printf("Mutliplication result: ");
        BN_printf(tmp_result);

        if (!BN_mul(tmp2_result, decrypted_random, mul_factor, ctx))
                goto end;

        if (BN_cmp(tmp_result, tmp2_result) == 0) {
                printf("Mutliplication OK!\n");
        } else {
                printf("Mutliplication ERROR!\n");
                printf("Expected result: ");
                BN_printf(tmp2_result);
        }
        /////////////

        ret = 0;
end:
        if (ret){
                printf("ERROR!\n");
                ERR_load_crypto_strings();
                fprintf(stderr, "main: %s", ERR_error_string(ERR_get_error(), NULL));
        }
 
         return ret;
}