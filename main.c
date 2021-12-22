#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "des.h"



/*
 * DES and 3DES test vectors from:
 *
 * http://csrc.nist.gov/groups/STM/cavp/documents/des/tripledes-vectors.zip
 */
static const unsigned char des3_test_keys[24] =
{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
    0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
};

static const unsigned char des3_test_buf[8] =
{
    0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74
};

static const unsigned char des3_test_ecb_dec[3][8] =
{
    { 0x37, 0x2B, 0x98, 0xBF, 0x52, 0x65, 0xB0, 0x59 },
    { 0xC2, 0x10, 0x19, 0x9C, 0x38, 0x5A, 0x65, 0xA1 },
    { 0xA2, 0x70, 0x56, 0x68, 0x69, 0xE5, 0x15, 0x1D }
};

static const unsigned char des3_test_ecb_enc[3][8] =
{
    { 0x1C, 0xD5, 0x97, 0xEA, 0x84, 0x26, 0x73, 0xFB },
    { 0xB3, 0x92, 0x4D, 0xF3, 0xC5, 0xB5, 0x42, 0x93 },
    { 0xDA, 0x37, 0x64, 0x41, 0xBA, 0x6F, 0x62, 0x6F }
};

static const unsigned char des3_test_iv[8] =
{
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
};

static const unsigned char des3_test_cbc_dec[3][8] =
{
    { 0x58, 0xD9, 0x48, 0xEF, 0x85, 0x14, 0x65, 0x9A },
    { 0x5F, 0xC8, 0x78, 0xD4, 0xD7, 0x92, 0xD9, 0x54 },
    { 0x25, 0xF9, 0x75, 0x85, 0xA8, 0x1E, 0x48, 0xBF }
};

static const unsigned char des3_test_cbc_enc[3][8] =
{
    { 0x91, 0x1C, 0x6D, 0xCF, 0x48, 0xA7, 0xC3, 0x4D },
    { 0x60, 0x1A, 0x76, 0x8F, 0xA1, 0xF9, 0x66, 0xF1 },
    { 0xA1, 0x50, 0x0F, 0x99, 0xB2, 0xCD, 0x64, 0x76 }
};

/*
 * Checkup routine
 */
int main(void)
{
    int i, j, u, v, ret = 0;
    mbedtls_des_context ctx;
    mbedtls_des3_context ctx3;
    unsigned char buf[8];
    unsigned char prv[8];
    unsigned char iv[8];

    mbedtls_des_init( &ctx );
    mbedtls_des3_init( &ctx3 );
    /*
     * ECB mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        printf( "  DES%c-ECB-%3d (%s): ",
                         ( u == 0 ) ? ' ' : '3', 56 + u * 56,
                         ( v == MBEDTLS_DES_DECRYPT ) ? "dec" : "enc" );

        memcpy( buf, des3_test_buf, 8 );

        switch( i )
        {
        case 0:
            mbedtls_des_setkey_dec( &ctx, des3_test_keys );
            break;

        case 1:
            mbedtls_des_setkey_enc( &ctx, des3_test_keys );
            break;

        case 2:
            mbedtls_des3_set2key_dec( &ctx3, des3_test_keys );
            break;

        case 3:
            mbedtls_des3_set2key_enc( &ctx3, des3_test_keys );
            break;

        case 4:
            mbedtls_des3_set3key_dec( &ctx3, des3_test_keys );
            break;

        case 5:
            mbedtls_des3_set3key_enc( &ctx3, des3_test_keys );
            break;

        default:
            return( 1 );
        }

        for( j = 0; j < 100; j++ )
        {
            if( u == 0 )
                mbedtls_des_crypt_ecb( &ctx, buf, buf );
            else
                mbedtls_des3_crypt_ecb( &ctx3, buf, buf );
        }

        if( ( v == MBEDTLS_DES_DECRYPT &&
                memcmp( buf, des3_test_ecb_dec[u], 8 ) != 0 ) ||
            ( v != MBEDTLS_DES_DECRYPT &&
                memcmp( buf, des3_test_ecb_enc[u], 8 ) != 0 ) )
        {
            printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        printf( "passed\n" );
    }

    printf( "\n" );

    /*
     * CBC mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        printf( "  DES%c-CBC-%3d (%s): ",
                             ( u == 0 ) ? ' ' : '3', 56 + u * 56,
                             ( v == MBEDTLS_DES_DECRYPT ) ? "dec" : "enc" );

        memcpy( iv,  des3_test_iv,  8 );
        memcpy( prv, des3_test_iv,  8 );
        memcpy( buf, des3_test_buf, 8 );

        switch( i )
        {
        case 0:
            mbedtls_des_setkey_dec( &ctx, des3_test_keys );
            break;

        case 1:
            mbedtls_des_setkey_enc( &ctx, des3_test_keys );
            break;

        case 2:
            mbedtls_des3_set2key_dec( &ctx3, des3_test_keys );
            break;

        case 3:
            mbedtls_des3_set2key_enc( &ctx3, des3_test_keys );
            break;

        case 4:
            mbedtls_des3_set3key_dec( &ctx3, des3_test_keys );
            break;

        case 5:
            mbedtls_des3_set3key_enc( &ctx3, des3_test_keys );
            break;

        default:
            return( 1 );
        }

        if( v == MBEDTLS_DES_DECRYPT )
        {
            for( j = 0; j < 100; j++ )
            {
                if( u == 0 )
                    mbedtls_des_crypt_cbc( &ctx, v, 8, iv, buf, buf );
                else
                    mbedtls_des3_crypt_cbc( &ctx3, v, 8, iv, buf, buf );
            }
        }
        else
        {
            for( j = 0; j < 100; j++ )
            {
                unsigned char tmp[8];

                if( u == 0 )
                    mbedtls_des_crypt_cbc( &ctx, v, 8, iv, buf, buf );
                else
                    mbedtls_des3_crypt_cbc( &ctx3, v, 8, iv, buf, buf );

                memcpy( tmp, prv, 8 );
                memcpy( prv, buf, 8 );
                memcpy( buf, tmp, 8 );
            }

            memcpy( buf, prv, 8 );
        }

        if( ( v == MBEDTLS_DES_DECRYPT &&
                memcmp( buf, des3_test_cbc_dec[u], 8 ) != 0 ) ||
            ( v != MBEDTLS_DES_DECRYPT &&
                memcmp( buf, des3_test_cbc_enc[u], 8 ) != 0 ) )
        {
            printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        printf( "passed\n" );
    }

    printf( "\n" );

exit:

    return( ret );
}

