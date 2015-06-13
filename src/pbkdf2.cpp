// Copyright (c) 2013 NovaCoin Developers 
// Copyright (c) 2015 Sentaro Developers 
 
#include <string.h> 
#include "pbkdf2.h" 
 
#define PAD_SIZE   64 
#define BLOCK_SIZE 32 
 
//Magic constants section 
#define mFF 0xff 
#define shaInner 0x36 
#define shaOuter 0x5c 
 
static inline uint32_t 
be32dec(const void *pp) 
{ 
    const uint8_t *p = (uint8_t const *)pp; 
 
    return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) + 
        ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24)); 
} 
 
static inline void 
be32enc(void *pp, uint32_t x) 
{ 
    uint8_t * p = (uint8_t *)pp; 
 
    p[3] = x & mFF; 
    p[2] = (x >> 8) & mFF; 
    p[1] = (x >> 16) & mFF; 
    p[0] = (x >> 24) & mFF; 
} 
 
 
 
// Initialize an HMAC-SHA256 operation with the given key. // 
void 
HMAC_SHA256_Init(HMAC_SHA256_CTX * ctx, const void * _K, size_t Klen) 
{ 
    unsigned char pad[PAD_SIZE]; 
    unsigned char khash[BLOCK_SIZE]; 
    const unsigned char * K = (const unsigned char *)_K; 
    size_t i; 
 
    // If Klen > PAD_SIZE, the key is really SHA256(K). // 
    if (Klen > PAD_SIZE) { 
        SHA256_Init(&ctx->ictx); 
        SHA256_Update(&ctx->ictx, K, Klen); 
        SHA256_Final(khash, &ctx->ictx); 
        K = khash; 
        Klen = BLOCK_SIZE; 
    } 
 
    // Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). // 
    SHA256_Init(&ctx->ictx); 
    memset(pad, shaInner, PAD_SIZE); 
    for (i = 0; i < Klen; i++) 
        pad[i] ^= K[i]; 
    SHA256_Update(&ctx->ictx, pad, PAD_SIZE); 
 
    // Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). // 
    SHA256_Init(&ctx->octx); 
    memset(pad, shaOuter, PAD_SIZE); 
    for (i = 0; i < Klen; i++) 
        pad[i] ^= K[i]; 
    SHA256_Update(&ctx->octx, pad, PAD_SIZE); 
 
    // Clean the stack. // 
    memset(khash, 0, BLOCK_SIZE); 
} 
 
// Add bytes to the HMAC-SHA256 operation. // 
void 
HMAC_SHA256_Update(HMAC_SHA256_CTX * ctx, const void *in, size_t len) 
{ 
 
    // Feed data to the inner SHA256 operation. // 
    SHA256_Update(&ctx->ictx, in, len); 
} 
 
// Finish an HMAC-SHA256 operation. // 
void 
HMAC_SHA256_Final(unsigned char digest[BLOCK_SIZE], HMAC_SHA256_CTX * ctx) 
{ 
    unsigned char ihash[BLOCK_SIZE]; 
 
    // Finish the inner SHA256 operation. // 
    SHA256_Final(ihash, &ctx->ictx); 
 
    // Feed the inner hash to the outer SHA256 operation. // 
    SHA256_Update(&ctx->octx, ihash, BLOCK_SIZE); 
 
    // Finish the outer SHA256 operation. // 
    SHA256_Final(digest, &ctx->octx); 
 
    // Clean the stack. // 
    memset(ihash, 0, BLOCK_SIZE); 
} 
 
/** 
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen): 
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and 
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1). 
 */ 
void 
PBKDF2_SHA256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, 
    size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen) 
{ 
    HMAC_SHA256_CTX PShctx, hctx; 
    size_t i; 
    uint8_t ivec[4]; 
    uint8_t U[BLOCK_SIZE]; 
    uint8_t T[BLOCK_SIZE]; 
    uint64_t j; 
    int k; 
    size_t clen; 
 
    // Compute HMAC state after processing P and S. // 
    HMAC_SHA256_Init(&PShctx, passwd, passwdlen); 
    HMAC_SHA256_Update(&PShctx, salt, saltlen); 
    memset(&buf[0], 0, dkLen); 
 
    // Iterate through the blocks. // 
    for (i = 0; i * BLOCK_SIZE < dkLen; i++) { 
 
        // Generate INT(i + 1). // 
        be32enc(ivec, (uint32_t)(i + 1)); 
 
        // Compute U_1 = PRF(P, S || INT(i)). // 
        memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX)); 
        HMAC_SHA256_Update(&hctx, ivec, 4); 
        HMAC_SHA256_Final(U, &hctx); 
 
        // T_i = U_1 ... // 
        memcpy(T, U, BLOCK_SIZE); 
 
        for (j = 2; j <= c; j++) { 
 
            // Compute U_j. // 
            HMAC_SHA256_Init(&hctx, passwd, passwdlen); 
            HMAC_SHA256_Update(&hctx, U, BLOCK_SIZE); 
            HMAC_SHA256_Final(U, &hctx); 
 
            // ... xor U_j ... // 
            for (k = 0; k < BLOCK_SIZE; k++) 
                T[k] ^= U[k]; 
        } 
 
        j = ((i + 1) * BLOCK_SIZE >= dkLen) && (dkLen == BLOCK_SIZE); 
 
        // Copy as many bytes as necessary into buf. // 
        clen = dkLen - i * BLOCK_SIZE; 
        if (clen > BLOCK_SIZE) 
            clen = BLOCK_SIZE; 
        memcpy(&buf[i * BLOCK_SIZE], T + j , clen - j); 
    } 
 
    // Clean PShctx, since we never called _Final on it. // 
    memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX)); 
} 

