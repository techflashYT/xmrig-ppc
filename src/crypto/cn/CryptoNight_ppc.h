/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2019 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2018-2020 SChernykh   <https://github.com/SChernykh>
 * Copyright 2016-2020 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 * Copyright 2024      Techflash   <officialTechflashYT@gmail.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *   This file is a set of stubs to CryptoNight on PowerPC.
 *   It contains no real functionality, but does get it to compile.
 */

#ifndef XMRIG_CRYPTONIGHT_PPC_H
#define XMRIG_CRYPTONIGHT_PPC_H


#include "backend/cpu/Cpu.h"
#include "base/crypto/keccak.h"
#include "crypto/cn/CnAlgo.h"
#include "crypto/cn/CryptoNight_monero.h"
#include "crypto/cn/CryptoNight.h"

extern "C"
{
#include "crypto/cn/c_groestl.h"
#include "crypto/cn/c_blake256.h"
#include "crypto/cn/c_jh.h"
#include "crypto/cn/c_skein.h"
}


static inline void do_blake_hash(const uint8_t *input, size_t len, uint8_t *output) {
    blake256_hash(output, input, len);
}


static inline void do_groestl_hash(const uint8_t *input, size_t len, uint8_t *output) {
    groestl(input, len * 8, output);
}


static inline void do_jh_hash(const uint8_t *input, size_t len, uint8_t *output) {
    jh_hash(32 * 8, input, 8 * len, output);
}


static inline void do_skein_hash(const uint8_t *input, size_t len, uint8_t *output) {
    xmr_skein(input, output);
}


void (* const extra_hashes[4])(const uint8_t *, size_t, uint8_t *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};

namespace xmrig {

template<Algorithm::Id ALGO, bool SOFT_AES, int interleave>
static NOINLINE void cn_explode_scratchpad(cryptonight_ctx *ctx)
{
}


template<Algorithm::Id ALGO, bool SOFT_AES, int interleave>
static NOINLINE void cn_implode_scratchpad(cryptonight_ctx *ctx)
{
}


} /* namespace xmrig */


void v4_soft_aes_compile_code(const V4_Instruction *code, int code_size, void *machine_code, xmrig::Assembly ASM);


alignas(64) static const uint32_t tweak1_table[256] = { 268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,268435456,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,805306368,0,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456,805306368,268435456 };

namespace xmrig {

template<Algorithm::Id ALGO, bool SOFT_AES, int interleave>
inline void cryptonight_single_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height)
{
    // XXX: ppc-stub - this is probably necessary.
}


template<Algorithm::Id ALGO, bool SOFT_AES>
inline void cryptonight_double_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height)
{
    // XXX: ppc-stub - this is probably necessary.
}

} /* namespace xmrig */

#define CN_STEP1(a, b0, b1, c, l, ptr, idx, conc_var) \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    c = _mm_load_si128(ptr);                          \
    if (ALGO == Algorithm::CN_CCX) {                  \
        cryptonight_conceal_tweak(c, conc_var);       \
    }



#define CN_STEP2(a, b0, b1, c, l, ptr, idx)                                             \
    if (IS_CN_HEAVY_TUBE) {                                                             \
        c = aes_round_tweak_div(c, a);                                                  \
    }                                                                                   \
    else if (SOFT_AES) {                                                                \
        c = soft_aesenc(&c, a, (const uint32_t*)saes_table);                            \
    } else {                                                                            \
        c = _mm_aesenc_si128(c, a);                                                     \
    }                                                                                   \
                                                                                        \
    if (BASE == Algorithm::CN_1 || BASE == Algorithm::CN_2) {                           \
        cryptonight_monero_tweak<ALGO>((uint64_t*)ptr, l, idx & MASK, a, b0, b1, c);    \
    } else {                                                                            \
        _mm_store_si128(ptr, _mm_xor_si128(b0, c));                                     \
    }


#define CN_STEP3(part, a, b0, b1, c, l, ptr, idx)     \
    idx = _mm_cvtsi128_si64(c);                       \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    uint64_t cl##part = ((uint64_t*)ptr)[0];          \
    uint64_t ch##part = ((uint64_t*)ptr)[1];


#define CN_STEP4(part, a, b0, b1, c, l, mc, ptr, idx)                                                       \
    uint64_t al##part, ah##part;                                                                            \
    if (BASE == Algorithm::CN_2) {                                                                          \
        if (props.isR()) {                                                                                  \
            al##part = _mm_cvtsi128_si64(a);                                                                \
            ah##part = _mm_cvtsi128_si64(_mm_srli_si128(a, 8));                                             \
            VARIANT4_RANDOM_MATH(part, al##part, ah##part, cl##part, b0, b1);                               \
            if (ALGO == Algorithm::CN_R) {                                                                  \
                al##part ^= r##part[2] | ((uint64_t)(r##part[3]) << 32);                                    \
                ah##part ^= r##part[0] | ((uint64_t)(r##part[1]) << 32);                                    \
            }                                                                                               \
        } else {                                                                                            \
            VARIANT2_INTEGER_MATH(part, cl##part, c);                                                       \
        }                                                                                                   \
    }                                                                                                       \
    lo = __umul128(idx, cl##part, &hi);                                                                     \
    if (BASE == Algorithm::CN_2) {                                                                          \
        if (ALGO == Algorithm::CN_R) {                                                                      \
            VARIANT2_SHUFFLE(l, idx & MASK, a, b0, b1, c, 0);                                               \
        } else {                                                                                            \
            VARIANT2_SHUFFLE2(l, idx & MASK, a, b0, b1, hi, lo, (((ALGO == Algorithm::CN_RWZ) || (ALGO == Algorithm::CN_UPX2)) ? 1 : 0)); \
        }                                                                                                   \
    }                                                                                                       \
    if (ALGO == Algorithm::CN_R) {                                                                          \
        a = _mm_set_epi64x(ah##part, al##part);                                                             \
    }                                                                                                       \
    a = _mm_add_epi64(a, _mm_set_epi64x(lo, hi));                                                           \
                                                                                                            \
    if (BASE == Algorithm::CN_1) {                                                                          \
        _mm_store_si128(ptr, _mm_xor_si128(a, mc));                                                         \
                                                                                                            \
        if (IS_CN_HEAVY_TUBE || ALGO == Algorithm::CN_RTO) {                                                \
            ((uint64_t*)ptr)[1] ^= ((uint64_t*)ptr)[0];                                                     \
        }                                                                                                   \
    } else {                                                                                                \
        _mm_store_si128(ptr, a);                                                                            \
    }                                                                                                       \
                                                                                                            \
    a = _mm_xor_si128(a, _mm_set_epi64x(ch##part, cl##part));                                               \
    idx = _mm_cvtsi128_si64(a);                                                                             \
    if (props.isHeavy()) {                                                                                  \
        int64_t n = ((int64_t*)&l[idx & MASK])[0];                                                          \
        int32_t d = ((int32_t*)&l[idx & MASK])[2];                                                          \
        int64_t q = n / (d | 0x5);                                                                          \
        ((int64_t*)&l[idx & MASK])[0] = n ^ q;                                                              \
        if (IS_CN_HEAVY_XHV) {                                                                              \
            d = ~d;                                                                                         \
        }                                                                                                   \
                                                                                                            \
        idx = d ^ q;                                                                                        \
    }                                                                                                       \
    if (BASE == Algorithm::CN_2) {                                                                          \
        b1 = b0;                                                                                            \
    }                                                                                                       \
    b0 = c;


#define CONST_INIT(ctx, n)                                                                       \
    __m128i mc##n;                                                                               \
    __m128i division_result_xmm_##n;                                                             \
    __m128i sqrt_result_xmm_##n;                                                                 \
    if (BASE == Algorithm::CN_1) {                                                               \
        mc##n = _mm_set_epi64x(*reinterpret_cast<const uint64_t*>(input + n * size + 35) ^       \
                               *(reinterpret_cast<const uint64_t*>((ctx)->state) + 24), 0);      \
    }                                                                                            \
    if (BASE == Algorithm::CN_2) {                                                               \
        division_result_xmm_##n = _mm_cvtsi64_si128(h##n[12]);                                   \
        sqrt_result_xmm_##n = _mm_cvtsi64_si128(h##n[13]);                                       \
    }                                                                                            \
    __m128i ax##n = _mm_set_epi64x(h##n[1] ^ h##n[5], h##n[0] ^ h##n[4]);                        \
    __m128i bx##n##0 = _mm_set_epi64x(h##n[3] ^ h##n[7], h##n[2] ^ h##n[6]);                     \
    __m128i bx##n##1 = _mm_set_epi64x(h##n[9] ^ h##n[11], h##n[8] ^ h##n[10]);                   \
    __m128i cx##n = _mm_setzero_si128();                                                         \
    __m128 conc_var##n;                                                                          \
    if (ALGO == Algorithm::CN_CCX) {                                                             \
        conc_var##n = _mm_setzero_ps();                                                          \
    }                                                                                            \
    VARIANT4_RANDOM_MATH_INIT(n);

namespace xmrig {

template<Algorithm::Id ALGO, bool SOFT_AES>
inline void cryptonight_triple_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height)
{
    // XXX: ppc-stub - this is probably necessary.
}


template<Algorithm::Id ALGO, bool SOFT_AES>
inline void cryptonight_quad_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height)
{
    // XXX: ppc-stub - this is probably necessary.
}


template<Algorithm::Id ALGO, bool SOFT_AES>
inline void cryptonight_penta_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height)
{
    // XXX: ppc-stub - this is probably necessary.
}


} /* namespace xmrig */


#endif /* XMRIG_CRYPTONIGHT_PPC_H */
