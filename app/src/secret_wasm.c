/*******************************************************************************
*   (c) 2023 Solar Republic LLC
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <string.h>
#include "utf8.h"
#include "os_math.h"
#include "lcx_aes.h"
#include "zxmacros.h"
#include "base64/base64_decoder.h"
#include "secret_wasm.h"

void xor_buffers(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        out[i] = a[i] ^ b[i];
    }
}

void double_block(uint8_t *block) {
    uint8_t carry = block[0] & 0x80;

    for (size_t i=0; i<AES_BLOCK_SIZE-1; ++i) {
        block[i] = (block[i] << 1) | (block[i + 1] >> 7);
    }
    block[AES_BLOCK_SIZE-1] <<= 1;

    if (carry) block[AES_BLOCK_SIZE-1] ^= 0x87;
}

void padding(const uint8_t *data, size_t data_len, uint8_t out[AES_BLOCK_SIZE]) {
    memmove(out, data, data_len);

    if (data_len < AES_BLOCK_SIZE) {
        // set high bit
        out[data_len] = 0x80;

        // pad remainder
        memset(out + data_len + 1, 0, AES_BLOCK_SIZE - data_len - 1);
    }
}


parser_error_t aes_cmac(cmac_context_t cmac, const uint8_t *data, size_t data_len, uint8_t buffer[AES_BLOCK_SIZE], uint8_t *s_end) {
    // allocate new buffer so as not to mutate data
    uint8_t m_last[AES_BLOCK_SIZE];

    // cache num blocks
    size_t num_blocks = (data_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    // last block (either given as arg or taken from data)
    const uint8_t *block_data = s_end != NULL? s_end: data + (((num_blocks? num_blocks: 1) - 1) * AES_BLOCK_SIZE);

    // last block requires padding
    size_t last_block_size = data_len % AES_BLOCK_SIZE;
    if (last_block_size != 0 || num_blocks == 0) {
        // padding(M_n)
        padding(block_data, last_block_size, buffer);

        // xor with k2
        xor_buffers(buffer, cmac.k2, m_last, AES_BLOCK_SIZE);
    }
    // no padding needed; xor with k1
    else {
        // M_last := M_n XOR K1
        xor_buffers(block_data, cmac.k1, m_last, AES_BLOCK_SIZE);
    }

    // X := const_Zero
    memset(buffer, 0, AES_BLOCK_SIZE);

    // for i := 1 to n-1
    if(num_blocks) {
        for (size_t block_idx = 0; block_idx<num_blocks-1; block_idx++) {
            // Y := X XOR M_i
            xor_buffers(buffer, data + (block_idx * AES_BLOCK_SIZE), buffer, AES_BLOCK_SIZE);

            // X := AES-128(K,Y)
            cx_aes(cmac.mac_key, CX_ENCRYPT, buffer, AES_BLOCK_SIZE, buffer, AES_BLOCK_SIZE);
        }
    }

    // Y := M_last XOR X (args commuted)
    xor_buffers(buffer, m_last, buffer, AES_BLOCK_SIZE);

    // T := AES-128(K,Y)
    cx_aes(cmac.mac_key, CX_ENCRYPT, buffer, AES_BLOCK_SIZE, buffer, AES_BLOCK_SIZE);

    return parser_ok;
}

__Z_INLINE int aes_s2v(const uint8_t *mac_rkd, const uint8_t *plaintext, size_t ciphertext_len, uint8_t *cmac) {
    cx_aes_key_t mac_key;
    cx_err_t aes_err = cx_aes_init_key_no_throw(mac_rkd, AES_SIV_SUBKEY_LEN, &mac_key);
    if (aes_err != CX_OK) {
        return parser_aes_init_error;
    }

    // k1 subkey generation
    uint8_t k1[AES_BLOCK_SIZE];

    // L := AES-128(K, const_Zero)
    cx_aes(&mac_key, CX_ENCRYPT, zero_block, AES_BLOCK_SIZE, k1, AES_BLOCK_SIZE);

    // K1 := L << 1  or  K1 := (L << 1) XOR const_Rb
    double_block(k1);

    // k2 subkey generation
    uint8_t k2[AES_BLOCK_SIZE];
    memcpy(k2, k1, AES_BLOCK_SIZE);

    // K2 := K1 << 1  or  K2 := (K2 << 1) XOR const_Rb
    double_block(k2);

    // prep cmac context
    cmac_context_t cmac_ctx = {&mac_key, k1, k2};

    // D = AES-CMAC(K, <zero>)
    aes_cmac(cmac_ctx, zero_block, AES_BLOCK_SIZE, cmac, NULL);

    // secret network associated data
    {
        // ANS_1 = dbl(D)
        double_block(cmac);

        // secret network associated data
        uint8_t ad[0];

        // ANS_2 = AES-CMAC(K, Si)
        uint8_t block[AES_BLOCK_SIZE];
        aes_cmac(cmac_ctx, ad, 0, block, NULL);

        // D = {ANS_1} xor {ANS_2}
        xor_buffers(cmac, block, cmac, AES_BLOCK_SIZE);
    }

    // rather than modifying plaintext directly, store last block data separately
    uint8_t s_end[AES_BLOCK_SIZE];

    // if len(Sn) >= 128
    if (ciphertext_len >= AES_BLOCK_SIZE) {
        // T = Sn xorend D
        xor_buffers(plaintext + ciphertext_len - AES_BLOCK_SIZE, cmac, s_end, AES_BLOCK_SIZE);
    }
    // T = dbl(D) xor pad(Sn)
    else {
        // dbl(D)
        double_block(cmac);
        uint8_t padded[AES_BLOCK_SIZE];
        padding(plaintext, ciphertext_len, padded);
        xor_buffers(padded, cmac, cmac, AES_BLOCK_SIZE);

        // keep last block as-is
        memcpy(s_end, plaintext + ciphertext_len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }

    // V = AES-CMAC(K, T)
    aes_cmac(cmac_ctx, plaintext, ciphertext_len, cmac, s_end);

    return parser_ok;
}

__Z_INLINE void increment_uint128_be(uint8_t *block) {
    for (int i = AES_BLOCK_SIZE-1; i >= 0; --i) {
        block[i]++;
        if (block[i] != 0) break;
    }
}

parser_error_t aes_siv_open(
    const uint8_t *keys,
    size_t keys_len,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out,
    // unint16_t out_offset,
    uint16_t *out_len
) {
    // AES-128 only
    if (keys_len != 32) {
        return parser_invalid_tek_data;
    }

    // write plaintext directly to output
    uint8_t *plaintext = (uint8_t *)out;

    // extract the keys
    const uint8_t *mac_rkd = keys;
    const uint8_t *ctr_rkd = keys + AES_SIV_SUBKEY_LEN;

    // init ctr key
    cx_aes_key_t ctr_key;
    cx_err_t aes_err = cx_aes_init_key_no_throw(ctr_rkd, AES_SIV_SUBKEY_LEN, &ctr_key);
    if (aes_err != CX_OK) return parser_aes_init_error;

    // no data
    if (payload_len < AES_BLOCK_SIZE) return parser_invalid_msg_contents;

    // extract tag from payload
    const uint8_t *tag = (const uint8_t *)payload;

    // extract ciphertext from payload
    size_t ciphertext_len = payload_len - AES_BLOCK_SIZE;
    const uint8_t *text = payload + AES_BLOCK_SIZE;

    // nothing to decrypt
    if (!ciphertext_len) {
        *out_len = 0;
        return parser_ok;
    }

    // init iv using tag
    uint8_t ctr_iv[AES_BLOCK_SIZE];
    memcpy(ctr_iv, tag, AES_BLOCK_SIZE);

    // zero out top bits in last 32-bit words of iv
    ctr_iv[AES_BLOCK_SIZE - 8] &= 0x7f;
    ctr_iv[AES_BLOCK_SIZE - 4] &= 0x7f;

    // compute num blocks
    size_t num_blocks = (ciphertext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    // prep block buffer
    uint8_t block_data[AES_BLOCK_SIZE];

    // decrypt in place
    uint8_t *readwrite = text;

    // decrypt blocks using AES-CTR
    for (uint16_t block_idx = 0; block_idx < num_blocks; block_idx++) {
        // encrypt next ctr (Ledger's cx_aes_no_throw crashes the app)
        cx_aes(&ctr_key, CX_ENCRYPT, ctr_iv, AES_BLOCK_SIZE, block_data, AES_BLOCK_SIZE);

        // update counter
        increment_uint128_be(ctr_iv);

        // compute intrinsic size of block
        bool_t last_block = block_idx == num_blocks - 1;
        size_t block_len = AES_BLOCK_SIZE;
        if (last_block) {
            block_len = ciphertext_len % AES_BLOCK_SIZE;
            if (0 == block_len) block_len = AES_BLOCK_SIZE;
        }

        // decrypt the block
        xor_buffers(readwrite, block_data, readwrite, block_len);

        // advance pointer
        readwrite += block_len;
    }

    // perform s2v to compute auth tag
    uint8_t cmac[AES_BLOCK_SIZE];
    aes_s2v(mac_rkd, text, ciphertext_len, cmac);

    // check that the computed mac matches the provided tag
    if (memcmp(cmac, tag, AES_BLOCK_SIZE) != 0) {
        memset(plaintext, 0, ciphertext_len);
        return parser_invalid_tek_data;
    }

    // set output length
    *out_len = MIN(ciphertext_len, readwrite - plaintext);

    // make sure not to exceed the bounds of the output buffer
    memmove(out, text, *out_len);

    return parser_ok;
}

parser_error_t decrypt_secret_wasm_msg(uint8_t *in, uint16_t in_len, uint8_t *out, uint16_t *out_len) {
    // determine max size needed for base64 decoded data and prepare a VLA
    uint16_t max_len = BASE64_DECODED_LEN(in_len);
    uint8_t imperative_buffer[*out_len >= max_len? 0: max_len];

    // attempt to use output as a buffer for intermediate data; use imperative buffer as fallback
    uint8_t *decoded = out;
    if (max_len > out_len) decoded = imperative_buffer;

    // set maximum amount of space available to use in buffer; then get actual used
    uint16_t decoded_len = *out_len;

    // base64 decode the string
    int decode_error = base64_decode(
        in,
        in_len,
        decoded,
        &decoded_len
    );

    // invalid base64
    if (decode_error != 0) return parser_invalid_msg_contents;

    // missing data
    if (decoded_len < MSG_PREAMBLE_LEN) return parser_invalid_msg_contents;

    // skip preamble to get to payload
    uint16_t payload_len = decoded_len - MSG_PREAMBLE_LEN;
    uint8_t *payload = (uint8_t *)decoded + MSG_PREAMBLE_LEN;

    // reuse the same buffer to conserve memory; overlap w/ ciphertext is tolerated
    uint8_t *plaintext = decoded;
    uint16_t plaintext_len;

    // attempt to decrypt the payload
    parser_error_t decrypt_error = aes_siv_open(
        parser_tx_obj.tek_data,
        parser_tx_obj.tek_k,
        payload,
        payload_len,
        plaintext,
        &plaintext_len
    );

    if (decrypt_error != CX_OK) return decrypt_error;

    // replace codepoints outside the ASCII range with a single character
    uint8_t *write = plaintext;
    uint8_t *read = plaintext + CODE_HASH_LEN;  // skip code hash
    while (read < plaintext + plaintext_len && *read != '\0') {
        utf8_int32_t codepoint;
        read = (uint8_t *)utf8codepoint((const char *)read, &codepoint);

        // write to buffer, replacing extended character with ASCII
        *write++ = codepoint > 0x7f? '+': (char)codepoint;
    }

    // trim end of string
    while (write > plaintext && (*write == ' ' || *write == '\0')) {
        *write-- = '\0';
    }

    // write final length
    *out_len = write - plaintext;

    return parser_ok;
}
