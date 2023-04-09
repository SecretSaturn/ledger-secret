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
    memcpy(out, data, data_len);

    if (data_len < AES_BLOCK_SIZE) {
        // set high bit
        out[data_len] = 0x80;

        // pad remainder
        memset(out + data_len + 1, 0, AES_BLOCK_SIZE - data_len - 1);
    }
}

parser_error_t aes_cmac(const uint8_t *key, size_t keylen, const uint8_t *data, size_t data_len, uint8_t buffer[AES_BLOCK_SIZE]) {
    cx_aes_key_t mac_key;
    cx_err_t aes_err = cx_aes_init_key_no_throw(key, keylen, &mac_key);
    if (aes_err != CX_OK) {
        return parser_aes_init_error;
    }

    // k1 subkey generation
    uint8_t k1[AES_BLOCK_SIZE];

    uint8_t zero_block[AES_BLOCK_SIZE] = {0};
    cx_aes(&mac_key, CX_ENCRYPT, zero_block, AES_BLOCK_SIZE, k1, AES_BLOCK_SIZE);
    double_block(k1);

    // k2 subkey generation
    uint8_t k2[AES_BLOCK_SIZE];
    memcpy(k2, k1, AES_BLOCK_SIZE);
    double_block(k2);
    
    // allocate new buffer so as not to mutate data
    uint8_t m_last[AES_BLOCK_SIZE];

    // cache num blocks
    size_t num_blocks = (data_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    // last block
    const uint8_t *block_data = data + ((num_blocks - 1) * AES_BLOCK_SIZE);

    // last block requires padding
    size_t last_block_size = data_len % AES_BLOCK_SIZE;
    if (last_block_size != 0) {
        // padding(M_n)
        padding(block_data, last_block_size, buffer);

        // xor with k2
        xor_buffers(buffer, k2, m_last, AES_BLOCK_SIZE);
    }
    // no padding needed; xor with k1
    else {
        // M_last := M_n XOR K1
        xor_buffers(block_data, k1, m_last, AES_BLOCK_SIZE);
    }

    // X := const_Zero
    memset(buffer, 0, AES_BLOCK_SIZE);

    // for i := 1 to n-1
    for (size_t block_idx = 0; block_idx<num_blocks-1; block_idx++) {
        // Y := X XOR M_i
        xor_buffers(buffer, data + (block_idx * AES_BLOCK_SIZE), buffer, AES_BLOCK_SIZE);

        // X := AES-128(K,Y)
        cx_aes(&mac_key, CX_ENCRYPT, buffer, AES_BLOCK_SIZE, buffer, AES_BLOCK_SIZE);
    }

    // Y := M_last XOR X (args commuted)
    xor_buffers(buffer, m_last, buffer, AES_BLOCK_SIZE);

    // T := AES-128(K,Y)
    cx_aes(&mac_key, CX_ENCRYPT, buffer, AES_BLOCK_SIZE, buffer, AES_BLOCK_SIZE);

    return parser_ok;
}

__Z_INLINE int aes_s2v(const uint8_t *mac_rkd, size_t subkey_len, const uint8_t *plaintext, size_t ciphertext_len, uint8_t *cmac) {
    // D = AES-CMAC(K, <zero>)
    uint8_t zero_block[AES_BLOCK_SIZE] = {0};
    aes_cmac(mac_rkd, subkey_len, zero_block, AES_BLOCK_SIZE, cmac);

    PRINTF("performed first cmac: %.*h\n", AES_BLOCK_SIZE, cmac);

    // no associated data

    // if len(Sn) >= 128
    if (ciphertext_len >= AES_BLOCK_SIZE) {
        // T + Sn xorend D
        xor_buffers(plaintext + ciphertext_len - AES_BLOCK_SIZE, cmac, cmac, AES_BLOCK_SIZE);
        PRINTF("xorend' %.*h\n", AES_BLOCK_SIZE, cmac);
    }
    // T = dbl(D) xor pad(Sn)
    else {
        double_block(cmac);
        uint8_t padded[AES_BLOCK_SIZE];
        padding(plaintext, ciphertext_len, padded);
        xor_buffers(padded, cmac, cmac, AES_BLOCK_SIZE);
        PRINTF("xor'd padded %.*h\n", AES_BLOCK_SIZE, cmac);
    }

    // V = AES-CMAC(K, T)
    aes_cmac(mac_rkd, subkey_len, cmac, AES_BLOCK_SIZE, cmac);

    return parser_ok;
}

parser_error_t aes_siv_decrypt(
    const uint8_t *keys,
    size_t keys_len,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out,
    uint16_t *out_len
) {
    // AES-128 only
    if (keys_len != 32) {
        return parser_invalid_tek_data;
    }

    // write plaintext directly to output
    uint8_t *plaintext = (uint8_t *)out;

    // extract the keys
    size_t subkey_len = keys_len / 2;
    const uint8_t *mac_rkd = keys;
    const uint8_t *ctr_rkd = keys + subkey_len;

    // init ctr key
    cx_aes_key_t ctr_key;
    cx_err_t aes_err = cx_aes_init_key_no_throw(ctr_rkd, subkey_len, &ctr_key);
    if(aes_err != CX_OK) return parser_aes_init_error;

    // extract tag from payload
    const uint8_t *tag = (const uint8_t *)payload;

    // extract ciphertext from payload
    size_t ciphertext_len = payload_len - AES_BLOCK_SIZE;
    const uint8_t *ciphertext = payload + AES_BLOCK_SIZE;

    // init iv using tag
    uint8_t ctr_iv[AES_BLOCK_SIZE];
    memcpy(ctr_iv, tag, AES_BLOCK_SIZE);

    // zero out top bits in last 32-bit words of iv
    ctr_iv[AES_BLOCK_SIZE - 8] &= 0x7f;
    ctr_iv[AES_BLOCK_SIZE - 4] &= 0x7f;

    // prep block buffer
    uint8_t block_data[AES_BLOCK_SIZE];

    // the shared secret prefix will get skipped during decoding
    size_t plaintext_len = ciphertext_len - SHARED_SECRET_LEN;

    // make sure not to exceed the bounds of the output buffer
    plaintext_len = MIN(plaintext_len, out_len);

    // use read/write pointers for ciphertext/plaintext, respectively
    uint8_t *read = ciphertext;
    uint8_t *write = plaintext - SHARED_SECRET_LEN;

    // decrypt blocks using AES-CTR
    for (size_t block_idx = 0; block_idx < ciphertext_len; block_idx += AES_BLOCK_SIZE) {
        // compute intrinsic size of block
        size_t block_len = ciphertext_len - block_idx;
        block_len = MIN(block_len, AES_BLOCK_SIZE);

        // encrypt next ctr (Ledger's cx_aes_no_throw crashes the app)
        cx_aes(&ctr_key, CX_ENCRYPT, ctr_iv, AES_BLOCK_SIZE, block_data, AES_BLOCK_SIZE);

        // update counter
        for (int byte_idx = AES_BLOCK_SIZE-1; byte_idx >= 0; --byte_idx) {
            ctr_iv[byte_idx]++;
            if (ctr_iv[byte_idx] != 0) break;
        }

        // only write once within bounds
        if (write >= plaintext) {
            // make sure not to exceed the bounds of the output buffer
            size_t write_offset = block_idx - SHARED_SECRET_LEN;
            block_len = MIN(block_len, plaintext_len - write_offset);

            xor_buffers(read, block_data, write, block_len);
        }

        // advance read/write pointers
        read += block_len;
        write += block_len;
    }

    // set output length
    *out_len = write >= plaintext? write - plaintext: 0;

    // TODO: finish s2v impl

    // PRINTF("init mac rkd: %.*h\n", subkey_len, mac_rkd);

    // uint8_t cmac[AES_BLOCK_SIZE];
    // aes_s2v(mac_rkd, plaintext, ciphertext_len, cmac);

    // PRINTF("performed 2nd cmac %.*h <> %.*h\n", AES_BLOCK_SIZE, cmac, AES_BLOCK_SIZE, tag);

    // // check that the computed mac matches the provided tag
    // if (memcmp(cmac, tag, AES_BLOCK_SIZE) != 0) {

    //     // mac mismatch, data is corrupted
    //     // memset(plaintext, 0, ciphertext_len);
    //     return -1;
    // }

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

    // skip preamble to get to payload
    uint16_t payload_len = decoded_len - MSG_PREAMBLE_LEN;
    uint8_t *payload = (uint8_t *)decoded + MSG_PREAMBLE_LEN;

    // write plaintext directly to output
    uint8_t *plaintext = (uint8_t *)out;
    uint16_t plaintext_len;

    // attempt to decrypt the payload
    parser_error_t decrypt_error = aes_siv_decrypt(
        parser_tx_obj.tek_data,
        parser_tx_obj.tek_k,
        payload,
        payload_len,
        plaintext,
        &plaintext_len
    );

    if (decrypt_error != CX_OK) return decrypt_error;

    // trim end of string
    uint8_t *write = plaintext + plaintext_len;
    while (write-- > plaintext && (*write == '\0' || *write == ' ')) {
        *write = '\0';
    }

    // update length
    plaintext_len = write + 1 - plaintext;

    // replace codepoints outside the ASCII range with a single character
    write = plaintext;
    uint8_t *read = plaintext;
    while (read < plaintext + plaintext_len && *read != '\0') {
        utf8_int32_t codepoint;
        read = (uint8_t *)utf8codepoint((const char *)read, &codepoint);

        // write to buffer, replacing extended character with ASCII
        *write++ = codepoint > 0x7f? '+': (char)codepoint;
    }

    // write final length
    *out_len = write - plaintext;

    return parser_ok;
}
