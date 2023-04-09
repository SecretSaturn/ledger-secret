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

#include <stdio.h>
#include <stdint.h>
#include "parser_impl.h"

#define AES_BLOCK_SIZE 16
#define MSG_PREAMBLE_LEN 64
#define SHARED_SECRET_LEN 64

static const char key_wasm_msg[] = "msgs/value/msg";

parser_error_t aes_siv_decrypt(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *plaintext,
    uint16_t *out_len
);

parser_error_t decrypt_secret_wasm_msg(uint8_t *in, uint16_t in_len, uint8_t *out, uint16_t *out_len);
