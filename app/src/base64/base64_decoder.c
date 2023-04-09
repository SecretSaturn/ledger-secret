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

#include "base64_decoder.h"

int base64_reverse_lookup(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    } else if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    } else if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    } else if (c == '+') {
        return 62;
    } else if (c == '/') {
        return 63;
    }

    return -1;
}

int base64_decode(const uint8_t *in, uint16_t in_len, char* out, uint16_t *out_len) {
    uint16_t max_len = BASE64_DECODED_LEN(in_len);

    // output buffer does not have enough space
    if(max_len > *out_len) return -2;

    // set output length return
    *out_len = max_len;

    // trim padding
    if (in[in_len - 1] == '=') {
        (*out_len)--;

        if (in[in_len - 2] == '=') {
            (*out_len)--;
        }
    }

    // decode
    for (uint16_t read = 0, write = 0; read < in_len; ++read) {
        int a = in[read] == '=' ? 0 : base64_reverse_lookup(in[read]);
        int b = in[++read] == '=' ? 0 : base64_reverse_lookup(in[read]);
        int c = in[++read] == '=' ? 0 : base64_reverse_lookup(in[read]);
        int d = in[++read] == '=' ? 0 : base64_reverse_lookup(in[read]);

        if(a == -1 || b == -1 || c == -1 || d == -1) return -1;

        out[write++] = (a << 2) | (b >> 4);
        if (write < *out_len) {
            out[write++] = (b << 4) | (c >> 2);
        }
        if (write < *out_len) {
            out[write++] = (c << 6) | d;
        }
    }

    return 0;
}
