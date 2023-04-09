/*******************************************************************************
*  (c) 2019 Zondax GmbH
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

#include "parser_impl.h"

parser_tx_t parser_tx_obj;

parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        ctx->buffer = NULL;
        ctx->bufferLen = 0;
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, size_t bufferSize) {
    parser_error_t err = parser_init_context(ctx, buffer, bufferSize);
    if (err != parser_ok)
        return err;

    return err;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_version:
            return "Unexpected version";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_duplicated_field:
            return "Unexpected duplicated field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_unexpected_chain:
            return "Unexpected chain";
        case parser_query_no_results:
            return "item query returned no results";
        case parser_missing_field:
            return "missing field";
//////
        case parser_display_idx_out_of_range:
            return "display index out of range";
        case parser_display_page_out_of_range:
            return "display page out of range";
//////
        case parser_json_zero_tokens:
            return "JSON. Zero tokens";
        case parser_json_too_many_tokens:
            return "JSON. Too many tokens";
        case parser_json_incomplete_json:
            return "JSON string is not complete";
        case parser_json_contains_whitespace:
            return "JSON Contains whitespace in the corpus";
        case parser_json_is_not_sorted:
            return "JSON Dictionaries are not sorted";
        case parser_json_missing_chain_id:
            return "JSON Missing chain_id";
        case parser_json_missing_sequence:
            return "JSON Missing sequence";
        case parser_json_missing_fee:
            return "JSON Missing fee";
        case parser_json_missing_msgs:
            return "JSON Missing msgs";
        case parser_json_missing_account_number:
            return "JSON Missing account number";
        case parser_json_missing_memo:
            return "JSON Missing memo";
        case parser_json_unexpected_error:
            return "JSON Unexpected error";
//////
        case parser_invalid_tek_k:
            return "Invalid tx encryption key size";
        case parser_invalid_tek_data:
            return "Invalid tx encryption key data";
        case parser_invalid_msg_contents:
            return "Invalid contract message contents";
        case parser_aes_init_error:
            return "Failed to init AES key";
        case parser_aes_decrypt_error:
            return "Failed to decrypt AES block";
        

        default:
            return "Unrecognized error code";
    }
}

parser_error_t _readTx(parser_context_t *c, tx_mode_t mode, parser_tx_t *v) {
    const char *buffer = (const char *) c->buffer;
    uint16_t buffer_len = c->bufferLen;

    const char *json = buffer;
    uint16_t json_len = buffer_len;

    // init transaction encryption key fields
    parser_tx_obj.tek_k = 0;
    parser_tx_obj.tek_data = NULL;

    // instruction is to sign in decrypt mode
    if (mode == TX_MODE_DECRYPT) {
        // extract tek k and data from buffer
        uint8_t tek_k = buffer[0];
        const char* tek_data = buffer + 1;

        // invalid key size
        if (tek_k != 32) return parser_invalid_tek_k;

        // missing key data
        if (buffer_len < 1 + tek_k) return parser_invalid_tek_data;

        // set fields
        parser_tx_obj.tek_k = tek_k;
        parser_tx_obj.tek_data = tek_data;

        // adjust json data pointer and length
        json += 1 + tek_k;
        json_len -= 1 + tek_k;
    }

    parser_error_t err = json_parse(&parser_tx_obj.json,
                                    json,
                                    json_len);
    if (err != parser_ok) {
        return err;
    }

    parser_tx_obj.tx = json;
    parser_tx_obj.flags.cache_valid = 0;
    parser_tx_obj.filter_msg_type_count = 0;
    parser_tx_obj.filter_msg_from_count = 0;

    return parser_ok;
}
