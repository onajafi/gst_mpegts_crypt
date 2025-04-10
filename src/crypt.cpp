/*
 *    Copyright (c) 2020 Karim <<karimdavoodi@gmail.com>>
 *
 *    Permission is hereby granted, free of charge, to any person obtaining a copy
 *    of this software and associated documentation files (the "Software"), to deal
 *    in the Software without restriction, including without limitation the rights
 *    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *    copies of the Software, and to permit persons to whom the Software is
 *    furnished to do so, subject to the following conditions:
 *
 *    The above copyright notice and this permission notice shall be included in all
 *    copies or substantial portions of the Software.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *    SOFTWARE.
 */
#include <iostream>
#include <gst/gst.h>
#include "gstmpegtscrypt.hpp"

using namespace std;

int _decode_hex_char(char c) {
    if ((c >= '0') && (c <= '9')) return c - '0';
    if ((c >= 'A') && (c <= 'F')) return c - 'A' + 10;
    if ((c >= 'a') && (c <= 'f')) return c - 'a' + 10;
    return -1;
}
int _decode_hex_string(const char *hex, uint8_t *bin, int asc_len) {
    int i;
    for (i = 0; i < asc_len; i += 2) {
        int n1 = _decode_hex_char(hex[i + 0]);
        int n2 = _decode_hex_char(hex[i + 1]);
        if (n1 == -1 || n2 == -1)
            return -1;
        bin[i / 2] = (n1 << 4) | (n2 & 0xf);
    }
    return asc_len / 2;
}
bool _init_biss_key(GstMpegtsCrypt*filter,  string key_str)
{
    if (key_str.size() > 2 && key_str[0] == '0' && key_str[1] == 'x')
        key_str = key_str.substr(2);
    uint8_t key[16];
    // Sometimes the BISS keys are entered with their checksums already calculated
    // (16 symbols, 8 bytes)
    // This is the same as constant cw with the same key for even and odd
    if (key_str.size() == (BISSKEY_LENGTH + 2) * 2) {
        if (_decode_hex_string(key_str.c_str(), key, key_str.size()) < 0) {
            GST_ERROR_OBJECT(filter, "Invalid hex string for BISS key.");
            return false;
        }
    } else {
        // BISS key without checksum (12 symbols, 6 bytes)
        if (key_str.size() != BISSKEY_LENGTH * 2) {
            GST_ERROR_OBJECT(filter, "Invalid BISS key len. must be %d or %d", 
                    BISSKEY_LENGTH*2,
                    (BISSKEY_LENGTH+2)*2);
            return false;
        }
        if (_decode_hex_string(key_str.c_str(), key, key_str.size()) < 0) {
            GST_ERROR_OBJECT(filter, "Invalid hex string for BISS key");
            return false;
        }
        // Calculate BISS KEY crc
        memmove(key + 4, key + 3, 3);
        key[3] = (uint8_t)(key[0] + key[1] + key[2]);
        key[7] = (uint8_t)(key[4] + key[5] + key[6]);
    }
    // Even and odd keys are the same
    dvbcsa_key_set(key, filter->biss_csakey[0]);
    dvbcsa_key_set(key, filter->biss_csakey[1]);
    GST_DEBUG_OBJECT(filter, "Init BISS key");
    return true;
}
bool _init_biss_v2_key(GstMpegtsCrypt*filter,  string key_str)
{
    if (key_str.size() > 2 && key_str[0] == '0' && key_str[1] == 'x')
        key_str = key_str.substr(2);

    uint8_t cissa_key[16];
    // (32 symbols, 16 bytes)
    if (_decode_hex_string(key_str.c_str(), cissa_key, key_str.size()) < 0) {
        GST_ERROR_OBJECT(filter, "Invalid hex string for BISS key.");
        return false;
    }
    
    filter->biss_cissa_key.set_word(cissa_key);
    GST_DEBUG_OBJECT(filter, "Init BISS-V2 Mode-1 key");
    return true;
}

// copy from libtsfuncs
uint8_t ts_packet_get_payload_offset(uint8_t *ts_packet) {
    if (ts_packet[0] != 0x47)
        return 0;

    uint8_t adapt_field   = (ts_packet[3] &~ 0xDF) >> 5; // 11x11111
    uint8_t payload_field = (ts_packet[3] &~ 0xEF) >> 4; // 111x1111

    if (!adapt_field && !payload_field) 
        return 0;

    if (adapt_field) {
        uint8_t adapt_len = ts_packet[4];
        if (payload_field && adapt_len > 182) // Validity checks
            return 0;
        if (!payload_field && adapt_len > 183)
            return 0;
        if (adapt_len + 4 > 188) // adaptation field takes the whole packet
            return 0;
        return 4 + 1 + adapt_len; // ts header + adapt_field_len_byte + adapt_field_len
    } else {
        return 4; // No adaptation, data starts directly after TS header
    }
}
void crypt_packet_aes(GstMpegtsCrypt* filter, uint8_t *ts_packet) {

    unsigned int payload_offset = ts_packet_get_payload_offset(ts_packet);
    // TODO: the last remaind of 16 bytes not crypt
    for(int i=payload_offset; i<188-16; i+=16){
        auto *in =  ts_packet + i;
        auto *out = ts_packet + i;
        switch(filter->method){
            case MPEGTSCRYPT_METHOD_AES128_CBC:
                if(filter->operation == MPEGTSCRYPT_OPERATION_ENC)
                    AES_cbc_encrypt (in , out, 16, &(filter->aes_enc_key), 
                            filter->aes_iv_enc, AES_ENCRYPT);
                else
                    AES_cbc_encrypt (in , out, 16, &(filter->aes_dec_key), 
                            filter->aes_iv_dec, AES_DECRYPT);
                break;
            case MPEGTSCRYPT_METHOD_AES128_ECB:
                if(filter->operation == MPEGTSCRYPT_OPERATION_ENC)
                    AES_ecb_encrypt (in , out, &(filter->aes_enc_key), AES_ENCRYPT);
                else
                    AES_ecb_encrypt (in , out, &(filter->aes_dec_key), AES_DECRYPT);
                break;
            case MPEGTSCRYPT_METHOD_AES256_CBC:
                if(filter->operation == MPEGTSCRYPT_OPERATION_ENC)
                    AES_cbc_encrypt (in , out, 16, &(filter->aes_enc_key), 
                            filter->aes_iv_enc, AES_ENCRYPT);
                else
                    AES_cbc_encrypt (in , out, 16, &(filter->aes_dec_key), 
                            filter->aes_iv_dec, AES_DECRYPT);
                break;
            case MPEGTSCRYPT_METHOD_AES256_ECB:
                if(filter->operation == MPEGTSCRYPT_OPERATION_ENC)
                    AES_ecb_encrypt (in , out, &(filter->aes_enc_key), AES_ENCRYPT);
                else
                    AES_ecb_encrypt (in , out, &(filter->aes_dec_key), AES_DECRYPT);
                break;
            default:
                break;
        }
    }
}
void crypt_packet_biss(GstMpegtsCrypt* filter, uint8_t *ts_packet) {
    static bool key_idx = 0;

    unsigned int payload_offset = ts_packet_get_payload_offset(ts_packet);
    GST_LOG_OBJECT(filter, "biss key idx: %d pyload size: %d",key_idx, 188 - payload_offset);

    if(filter->operation == MPEGTSCRYPT_OPERATION_ENC){
        if(key_idx == 0)  ts_packet[3] |= 2 << 6;   // even key
        else              ts_packet[3] |= 3 << 6;   // odd key
        dvbcsa_encrypt(filter->biss_csakey[key_idx], ts_packet + payload_offset, 
                188 - payload_offset);
        key_idx = key_idx == 0 ? 1 : 0;
    }else{
        int scramble_idx =  ts_packet[3] >> 6;
        if (scramble_idx > 1) {
            unsigned int key_idx = scramble_idx - 2;
            ts_packet[3] = ts_packet[3] &~ 0xc0; // set not scrambled (11xxxxxx)
            dvbcsa_decrypt(filter->biss_csakey[key_idx], ts_packet + payload_offset, 
                    188 - payload_offset);
        }else GST_WARNING_OBJECT(filter, "Ts packet is not scrambled");
    }
}
void crypt_packet_biss_v2(GstMpegtsCrypt* filter, uint8_t *ts_packet) {
    static bool key_idx = 0;

    if(filter->operation == MPEGTSCRYPT_OPERATION_ENC){//Scramble
    }else{//Unscramble
        filter->biss_cissa_key.descramble_packet(ts_packet);
    }
}
void crypt_finish(GstMpegtsCrypt* filter)
{
    GST_DEBUG_OBJECT(filter, "Finish crypto");
    switch(filter->method){
        case MPEGTSCRYPT_METHOD_BISS: 
            dvbcsa_key_free(filter->biss_csakey[0]);
            dvbcsa_key_free(filter->biss_csakey[1]);
            break;
        default:
            break;
    }

}
void crypt_init(GstMpegtsCrypt* filter)
{
    int aes_bit = 256;
    GST_DEBUG_OBJECT(filter, "Init crypto by key '%s' ", filter->key);
    switch(filter->method){
        case MPEGTSCRYPT_METHOD_BISS: 
            filter->biss_csakey[0] = dvbcsa_key_alloc();
            filter->biss_csakey[1] = dvbcsa_key_alloc();
            _init_biss_key(filter, string(filter->key) );
            break;
        case MPEGTSCRYPT_METHOD_BISS_V2_1: 
            filter->biss_version = 2;
            filter->biss_mode = MPEGTSCRYPT_BISS_MODE_1;
            _init_biss_v2_key(filter, string(filter->key) );
            break;
        case MPEGTSCRYPT_METHOD_BISS_V2_E: 
            // To be implemented...
            break;
        case MPEGTSCRYPT_METHOD_BISS_V2_CA: 
            // To be implemented...
            break;

        case MPEGTSCRYPT_METHOD_AES128_ECB:
        case MPEGTSCRYPT_METHOD_AES128_CBC:
            aes_bit = 128;
        case MPEGTSCRYPT_METHOD_AES256_ECB:
        case MPEGTSCRYPT_METHOD_AES256_CBC:
            AES_set_encrypt_key((const unsigned char*)filter->key, aes_bit, 
                    &(filter->aes_enc_key));
            AES_set_decrypt_key((const unsigned char*)filter->key, aes_bit, 
                    &(filter->aes_dec_key));
            memset(filter->aes_iv_dec, 0xf1, AES_BLOCK_SIZE);
            memset(filter->aes_iv_enc, 0xf1, AES_BLOCK_SIZE);
            break;
    }

}
