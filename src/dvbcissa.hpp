/*
 *    Copyright (c) 2020 Omid <<omid@omid.blue>>
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

#ifndef DVBCISSA_H
#define DVBCISSA_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

class dvbcissa_key_t {
private:
    AES_KEY enc_key;
    AES_KEY dec_key;
    bool key_set;

    static constexpr uint8_t DVBCISSA_IV[16] = {
        0x44, 0x56, 0x42, 0x54, 0x4D, 0x43, 0x50, 0x54,
        0x41, 0x45, 0x53, 0x43, 0x49, 0x53, 0x53, 0x41
    };
    static const int TS_PACKET_SIZE = 188;

    int scramble_block(const uint8_t *in, uint8_t *out, size_t len) {
        uint8_t iv[16];
        if (!key_set || !in || !out || len % 16 != 0) {
            return -1;
        }
        memcpy(iv, DVBCISSA_IV, 16);
        CRYPTO_cbc128_encrypt(in, out, len, &enc_key, iv, (block128_f)AES_encrypt);
        return 0;
    }

    int descramble_block(const uint8_t *in, uint8_t *out, size_t len) {
        uint8_t iv[16];
        if (!key_set || !in || !out || len % 16 != 0) {
            return -1;
        }
        memcpy(iv, DVBCISSA_IV, 16);
        CRYPTO_cbc128_decrypt(in, out, len, &dec_key, iv, (block128_f)AES_decrypt);
        return 0;
    }

public:
    dvbcissa_key_t() : key_set(false) {}

    ~dvbcissa_key_t() {
        clear();
    }

    void clear() {
        memset(&enc_key, 0, sizeof(enc_key));
        memset(&dec_key, 0, sizeof(dec_key));
        key_set = false;
    }

    int set_word(const uint8_t *word) {
        if (!word) {
            return -1;
        }
        if (AES_set_encrypt_key(word, 128, &enc_key) != 0) {
            return -1;
        }
        if (AES_set_decrypt_key(word, 128, &dec_key) != 0) {
            return -1;
        }
        key_set = true;
        return 0;
    }

    int scramble_packet(uint8_t *ts_packet, uint8_t odd) {
        if (!key_set || !ts_packet) {
            return -1;
        }
        if (ts_packet[0] != 0x47) {
            return -1;
        }

        uint8_t adaptation_field_control = (ts_packet[3] & 0x30) >> 4;
        uint8_t offset = 4;

        if (adaptation_field_control & 0x2) {
            offset += ts_packet[4] + 1;
        }

        if (!(adaptation_field_control & 0x1)) {
            return 0;
        }

        int payload_len = TS_PACKET_SIZE - offset;
        if (payload_len < 16) {
            return 0;
        }

        payload_len = (payload_len / 16) * 16;
        ts_packet[3] = (ts_packet[3] & 0x3F) | (odd ? 0xC0 : 0x80);

        return scramble_block(ts_packet + offset, ts_packet + offset, payload_len);
    }

    int descramble_packet(uint8_t *ts_packet) {
        if (!key_set || !ts_packet) {
            return -1;
        }
        if (ts_packet[0] != 0x47) {
            return -1;
        }

        uint8_t scrambling_control = (ts_packet[3] & 0xC0) >> 6;
        if (scrambling_control == 0) {
            return 0;
        }

        uint8_t adaptation_field_control = (ts_packet[3] & 0x30) >> 4;
        uint8_t offset = 4;

        if (adaptation_field_control & 0x2) {
            offset += ts_packet[4] + 1;
        }

        if (!(adaptation_field_control & 0x1)) {
            return 0;
        }

        int payload_len = TS_PACKET_SIZE - offset;
        if (payload_len < 16) {
            return 0;
        }

        payload_len = (payload_len / 16) * 16;
        int result = descramble_block(ts_packet + offset, ts_packet + offset, payload_len);

        if (result == 0) {
            ts_packet[3] &= 0x3F;
        }

        return result;
    }
};

#endif /* DVBCISSA_H */
