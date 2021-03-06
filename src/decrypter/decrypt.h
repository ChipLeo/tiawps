#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdint.h>
#include <openssl/evp.h>

struct decryption_state
{
    uint8_t *buffer;
    uint32_t bufferSize;

    uint8_t skipDecryptCount;
    uint8_t decryptedHeaderBytes;

    uint8_t s2c;
    uint8_t opcodeLen;
    EVP_CIPHER_CTX key;
};

void init_decryption_state_server(struct decryption_state *state, uint8_t *sessionkey, uint8_t* customseed);
void init_decryption_state_client(struct decryption_state *state, uint8_t *sessionkey, uint8_t* customseed);
void free_decryption_state(struct decryption_state *);

void update_decryption(struct decryption_state *state, uint64_t time, uint8_t *data, uint32_t data_len, void *db,
        void(*callback)(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t *data, uint32_t data_len, void *db));

#endif
