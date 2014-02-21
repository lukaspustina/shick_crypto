#ifndef SHICK_CRYPTO
#define SHICK_CRYPTO

#include <sodium.h>

const int SC_ENC_ASYM_FAILED = -1001;
const int SC_ENC_SYM_FAILED = -1002;
const int SC_DEC_ASYM_FAILED = -1101;
const int SC_DEC_SYM_FAILED = -1102;


typedef unsigned char SC_CHAR;
typedef unsigned long long SC_LEN;
typedef struct {
  SC_CHAR key[crypto_secretbox_KEYBYTES];
  SC_CHAR nonce[crypto_secretbox_NONCEBYTES];
} SC_SYM_KEY;
typedef struct {
  SC_CHAR mac[crypto_box_MACBYTES];
  SC_CHAR key[crypto_secretbox_KEYBYTES];
  SC_CHAR nonce[crypto_secretbox_NONCEBYTES];
} SC_ENC_SYM_KEY;


const char* shick_crypto_version();

/*
 * Call this before once, before using any shick_crypto function.
 */
void shick_crypto_init();

/*
 * Creates a asymmetric secret/public key pair. The size of the keys are
 *    unsigned char pk[crypto_box_PUBLICKEYBYTES];
 *    unsigned char sk[crypto_box_SECRETKEYBYTES];
 */
int shick_crypto_create_asymmetric_key_pair(SC_CHAR secret_key[crypto_box_SECRETKEYBYTES], SC_CHAR public_key[crypto_box_PUBLICKEYBYTES]);

void shick_create_nonce(SC_CHAR* nonce, int len);

int shick_crypto_enc_message(const SC_CHAR sender_secret_key[crypto_box_SECRETKEYBYTES], const SC_CHAR** recipient_public_keys, const int amount_of_recipients, const SC_CHAR* message, const SC_LEN message_len, SC_CHAR nonce[crypto_box_NONCEBYTES], SC_ENC_SYM_KEY* encrypted_symmetric_keys, SC_CHAR* ciphertext);

int shick_crypto_dec_message(const SC_CHAR recipient_secret_key[crypto_box_SECRETKEYBYTES], const SC_CHAR sender_public_key[crypto_box_PUBLICKEYBYTES], const SC_ENC_SYM_KEY encrypted_symmetric_key, const SC_CHAR* ciphertext, const SC_LEN cipertext_len, const SC_CHAR nonce[crypto_box_NONCEBYTES], SC_CHAR* message);

#endif

