#include <config.h>
#include <sodium.h>
#include <sodium/crypto_box.h>
#include <string.h>

#include "shick_crypto.h"

const char*
shick_crypto_version() {
  return PACKAGE_VERSION;
}

/*
 * Recommended to call in order to select optimal implementation details
 * at run time.
 * See https://github.com/jedisct1/libsodium/blob/master/README.markdown
 */
void
shick_crypto_init() {
  sodium_init();
}

int
shick_crypto_create_asymmetric_key_pair(SC_CHAR secret_key[crypto_box_SECRETKEYBYTES],
                                        SC_CHAR  public_key[crypto_box_PUBLICKEYBYTES]) {
     return crypto_box_keypair(public_key, secret_key);
}

void
shick_create_nonce(SC_CHAR* nonce, int len) {
  randombytes_buf(nonce, len);
}

int
shick_crypto_enc_message(const SC_CHAR sender_secret_key[crypto_box_SECRETKEYBYTES],
                         const SC_CHAR** recipient_public_keys,
                         const int amount_of_recipients,
                         const SC_CHAR* message,
                         const SC_LEN message_len,
                         SC_CHAR nonce[crypto_box_NONCEBYTES],
                         SC_ENC_SYM_KEY* encrypted_symmetric_keys,
                         SC_CHAR* ciphertext) {
  int failed = 0;

  // Create symmetric key
  SC_SYM_KEY sym_key;
  randombytes_buf((void*) sym_key.key, sizeof sym_key.key);
  randombytes_buf((void*) sym_key.nonce, sizeof sym_key.nonce);

  // Encrypt message symmetrically
  failed = crypto_secretbox_easy(ciphertext, message, message_len, sym_key.nonce, sym_key.key);
  if (failed) return SC_ENC_SYM_FAILED;

  // Encrypt symmetric key asymmetrically for each recipient
  for (int i = 0; i < amount_of_recipients; i++) {
    SC_CHAR public_key[crypto_box_PUBLICKEYBYTES];
    memcpy(public_key, recipient_public_keys[i], crypto_box_PUBLICKEYBYTES);
    failed = crypto_box_easy((SC_CHAR*) &encrypted_symmetric_keys[i], (SC_CHAR*) &sym_key, sizeof sym_key, nonce, public_key, sender_secret_key);
    if (failed) return SC_ENC_ASYM_FAILED;
  }

  return 0;
}

int
shick_crypto_dec_message(const SC_CHAR recipient_secret_key[crypto_box_SECRETKEYBYTES],
                         const SC_CHAR sender_public_key[crypto_box_PUBLICKEYBYTES],
                         const SC_ENC_SYM_KEY encrypted_symmetric_key,
                         const SC_CHAR* ciphertext,
                         const SC_LEN ciphertext_len,
                         const SC_CHAR nonce[crypto_box_NONCEBYTES],
                         SC_CHAR* message) {
  int failed = 0;
  SC_CHAR buffer[sizeof(SC_SYM_KEY)];
  SC_SYM_KEY* sym_key;

  // Decrypt symmetric key 
  failed = crypto_box_open_easy(buffer, (SC_CHAR*) &encrypted_symmetric_key, sizeof encrypted_symmetric_key, nonce, sender_public_key, recipient_secret_key);
  if (failed) return SC_DEC_ASYM_FAILED;

  // Decrypt message with symmetric key
  sym_key = (SC_SYM_KEY*) buffer;
  failed = crypto_secretbox_open_easy(message, ciphertext, ciphertext_len, sym_key->nonce, sym_key->key);
  if (failed) return SC_DEC_SYM_FAILED;

  return 0;
}

