#include "../src/shick_crypto.h"

void printBufferAsHex(SC_CHAR* buffer, SC_LEN buffer_len) {
  for (int c=0; c < buffer_len; c++) {
    printf(",0x%02x",(unsigned int) buffer[c]);
    if (c % 8 == 7) printf("\n");
  }
}

int run_example() {
  SC_CHAR message[] = "Shick Crypto Lib";

  int result = 0;
  int amount_of_recipients = 1;

  SC_CHAR alice_secret_key[crypto_box_SECRETKEYBYTES];
  SC_CHAR alice_public_key[crypto_box_PUBLICKEYBYTES];
  SC_CHAR bob_secret_key[crypto_box_SECRETKEYBYTES];
  SC_CHAR bob_public_key[crypto_box_PUBLICKEYBYTES];

  const SC_CHAR* recipient_public_keys[amount_of_recipients];
  SC_CHAR nonce[crypto_box_NONCEBYTES];
  SC_CHAR ciphertext[crypto_box_MACBYTES + sizeof message];
  SC_ENC_SYM_KEY encrypted_symmetric_keys[amount_of_recipients];
  SC_CHAR message_decrypted[sizeof message];

  shick_crypto_init();

  shick_crypto_create_asymmetric_key_pair(alice_secret_key, alice_public_key);
  shick_crypto_create_asymmetric_key_pair(bob_secret_key, bob_public_key);

  recipient_public_keys[0] = bob_public_key;

  shick_create_nonce(nonce, sizeof nonce);

  // Encrypt
  shick_crypto_enc_message(alice_secret_key, recipient_public_keys, amount_of_recipients, message, sizeof message, nonce, encrypted_symmetric_keys, ciphertext);
  // Now your message is encrypted for Bob and Bobby
  // Send (nonce, encrypted_symmetric_keys[i], ciphertext) to Bob and Bobby

  // Decrypt for Bob
  shick_crypto_dec_message(bob_secret_key, alice_public_key, encrypted_symmetric_keys[0], ciphertext, sizeof ciphertext, nonce, message_decrypted);


  // Show data on console
  printf("* Alice' SK:\n"); printBufferAsHex(alice_secret_key, crypto_box_SECRETKEYBYTES);
  printf("* Alice' PK:\n"); printBufferAsHex(alice_public_key, crypto_box_PUBLICKEYBYTES);
  printf("* Bobs SK:\n"); printBufferAsHex(bob_secret_key, crypto_box_SECRETKEYBYTES);
  printf("* Bobs PK:\n"); printBufferAsHex(bob_public_key, crypto_box_PUBLICKEYBYTES);
  printf("* Nonce:\n"); printBufferAsHex(nonce, crypto_box_NONCEBYTES);
  SC_ENC_SYM_KEY key = encrypted_symmetric_keys[0];
  printf("* Enc Sym Key:\n"); printBufferAsHex(((SC_CHAR*) &key), sizeof(SC_ENC_SYM_KEY));
  printf("* Cipher Text:\n"); printBufferAsHex(ciphertext, sizeof ciphertext);

  return 0;
}

int main() {
  return run_example();
}

