#include <config.h>
#include <sodium.h>
#include <stdlib.h>
#include <check.h>
#include "../src/shick_crypto.h"

START_TEST (test_shick_crypto_asymmetric_crypto_roundtrip) {
  int result = 0;
  int amount_of_recipients = 2;
  SC_CHAR alice_secret_key[crypto_box_SECRETKEYBYTES];
  SC_CHAR alice_public_key[crypto_box_PUBLICKEYBYTES];
  SC_CHAR bob_secret_key[crypto_box_SECRETKEYBYTES];
  SC_CHAR bob_public_key[crypto_box_PUBLICKEYBYTES];
  SC_CHAR bobby_secret_key[crypto_box_SECRETKEYBYTES];
  SC_CHAR bobby_public_key[crypto_box_PUBLICKEYBYTES];
  const SC_CHAR* recipient_public_keys[amount_of_recipients];
  SC_CHAR nonce[crypto_box_NONCEBYTES];
  SC_CHAR message[] = "Shick Crypto Lib";
  SC_CHAR ciphertext[crypto_box_MACBYTES + sizeof message];
  SC_ENC_SYM_KEY encrypted_symmetric_keys[amount_of_recipients];
  SC_CHAR message_decrypted[sizeof message];

  shick_crypto_init();
  result = shick_crypto_create_asymmetric_key_pair(alice_secret_key, alice_public_key);
  ck_assert_int_eq(result, 0);
  result = shick_crypto_create_asymmetric_key_pair(bob_secret_key, bob_public_key);
  ck_assert_int_eq(result, 0);
  result = shick_crypto_create_asymmetric_key_pair(bobby_secret_key, bobby_public_key);
  ck_assert_int_eq(result, 0);

  recipient_public_keys[0] = bob_public_key;
  recipient_public_keys[1] = bobby_public_key;
  shick_create_nonce(nonce, sizeof nonce);

  // Encrypt
  result = shick_crypto_enc_message(alice_secret_key, recipient_public_keys, amount_of_recipients, message, sizeof message, nonce, encrypted_symmetric_keys, ciphertext);
  // Now your message is encrypted for Bob and Bobby
  // Send (nonce, encrypted_symmetric_keys[i], ciphertext) to Bob and Bobby
  ck_assert_int_eq(result, 0);

  /*
  printf("Alice' SK:\n");
  for (int c=0; c < crypto_box_SECRETKEYBYTES; c++) {
    printf(",0x%02x",(unsigned int) alice_secret_key[c]);
    if (c % 8 == 7) printf("\n");
  }
  printf("\n");
  printf("Alice' PK:\n");
  for (int c=0; c < crypto_box_PUBLICKEYBYTES; c++) {
    printf(",0x%02x",(unsigned int) alice_public_key[c]);
    if (c % 8 == 7) printf("\n");
  }
  printf("\n");
  printf("Bobs SK:\n");
  for (int c=0; c < crypto_box_SECRETKEYBYTES; c++) {
    printf(",0x%02x",(unsigned int) bob_secret_key[c]);
    if (c % 8 == 7) printf("\n");
  }
  printf("\n");
  printf("Bobs PK:\n");
  for (int c=0; c < crypto_box_PUBLICKEYBYTES; c++) {
    printf(",0x%02x",(unsigned int) bob_public_key[c]);
    if (c % 8 == 7) printf("\n");
  }
  printf("\n");
  printf("Nonce:\n");
  for (int c=0; c < crypto_box_NONCEBYTES; c++) {
    printf(",0x%02x",(unsigned int) nonce[c]);
    if (c % 8 == 7) printf("\n");
  }
  printf("\n");
  printf("Enc Sym Key:\n");
  SC_ENC_SYM_KEY key = encrypted_symmetric_keys[0];
  for (int c=0; c < sizeof(SC_ENC_SYM_KEY); c++) {
    printf(",0x%02x",(unsigned int) ((SC_CHAR*) &key)[c]);
    if (c % 8 == 7) printf("\n");
  }
  printf("\n");
  printf("Cipher Text:\n");
  for (int c=0; c < sizeof ciphertext; c++) {
    printf(",0x%02x",(unsigned int) ciphertext[c]);
    if (c % 8 == 7) printf("\n");
  }
  printf("\n");
  */


  // Decrypt for Bob
  result = shick_crypto_dec_message(bob_secret_key, alice_public_key, encrypted_symmetric_keys[0], ciphertext, sizeof ciphertext, nonce, message_decrypted);
  ck_assert_int_eq(result, 0);
  ck_assert_str_eq((const char*) message_decrypted, (const char*) message);

  // Decrypt for Bobby
  result = shick_crypto_dec_message(bobby_secret_key, alice_public_key, encrypted_symmetric_keys[1], ciphertext, sizeof ciphertext, nonce, message_decrypted);
  ck_assert_int_eq(result, 0);
  ck_assert_str_eq((const char*) message_decrypted, (const char*) message);
}
END_TEST

Suite* shick_crypto_suite(void) {
  Suite *s = suite_create ("Shick Crypto Lib - Acceptance Tests");

  TCase *tc_core = tcase_create ("Core");
  tcase_add_test (tc_core, test_shick_crypto_asymmetric_crypto_roundtrip);
  suite_add_tcase (s, tc_core);

  return s;
}

int main (void) {
  int number_failed;
  Suite *s = shick_crypto_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

