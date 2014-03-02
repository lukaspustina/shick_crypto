# Shick Crypto Library
This library shows how to use [NaCl][NaCl] in form of [libsodium][libsodium] to securely encrypt a message with asymmetric encryption. 

In German, *Schick!* (pronounced [shick]) means *Send!*. So, clone and start sending securely. You can find Shick Crypto Library

* on [GitHub](https://github.com/lukaspustina/shick_crypto)
* on [Travis CI](https://travis-ci.org/lukaspustina/shick_crypto)

Please feel free to clone and adapt to your needs. If you find any bugs or have enhancements, please share it. I will react on pull requests promptly.

## How Does it Work

Shick Crypto Library is just a thin wrapper around libsodium. The main functionality consists of two functions, i.e., `shick_crypto_enc_message` and `shick_crypto_dec_message`. Messages are encrypted and decrypted following the same pattern as used in [GPG](http://en.wikipedia.org/wiki/GNU_Privacy_Guard#Process) by generating a random *symmetric* key, encrypting a message symmetrically, and finally encrypt the random key *asymmetrically*. Since asymmetric encryption is computational more expensive than symmetric encryption, this pattern combines the security and speed of both worlds. In addition, all encryption, i.e., asymmetric and symmetric encryption, is protected by [MACs](http://en.wikipedia.org/wiki/Message_authentication_code) and initialized with [nouces](http://en.wikipedia.org/wiki/Cryptographic_nonce). The concrete algorithms used by NaCl are currently [Curve25519](http://en.wikipedia.org/wiki/Curve25519) elliptic curve cryptography for asymmetric encryption, [Salsa20](http://en.wikipedia.org/wiki/Salsa20) for symmetric encryption, and [Poly1305-AES](http://en.wikipedia.org/wiki/Poly1305-AES) for [message authentication code](http://en.wikipedia.org/wiki/Message_authentication_code) (MAC) computation.

## How to Use

### Prerequisites

1. Crypto library [NaCl][NaCl] in form of [libsodium][libsodium]
2. C unit testing library [Check](http://en.wikipedia.org/wiki/Cryptographic_nonce)

Check is usually available on all Linux distributions and in [Homebrew](http://en.wikipedia.org/wiki/Cryptographic_nonce). libsodium might be available, but please make sure you use a recent version. It is easy to install from source -- see their [Readme](https://github.com/jedisct1/libsodium/blob/master/README.markdown). If you compile from source, please make sure to pass the parameter `--enable-blocking-random` to `./configure` in order to use `/dev/random` for random number generation.

[NaCl]:http://nacl.cace-project.eu
[libsodium]:https://github.com/jedisct1/libsodium

### Compile

1. `autoreconf --install && ./configure && make`

### Run Tests

1. `make check` for acceptance and unit tests
1. `./configure --enable-gcov && make clean && make && make check` for coverage test

### API

Shick Crypto Library has six functions:

```
// Returns Shick Crypto Library version
const char* shick_crypto_version()
```
```
// Initializes libsodium and should be run once per application run
void shick_crypto_init()
```
```
// Creates an asymmetric key pair
int shick_crypto_create_asymmetric_key_pair(secret_key, public_key)
```
```
// Creates a random nonce of specific length
void shick_create_nonce(nonce, len)
```
```
// Encrypts a message with a random symmetric key and encrypts this key asymmetrically for all recipients
int shick_crypto_enc_message(sender_secret_key, recipient_public_keys,  
    amount_of_recipients, message, message_len, nonce, encrypted_symmetric_keys, ciphertext)
```
```
// Decrypts a message with a asymmetrically encrypted symmetric key
int shick_crypto_dec_message(recipient_secret_key, sender_public_key,
    encrypted_symmetric_key, ciphertext, cipertext_len, nonce, message)
```

The results to send to each recipient are the chosen nonce, the encrypted symmetric key for the particular recipient, and the ciphertext.

### Example

This example is an excerpt from the example in [examples/examples1.c](https://github.com/lukaspustina/shick_crypto/blob/master/examples/example1.c). See there for a full example.

```
  SC_CHAR message[] = "Shick Crypto Lib"; // Message to send

  int amount_of_recipients = 1; // Number of recipients
  const SC_CHAR* recipient_public_keys[amount_of_recipients]; // List of recipients

  // Buffer Alice' and Bob's key pairs
  SC_CHAR alice_secret_key[crypto_box_SECRETKEYBYTES];
  SC_CHAR alice_public_key[crypto_box_PUBLICKEYBYTES];
  SC_CHAR bob_secret_key[crypto_box_SECRETKEYBYTES];
  SC_CHAR bob_public_key[crypto_box_PUBLICKEYBYTES];

  // Buffers for nonce, ciphertext, and encrypted symmetric keys
  SC_CHAR nonce[crypto_box_NONCEBYTES];
  SC_CHAR ciphertext[crypto_box_MACBYTES + sizeof message]; // Space for MAC
  SC_ENC_SYM_KEY encrypted_symmetric_keys[amount_of_recipients];

  SC_CHAR message_decrypted[sizeof message]; // Buffer for roundtrip decrypted message

  shick_crypto_init(); // Init libsodium

  // Create Alice' and Bob's key pairs
  shick_crypto_create_asymmetric_key_pair(alice_secret_key, alice_public_key);
  shick_crypto_create_asymmetric_key_pair(bob_secret_key, bob_public_key);
  recipient_public_keys[0] = bob_public_key;

  shick_create_nonce(nonce, sizeof nonce); // Create nonce for asymmetric encryption

  // Encrypt and sign from Alice to Bob
  shick_crypto_enc_message(alice_secret_key, recipient_public_keys, 
    amount_of_recipients, message, sizeof message, nonce, encrypted_symmetric_keys, ciphertext);
  // Now your message is encrypted for Bob and Bobby
  // Send (nonce, encrypted_symmetric_keys[i], ciphertext) to Bob and Bobby

  // Decrypt and verify signature for Bob from Alice
  shick_crypto_dec_message(bob_secret_key, alice_public_key, 
    encrypted_symmetric_keys[0], ciphertext, sizeof ciphertext, nonce, message_decrypted);
```

Send securely.

