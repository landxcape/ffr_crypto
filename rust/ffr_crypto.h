#ifndef FFR_CRYPTO_H
#define FFR_CRYPTO_H

#include <stddef.h>

void ffr_crypto_free_string(char* ptr);
void ffr_crypto_free_bytes(unsigned char* ptr, size_t len);
int ffr_crypto_random_bytes(unsigned char* buf, size_t len);
int ffr_crypto_rsa_generate_keypair(unsigned int key_size, char** pub_pem, char** priv_pem);
int ffr_crypto_rsa_encrypt(const char* pub_key_pem, const unsigned char* plaintext, size_t plaintext_len, unsigned char** out_ciphertext, size_t* out_len);
int ffr_crypto_rsa_decrypt(const char* priv_key_pem, const unsigned char* ciphertext, size_t ciphertext_len, unsigned char** out_plaintext, size_t* out_len);
int ffr_crypto_rsa_sign(const char* priv_key_pem, const unsigned char* digest, size_t digest_len, unsigned char** out_sig, size_t* out_sig_len);
int ffr_crypto_rsa_verify(const char* pub_key_pem, const unsigned char* digest, size_t digest_len, const unsigned char* sig, size_t sig_len);

struct HasherContext;
typedef struct HasherContext HasherContext;

int ffr_crypto_hasher_new(int alg_id, HasherContext** out_hasher);
int ffr_crypto_hasher_update(HasherContext* hasher, const unsigned char* data, size_t len);
int ffr_crypto_hasher_finalize(HasherContext* hasher, unsigned char** out_digest, size_t* out_len);
void ffr_crypto_hasher_free(HasherContext* hasher);

int ffr_crypto_aes_gcm_encrypt(const unsigned char* key, size_t key_len, const unsigned char* plaintext, size_t plaintext_len, const unsigned char* nonce, size_t nonce_len, const unsigned char* aad, size_t aad_len, unsigned char** out_ciphertext, size_t* out_len);
int ffr_crypto_aes_gcm_decrypt(const unsigned char* key, size_t key_len, const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* nonce, size_t nonce_len, const unsigned char* aad, size_t aad_len, unsigned char** out_plaintext, size_t* out_len);
int ffr_crypto_chacha20_poly1305_encrypt(const unsigned char* key, size_t key_len, const unsigned char* plaintext, size_t plaintext_len, const unsigned char* nonce, size_t nonce_len, const unsigned char* aad, size_t aad_len, unsigned char** out_ciphertext, size_t* out_len);
int ffr_crypto_chacha20_poly1305_decrypt(const unsigned char* key, size_t key_len, const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* nonce, size_t nonce_len, const unsigned char* aad, size_t aad_len, unsigned char** out_plaintext, size_t* out_len);

int ffr_crypto_pbkdf2(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int iterations, unsigned char* out_key, size_t out_key_len);
int ffr_crypto_hkdf(const unsigned char* ikm, size_t ikm_len, const unsigned char* salt, size_t salt_len, const unsigned char* info, size_t info_len, unsigned char* out_key, size_t out_key_len);
int ffr_crypto_argon2(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned int m_cost, unsigned int t_cost, unsigned int p_cost, int variant, unsigned char* out_key, size_t out_key_len);

int ffr_crypto_ed25519_generate_keypair(unsigned char* out_pub, unsigned char* out_priv);
int ffr_crypto_ed25519_sign(const unsigned char* priv_key, const unsigned char* message, size_t message_len, unsigned char* out_sig);
int ffr_crypto_ed25519_verify(const unsigned char* pub_key, const unsigned char* message, size_t message_len, const unsigned char* sig);
int ffr_crypto_x25519_generate_keypair(unsigned char* out_pub, unsigned char* out_priv);
int ffr_crypto_x25519_compute_shared_secret(const unsigned char* priv_key, const unsigned char* peer_pub_key, unsigned char* out_secret);

#endif // FFR_CRYPTO_H
