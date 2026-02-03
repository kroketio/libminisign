#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define MINISIGN_API __attribute__((visibility("default")))
#else
#define MINISIGN_API
#endif

#include <sodium.h>

#include "globals.h"

/**
 * Initializes minisign and the Sodium library, and sets the key directory.
 *
 * @param key_dir  Path to the directory where keys are stored.
 *
 * @return 1 on success, 0 on failure.
 */
MINISIGN_API int
minisign_init(char* key_dir);

/**
 * Generates a new key pair.
 *
 * @param key_name  Name of the key to generate.
 * @param key_dir   Directory where keys should be stored.
 * @param password  Optional password for encrypting the secret key.
 *
 * @return 1 on success, 0 on failure.
 */
MINISIGN_API int
minisign_generate(const char* key_name, const char* key_dir, const char* password);

/**
 * Signs a message buffer and returns the generated signature.
 *
 * @param key_name          Key name to use for signing.
 * @param key_dir           Directory where keys are stored.
 * @param password          Optional password for the secret key.
 * @param message           Pointer to the message buffer to sign.
 * @param message_len       Length of the message buffer.
 * @param comment           Optional comment to include in the signature.
 * @param trusted_comment   Optional trusted comment to include in the signature.
 * @param out_sig           Output pointer to store the generated signature buffer.
 * @param out_sig_len       Output length of the generated signature buffer.
 * @param verification      If 1, verify the generated signature before returning.
 *
 * @return 1 on success, 0 on failure.
 */
MINISIGN_API int
minisign_sign(
    const char* key_name,
    const char* key_dir,
    char* password,
    const unsigned char* message,
    size_t message_len,
    const char* comment,
    const char* trusted_comment,
    char** out_sig,
    size_t* out_sig_len,
    int verification);

/**
 * Signs a file and writes the signature to a separate file.
 *
 * @param key_name          Key name to use for signing.
 * @param key_dir           Directory where keys are stored.
 * @param password          Optional password for the secret key.
 * @param path_in           Path to the input message file.
 * @param path_out_sig      Path to the output signature file.
 * @param comment           Optional comment to include in the signature.
 * @param trusted_comment   Optional trusted comment to include in the signature.
 * @param verification      If 1, verify the generated signature before writing.
 *
 * @return 1 on success, 0 on failure.
 */
MINISIGN_API int
minisign_sign_file(
    const char* key_name,
    const char* key_dir,
    char* password,
    const char* path_in,
    const char* path_out_sig,
    const char* comment,
    const char* trusted_comment,
    int verification);

/**
 * Verifies a signed file against a public key.
 *
 * @param key_name  Key name to use for verification.
 * @param key_dir   Directory where keys are stored.
 * @param path      Path to the message file.
 * @param path_sig  Path to the signature file.
 *
 * @return 1 if valid, 0 if invalid or error.
 */
MINISIGN_API int
minisign_verify_file(
    const char* key_name,
    const char* key_dir,
    const char* path,
    const char* path_sig);

/**
 * Verifies a signed message buffer against a public key string.
 *
 * @param pubkey_string     Public key in string format.
 * @param message_contents  Pointer to the message buffer to verify.
 * @param message_size      Length of the message buffer.
 * @param message_sig       Signature string to verify against.
 *
 * @return 1 if valid, 0 if invalid or error.
 */
MINISIGN_API int
minisign_verify(
    const char* pubkey_string,
    const unsigned char* message_contents,
    unsigned int message_size,
    const char* message_sig);

/**
 * Validates a key name string (alphanumeric + underscore only).
 *
 * @param s  Key name string to validate.
 *
 * @return 1 if valid, 0 if invalid.
 */
MINISIGN_API int
minisign_validate_key_name(const char* s);

/**
 * Reads a public key file and returns its contents as a string.
 *
 * @param key_name  Name of the key.
 * @param key_dir   Directory where keys are stored.
 *
 * @return Pointer to a string containing the public key, or NULL on failure.
 */
MINISIGN_API char*
minisign_read_pubkey(
    const char* key_name,
    const char* key_dir);

/**
 * Reads a secret key file and returns its contents as a string.
 *
 * @param key_name  Name of the key.
 * @param key_dir   Directory where keys are stored.
 *
 * @return Pointer to a string containing the secret key, or NULL on failure.
 */
MINISIGN_API char*
minisign_read_seckey(
    const char* key_name,
    const char* key_dir);

#ifdef __cplusplus
}
#endif
