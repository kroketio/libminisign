#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define MINISIGN_API __attribute__((visibility("default")))
#else
#define MINISIGN_API
#endif

#include "globals.h"
#include <sodium.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>

/**
 * Sets up Sodium, the keys directory, and loads/generates keys as needed.
 *
 * @param path_keys_directory     Path to config directory.
 * @param password                Optional password for the secret key.
 *
 * @return 1 on success, 0 on failure.
 */
MINISIGN_API int minisign_init(
    const char* path_keys_directory,
    const char* password);

/**
 * Signs a file.
 *
 * The file at `path_message` will be signed, and the
 * signature will be written to `path_sig`. Optional human-readable comments
 * and trusted comments can be embedded in the signature.
 *
 * @param path_message    Path to the message file to sign.
 * @param path_sig        Path to the output signature file.
 * @param comment         Comment to include in the signature
 * @param trusted_comment Trusted comment to include in the signature (optional)
 * @param verification    If 1, before writing the file, verify the generated signature (optional)
 *
 * @return 1 on success, 0 on failure.
 */
MINISIGN_API int minisign_sign_file(
    const char* path_message,
    const char* path_sig,
    const char* comment,
    const char* trusted_comment,
    int verification);

/**
 * Signs a message and produces a signature.
 *
 * The given message buffer will be signed, and the
 * resulting signature will be returned in `out_sig`. Optional comments can
 * be embedded in the signature. The caller is responsible for freeing
 * the allocated signature buffer.
 *
 * performance: ~0.5ms (debug build) for trivial data (few sentences)
 *
 * Example:
 *
 * @param message         Pointer to the message buffer to sign.
 * @param message_len     Length of the message buffer.
 * @param comment         Optional comment to include in the signature.
 * @param trusted_comment Optional trusted comment to include in the signature.
 * @param out_sig         Output pointer to the generated signature buffer.
 * @param out_sig_len     Output length of the generated signature buffer.
 * @param verification    If 1, before writing the file, verify the generated signature (optional)
 *
 * @return 1 on success, 0 on failure.
 */
MINISIGN_API int minisign_sign(
    const unsigned char* message,
    size_t message_len,
    const char* comment,
    const char* trusted_comment,
    char** out_sig,
    size_t* out_sig_len,
    int verification);

/**
 * Verifies a signed file against a public key.
 *
 * The file at `path_message` will be checked against the signature
 * at `path_sig` using the provided public key string.
 *
 * @param pubkey_s       The public key to use for verification, in string format.
 * @param path_message   Path to the message file to verify.
 * @param path_sig       Path to the signature file to verify.
 *
 * @return 1 if the signature is valid, 0 otherwise.
 */
MINISIGN_API int minisign_verify_file(
    const char* pubkey_s,
    const char* path_message,
    const char* path_sig);

/**
 * Verifies a signed message buffer against a public key.
 *
 * The given message buffer and signature will be checked using
 * the provided public key string.
 *
 * @param pubkey_s         The public key to use for verification, in string format.
 * @param message_contents Pointer to the message buffer to verify.
 * @param message_size     Length of the message buffer.
 * @param message_sig      Signature string to verify against.
 *
 * @return 1 if the signature is valid, 0 otherwise.
 */
MINISIGN_API int minisign_verify(
    const char* pubkey_s,
    const unsigned char* message_contents,
    unsigned int message_size,
    const char* message_sig);

/* do not free PATH_SK */
MINISIGN_API inline const char* minisign_get_sk_path() {
    return PATH_SK;
}

/* do not free PATH_PK */
MINISIGN_API inline const char* minisign_get_pk_path() {
    return PATH_PK;
}

#ifdef __cplusplus
}
#endif
