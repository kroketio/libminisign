#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <sodium.h>

// #define minisign_err(...) \
//     fprintf(stderr, "%s:%d: ", strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__, __LINE__), \
//     fprintf(stderr, __VA_ARGS__), \
//     fprintf(stderr, "\n")


static inline void minisign_err_impl(const char* file, int line, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "%s:%d: ", file, line);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

#define minisign_err(...) \
    minisign_err_impl(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__, __LINE__, __VA_ARGS__)

extern char* CONFIG_DIR;
extern int MINISIGN_INIT;

#define COMMENTMAXBYTES                1024
#define KEYNUMBYTES                    8
#define PASSWORDMAXBYTES               1024
#define TRUSTEDCOMMENTMAXBYTES         8192
#define SIGALG                         "Ed"
#define SIGALG_HASHED                  "ED"
#define KDFALG                         "Sc"
#define KDFNONE                        "\0\0"
#define CHKALG                         "B2"
#ifndef COMMENT_PREFIX
#define COMMENT_PREFIX "untrusted comment: "
#endif
#ifndef TRUSTED_COMMENT_PREFIX
#define TRUSTED_COMMENT_PREFIX "trusted comment: "
#endif
#define DEFAULT_COMMENT                "signature from minisign secret key"
#define SECRETKEY_DEFAULT_COMMENT      "minisign encrypted secret key"
#define SIG_DEFAULT_CONFIG_DIR         ".minisign"
#define SIG_DEFAULT_CONFIG_DIR_ENV_VAR "MINISIGN_CONFIG_DIR"
#define SIG_DEFAULT_PKFILE             "minisign.pub"
#define SIG_DEFAULT_SKFILE             "minisign.key"
#define SIG_SUFFIX                     ".minisig"
#define VERSION_STRING                 "minisign 0.12"

typedef struct KeynumSK_ {
    unsigned char keynum[KEYNUMBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char chk[crypto_generichash_BYTES];
} KeynumSK;

typedef struct KeynumPK_ {
    unsigned char keynum[KEYNUMBYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
} KeynumPK;

typedef struct SeckeyStruct_ {
    unsigned char sig_alg[2];
    unsigned char kdf_alg[2];
    unsigned char chk_alg[2];
    unsigned char kdf_salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    unsigned char kdf_opslimit_le[8];
    unsigned char kdf_memlimit_le[8];
    KeynumSK      keynum_sk;
} SeckeyStruct;

typedef struct PubkeyStruct_ {
    unsigned char sig_alg[2];
    KeynumPK      keynum_pk;
} PubkeyStruct;

typedef struct SigStruct_ {
    unsigned char sig_alg[2];
    unsigned char keynum[KEYNUMBYTES];
    unsigned char sig[crypto_sign_BYTES];
} SigStruct;

typedef enum Action_ {
    ACTION_NONE,
    ACTION_GENERATE,
    ACTION_SIGN,
    ACTION_VERIFY,
    ACTION_RECREATE_PK,
    ACTION_UPDATE_PASSWORD
} Action;

#ifdef __cplusplus
}
#endif