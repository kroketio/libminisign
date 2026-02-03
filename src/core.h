#pragma once
#include "minisign/globals.h"

int set_config_directory(const char* config_dir);

PubkeyStruct *pubkey_load(const char *pubkey_s);
PubkeyStruct *pubkey_load_file(const char *pk_file);

SeckeyStruct *seckey_load_file(const char* key_path, char *const password, char *const sk_comment_line);
int generate_keys(const char* path_pubkey, const char* path_seckey, const char *comment, const char *password);

int sign_file(
    const PubkeyStruct *pubkey_struct,
    const SeckeyStruct *seckey_struct,
    const char *path_in,
    const char *path_out_sig,
    const char *comment,
    const char *trusted_comment,
    int verification);

int sign_memory(
    const PubkeyStruct *pubkey_struct,
    const SeckeyStruct *seckey_struct,
    const unsigned char *message_contents, size_t message_len,
    const char *comment, const char *trusted_comment,
    char **out_sig, size_t *out_sig_len,
    int verification);

int verify(
    const PubkeyStruct* pubkey_struct,
    const unsigned char* message_contents,
    unsigned int message_size,
    const char* sig_contents);

char* read_file(const char* path);