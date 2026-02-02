#pragma once
#include "minisign/globals.h"

int set_config_directory(const char* config_dir);

PubkeyStruct *pubkey_load(const char *pubkey_s, int *res);
PubkeyStruct *pubkey_load_file(const char *pk_file, int *res);

SeckeyStruct *seckey_load(char *const pwd, char *const sk_comment_line, int* res);
int generate_keys(const char *comment, int unencrypted_key);

int sign_file(
  const PubkeyStruct *pubkey_struct,
  const char *path_message,
  const char *path_sig,
  const char *comment,
  const char *trusted_comment,
  int verification);

int sign_memory(const PubkeyStruct *pubkey_struct,
                 const unsigned char *message_contents, size_t message_len,
                 const char *comment, const char *trusted_comment,
                 char **out_sig, size_t *out_sig_len,
                 int verification);

int verify(
    const PubkeyStruct* pubkey_struct,
    const unsigned char* message_contents,
    unsigned int message_size,
    const char* sig_contents);
