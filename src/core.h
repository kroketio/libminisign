#pragma once
#include <stdbool.h>
#include "minisign/globals.h"

bool set_config_directory(const char* config_dir);

PubkeyStruct *pubkey_load(const char *pubkey_s, bool *res);
PubkeyStruct *pubkey_load_file(const char *pk_file, bool *res);

SeckeyStruct *seckey_load(char *const pwd, char *const sk_comment_line, bool *res);
bool generate_keys(const char *comment, int unencrypted_key);

bool sign_file(
  const PubkeyStruct *pubkey_struct,
  const char *path_message,
  const char *path_sig,
  const char *comment,
  const char *trusted_comment,
  bool verification);

bool sign_memory(const PubkeyStruct *pubkey_struct,
                 const unsigned char *message_contents, size_t message_len,
                 const char *comment, const char *trusted_comment,
                 char **out_sig, size_t *out_sig_len,
                 bool verification);

bool verify(
    PubkeyStruct *pubkey_struct,
    const unsigned char *message_contents,
    unsigned int message_size,
    const char *sig_contents);
