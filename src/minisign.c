#include "inttypes.h"

#include <minisign/minisign.h>
#include <minisign/globals.h>

#include "core.h"
#include "helpers.h"
#include "base64.h"

int minisign_init(const char* path_keys_directory, const char* password) {
  if (sodium_init() != 0) {
    fprintf(stderr, "Unable to initialize the Sodium library\n");
    return 0;
  }

  PWD = xsodium_malloc(PASSWORDMAXBYTES);
  snprintf(PWD, PASSWORDMAXBYTES, "%s", password);

  if (!set_config_directory(path_keys_directory))
    return 0;

  // pubkey/privkey exist?
  struct stat st;
  int pk_found = 1;
  int sk_found = 1;

  if (stat(PATH_PK, &st) != 0)
    pk_found = 0;
  if (stat(PATH_SK, &st) != 0)
    sk_found = 0;

  // auto-gen
  if(!sk_found && !pk_found) {
    const int unencrypted_key = 0;
    const char *comment = NULL;
    comment = SECRETKEY_DEFAULT_COMMENT;
    generate_keys(comment, unencrypted_key);
  // one present while the other is not = error
  } else if((pk_found && !sk_found) || (!pk_found && sk_found)) {
    if(pk_found) {
      fprintf(stderr, "minisign: error: %s found, but not %s", PATH_PK, PATH_SK);
      return 0;
    }

    fprintf(stderr, "minisign: error: %s found, but not %s", PATH_SK, PATH_PK);
    return 0;
  }

  char sk_comment_line_buf[COMMENTMAXBYTES];
  int res = 0;
  SECKEY = seckey_load(PWD, sk_comment_line_buf, &res);
  if(!res)
    return 0;

  PUBKEY = pubkey_load_file(PATH_PK, &res);
  if(!res)
    return 0;

  MINISIGN_INIT = 1;
  return 1;
}

int minisign_sign_file(
  const char* path_message,
  const char* path_sig,
  const char* comment,
  const char* trusted_comment,
  int verification) {

  if (!MINISIGN_INIT) {
    fprintf(stderr, "minisign: call minisign_init() before using %s\n", __func__);
    return 0;
  }

  int res = 0;
  const PubkeyStruct* pubkey_struct = pubkey_load_file(PATH_PK, &res);
  if (!res) {
    fprintf(stderr, "minisign: error: failed to load public key from %s\n", PATH_PK);
    return 0;
  }

  return sign_file(
    pubkey_struct, path_message, path_sig,
    comment, trusted_comment, verification);
}

int minisign_sign(
  const unsigned char* message,
  size_t message_len,
  const char* comment,
  const char* trusted_comment,
  char** out_sig,
  size_t* out_sig_len,
  int verification) {

  if (!MINISIGN_INIT) {
    fprintf(stderr, "minisign: call minisign_init() before using %s\n", __func__);
    return 0;
  }

  int res = 0;
  const PubkeyStruct* pubkey_struct = pubkey_load_file(PATH_PK, &res);
  if (!res) {
    fprintf(stderr, "minisign: error: failed to load public key from %s\n", PATH_PK);
    return 0;
  }

  if (!sign_memory(
      pubkey_struct, message, message_len,
      comment, trusted_comment,
      out_sig, out_sig_len, 1) != 0) {
    fprintf(stderr, "Signing failed\n");
    return 0;
  }

  return 1;
}

int minisign_verify_file(
  const char* pubkey_s,
  const char* path_message,
  const char* path_sig) {
  int res = 0;
  PubkeyStruct* pubkey_struct;

  const int custom_pubkey = pubkey_s != NULL ? 1 : 0;

  if (!custom_pubkey) {
    pubkey_struct = PUBKEY;
  } else {
    pubkey_struct = pubkey_load(pubkey_s, &res);
    if (!res) {
      fprintf(stderr, "minisign: error: failed to load public key from %s\n", pubkey_s);
      sodium_free(pubkey_struct);
      return 0;
    }
  }

  // file
  long msg_size;
  long sig_size;
  FILE *fp_msg = fopen(path_message, "rb");
  if (!fp_msg) {
    fprintf(stderr, "minisig: error: could not open %s\n", path_message);
    if (custom_pubkey)
      sodium_free(pubkey_struct);
    return 0;
  }

  fseek(fp_msg, 0, SEEK_END);
  msg_size = ftell(fp_msg);
  rewind(fp_msg);

  unsigned char *message_contents = malloc(msg_size + 1);
  if (!message_contents) {
    free(message_contents);
    if (custom_pubkey)
      sodium_free(pubkey_struct);
    fprintf(stderr, "minisig: error: memory %s\n", path_message);
    return 0;
  }

  fread(message_contents, 1, msg_size, fp_msg);
  message_contents[msg_size] = '\0';
  fclose(fp_msg);

  // sig file
  FILE *fp_sig = fopen(path_sig, "rb");
  if (!fp_sig) {
    fprintf(stderr, "minisig: error: could not open %s\n", path_sig);
    if (custom_pubkey)
      sodium_free(pubkey_struct);
    free(message_contents);
    return 0;
  }

  fseek(fp_sig, 0, SEEK_END);
  sig_size = ftell(fp_sig);
  rewind(fp_sig);

  char *sig_contents = malloc(sig_size + 1);
  if (!sig_contents) {
    free(message_contents);
    free(sig_contents);
    if (custom_pubkey)
      sodium_free(pubkey_struct);
    fprintf(stderr, "minisig: error: could not open %s\n", path_sig);
    return 0;
  }

  fread(sig_contents, 1, sig_size, fp_sig);
  sig_contents[sig_size] = '\0';

  fclose(fp_sig);

  res = verify(pubkey_struct, message_contents, msg_size, sig_contents);
  free(message_contents);
  free(sig_contents);
  if (custom_pubkey)
    sodium_free(pubkey_struct);

  return res;
}

int minisign_verify(
  const char* pubkey_s,
  const unsigned char* message_contents,
  const unsigned int message_size,
  const char* sig_contents) {
  int res = 0;
  PubkeyStruct* pubkey_struct;

  if (sig_contents == NULL) {
    fprintf(stderr, "minisign: error: you did not provide the signature contents");
    return 0;
  }

  if (message_contents == NULL) {
    fprintf(stderr, "minisign: error: you did not provide a message");
    return 0;
  }

  if (message_size == 0) {
    fprintf(stderr, "minisign: error: you did not provide the message size");
    return 0;
  }

  const int custom_pubkey = pubkey_s != NULL ? 1 : 0;

  if (!custom_pubkey) {
    pubkey_struct = PUBKEY;
  } else {
    pubkey_struct = pubkey_load(pubkey_s, &res);
    if (!res) {
      fprintf(stderr, "minisign: error: failed to load public key from %s\n", pubkey_s);
      return 0;
    }
  }

  res = verify(pubkey_struct, message_contents, message_size, sig_contents);
  if (custom_pubkey)
    sodium_free(pubkey_struct);
  return res;
}