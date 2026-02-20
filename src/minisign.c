#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <inttypes.h>

#include <minisign/minisign.h>
#include <minisign/globals.h>

#include "core.h"
#include "helpers.h"
#include "base64.h"

static int
ensure_minisign_init() {
  if (!MINISIGN_INIT) {
    minisign_err("minisign: call minisign_init(key_dir) first");
    return 0;
  }
  return 1;
}

static int
ensure_valid_key_dir_name(const char *key_dir) {
  const size_t len = strlen(key_dir);
  if (len == 0 || key_dir[len-1] != '/') {
    minisign_err("argument 'key_dir' must end with /");
    return 0;
  }
  return 1;
}

int
minisign_validate_key_name(const char* s) {
  if (!s || !*s)
    return 0;
  for (; *s; s++) {
    if (!((*s >= 'a' && *s <= 'z') ||
        (*s >= 'A' && *s <= 'Z') ||
        (*s >= '0' && *s <= '9') ||
        *s == '_'))
      return 0;
  }
  return 1;
}

int
minisign_init(char* key_dir) {
  if (!ensure_valid_key_dir_name(key_dir)) return 0;
  if (sodium_init() != 0) {
    minisign_err("Unable to initialize the Sodium library");
    return 0;
  }

  // create key_dir if it does not exist yet
  struct stat st;
  if (stat(key_dir, &st) == 0) {
    if (!S_ISDIR(st.st_mode))
      return minisign_err("%s exists but is not a directory", key_dir), 0;
  } else if (errno == ENOENT) {
    if (mkdir(key_dir, 0700) != 0)
      return perror("mkdir"), 0;
  } else {
    return minisign_err("%s exists but is not a directory", key_dir), 0;
  }

  if (!set_config_directory(key_dir)) {
    minisign_err("%s exists but is not a directory", key_dir);
    return 0;
  }

  MINISIGN_INIT = 1;
  return 1;
}

int
minisign_generate(const char* key_name, const char* key_dir, const char* password) {
  if (!ensure_valid_key_dir_name(key_dir)) return 0;
  if (!ensure_minisign_init()) return 0;
  if (!minisign_validate_key_name(key_name)) {
    minisign_err("Illegal key name: %s", key_name);
    return 0;
  }

  char priv_path[PATH_MAX] = {0};
  char pub_path[PATH_MAX] = {0};

  if (!safe_copy(priv_path, sizeof(priv_path), key_dir)) {
    minisign_err("key dir too long");
    return 0;
  }

  if (!safe_join(priv_path, sizeof(priv_path), priv_path, key_name)) {
    minisign_err("private key path too long");
    return 0;
  }

  if (!safe_copy(pub_path, sizeof(pub_path), priv_path)) {
    minisign_err("private key path too long");
    return 0;
  }

  if (!safe_join(pub_path, sizeof(pub_path), pub_path, ".pub")) {
    minisign_err("public key path too long");
    return 0;
  }

  if (access(priv_path, F_OK) == 0) {
    minisign_err("Key file already exists: %s", priv_path);
    return 0;
  }

  if (access(pub_path, F_OK) == 0) {
    minisign_err("Key file already exists: %s", pub_path);
    return 0;
  }

  const char *comment = SECRETKEY_DEFAULT_COMMENT;
  if (!generate_keys(pub_path, priv_path, comment, password)) {
    minisign_err("Failed to generate keys");
    return 0;
  }

  return 1;
}

int
minisign_sign(
    const char* key_name,
    const char* key_dir,
    char* password,
    const unsigned char* message,
    const size_t message_len,
    const char* comment,
    const char* trusted_comment,
    char** out_sig,
    size_t* out_sig_len,
    int verification) {
  if (!ensure_valid_key_dir_name(key_dir)) return 0;
  if (!ensure_minisign_init()) return 0;
  if (!minisign_validate_key_name(key_name)) {
    minisign_err("Illegal key name: %s", key_name);
    return 0;
  }

  char priv_path[PATH_MAX] = {0};
  char pub_path[PATH_MAX] = {0};

  if (!safe_copy(priv_path, sizeof(priv_path), key_dir)) {
    minisign_err("key dir too long");
    return 0;
  }

  if (!safe_join(priv_path, sizeof(priv_path), priv_path, key_name)) {
    minisign_err("private key path too long");
    return 0;
  }

  if (!safe_copy(pub_path, sizeof(pub_path), priv_path)) {
    minisign_err("private key path too long");
    return 0;
  }

  if (!safe_join(pub_path, sizeof(pub_path), pub_path, ".pub")) {
    minisign_err("public key path too long");
    return 0;
  }

  if (access(priv_path, F_OK) != 0) {
    minisign_err("Private key file not found: %s", priv_path);
    return 0;
  }

  if (access(pub_path, F_OK) != 0) {
    minisign_err("Public key file not found: %s", pub_path);
    return 0;
  }

  const PubkeyStruct* pubkey_struct = pubkey_load_file(pub_path);
  if (!pubkey_struct) {
    minisign_err("Failed to load public key from: %s", pub_path);
    return 0;
  }

  char sk_comment_line_buf[COMMENTMAXBYTES];
  const SeckeyStruct* seckey_struct = seckey_load_file(priv_path, password, sk_comment_line_buf);
  if (!seckey_struct) {
    minisign_err("Failed to load private key from: %s", priv_path);
    return 0;
  }

  if (!sign_memory(pubkey_struct, seckey_struct, message, message_len,
                   comment, trusted_comment, out_sig, out_sig_len, 1)) {
    minisign_err("Signing failed: %s", priv_path);
    return 0;
  }

  return 1;
}

int
minisign_sign_file(
    const char* key_name,
    const char* key_dir,
    char* password,
    const char* path_in,
    const char* path_out_sig,
    const char* comment,
    const char* trusted_comment,
    int verification) {
  if (!ensure_valid_key_dir_name(key_dir)) return 0;
  if (!ensure_minisign_init()) return 0;
  if (!minisign_validate_key_name(key_name)) {
    minisign_err("Illegal key name: %s", key_name);
    return 0;
  }

  char priv_path[PATH_MAX] = {0};
  char pub_path[PATH_MAX] = {0};

  if (!safe_copy(priv_path, sizeof(priv_path), key_dir)) {
    minisign_err("key dir too long");
    return 0;
  }

  if (!safe_join(priv_path, sizeof(priv_path), priv_path, key_name)) {
    minisign_err("private key path too long");
    return 0;
  }

  if (!safe_copy(pub_path, sizeof(pub_path), priv_path)) {
    minisign_err("private key path too long");
    return 0;
  }

  if (!safe_join(pub_path, sizeof(pub_path), pub_path, ".pub")) {
    minisign_err("public key path too long");
    return 0;
  }

  if (access(priv_path, F_OK) != 0) {
    minisign_err("Private key file not found: %s", priv_path);
    return 0;
  }

  if (access(pub_path, F_OK) != 0) {
    minisign_err("Public key file not found: %s", pub_path);
    return 0;
  }

  const PubkeyStruct* pubkey_struct = pubkey_load_file(pub_path);
  if (!pubkey_struct) {
    minisign_err("Failed to load public key from: %s", pub_path);
    return 0;
  }

  char sk_comment_line_buf[COMMENTMAXBYTES];
  const SeckeyStruct* seckey_struct = seckey_load_file(priv_path, password, sk_comment_line_buf);
  if (!seckey_struct) {
    minisign_err("Failed to load private key from: %s", priv_path);
    return 0;
  }

  if (!sign_file(pubkey_struct, seckey_struct, path_in, path_out_sig, comment, trusted_comment, 0)) {
    minisign_err("Signing failed: %s", priv_path);
    return 0;
  }

  return 1;
}

int
minisign_verify_file(
    const char* key_name,
    const char* key_dir,
    const char* path,
    const char* path_sig) {
  if (!ensure_valid_key_dir_name(key_dir)) return 0;
  if (!ensure_minisign_init()) return 0;
  if (!minisign_validate_key_name(key_name)) {
    minisign_err("Illegal key name: %s", key_name);
    return 0;
  }

  char priv_path[PATH_MAX] = {0};
  char pub_path[PATH_MAX] = {0};

  if (!safe_copy(priv_path, sizeof(priv_path), key_dir)) {
    minisign_err("key dir too long");
    return 0;
  }

  if (!safe_join(priv_path, sizeof(priv_path), priv_path, key_name)) {
    minisign_err("private key path too long");
    return 0;
  }

  if (!safe_copy(pub_path, sizeof(pub_path), priv_path)) {
    minisign_err("private key path too long");
    return 0;
  }

  if (!safe_join(pub_path, sizeof(pub_path), pub_path, ".pub")) {
    minisign_err("public key path too long");
    return 0;
  }

  PubkeyStruct* pubkey_struct = pubkey_load_file(pub_path);
  if (!pubkey_struct) {
    minisign_err("failed to load public key from %s", pub_path);
    return 0;
  }

  char* message_contents = read_file(path);
  if (!message_contents) return 0;

  char* sig_contents = read_file(path_sig);
  if (!sig_contents) {
    free(message_contents);
    return 0;
  }

  const int res = verify(pubkey_struct, (unsigned char*)message_contents, strlen(message_contents), sig_contents);
  free(message_contents);
  free(sig_contents);
  return res;
}

int
minisign_verify(
    const char* pubkey_string,
    const unsigned char* message_contents,
    const unsigned int message_size,
    const char* message_sig) {
  if (!ensure_minisign_init()) return 0;
  int res = 0;

  if (message_sig == NULL) {
    minisign_err("you did not provide the signature contents");
    return 0;
  }

  if (message_contents == NULL) {
    minisign_err("you did not provide a message");
    return 0;
  }

  if (message_size == 0) {
    minisign_err("you did not provide the message size");
    return 0;
  }

  PubkeyStruct* pubkey_struct = pubkey_load(pubkey_string);
  if (!pubkey_struct) {
    return 0;
  }

  res = verify(pubkey_struct, message_contents, message_size, message_sig);
  sodium_free(pubkey_struct);
  return res;
}

char*
minisign_read_pubkey(const char* key_name, const char* key_dir) {
  char pub_path[PATH_MAX] = {0};

  if (!safe_copy(pub_path, sizeof(pub_path), key_dir)) {
    minisign_err("key dir too long");
    return NULL;
  }

  if (!safe_join(pub_path, sizeof(pub_path), pub_path, key_name)) {
    minisign_err("pub key path too long");
    return NULL;
  }

  if (!safe_join(pub_path, sizeof(pub_path), pub_path, ".pub")) {
    minisign_err("public key path too long");
    return 0;
  }

  char* res = read_file(pub_path);
  if (!res) {
    minisign_err("Failed to read public key from %s", pub_path);
    return NULL;
  }

  return res;
}

char*
minisign_read_seckey(const char* key_name, const char* key_dir) {
  char priv_path[PATH_MAX] = {0};

  if (!safe_copy(priv_path, sizeof(priv_path), key_dir)) {
    minisign_err("key dir too long");
    return NULL;
  }

  if (!safe_join(priv_path, sizeof(priv_path), priv_path, key_name)) {
    minisign_err("private key path too long");
    return NULL;
  }

  char* res = read_file(priv_path);
  if (!res) {
    minisign_err("Failed to read private key from %s", priv_path);
    return NULL;
  }
  return res;
}

int
safe_copy(char *dst, const size_t n, const char *src) {
  const size_t l = strlen(src);

  if (l >= n)
    return 0;

  memcpy(dst, src, l + 1);
  return 1;
}

int
safe_join(char *dst, const size_t n, const char *a, const char *b) {
  const size_t al = strlen(a);
  const size_t bl = strlen(b);

  if (al + bl >= n)
    return 0;

  memmove(dst, a, al);
  memmove(dst + al, b, bl);
  dst[al + bl] = 0;
  return 1;
}