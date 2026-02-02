#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>

#include "minisign/globals.h"

#include "base64.h"
#include "helpers.h"
#include "core.h"

static unsigned char *
message_load_hashed(const unsigned char *message_contents, unsigned int message_size) {
  crypto_generichash_state hs;

  if (message_contents == NULL) {
    fprintf(stderr, "message_contents is NULL\n");
    exit(EXIT_FAILURE);
  }

  crypto_generichash_init(&hs, NULL, 0U, crypto_generichash_BYTES_MAX);
  crypto_generichash_update(&hs, (const unsigned char *) message_contents, message_size);

  unsigned char *message = xmalloc(crypto_generichash_BYTES_MAX);
  crypto_generichash_final(&hs, message, crypto_generichash_BYTES_MAX);

  return message;
}

static unsigned char *
message_load_hashed_file(size_t *message_len, const char *message_file) {
  crypto_generichash_state hs;
  unsigned char buf[65536U];
  unsigned char *message = NULL;
  FILE *fp = NULL;
  size_t n;

  if ((fp = fopen(message_file, "rb")) == NULL) {
    exit_err(message_file);
  }

  crypto_generichash_init(&hs, NULL, 0U, crypto_generichash_BYTES_MAX);
  while ((n = fread(buf, 1U, sizeof buf, fp)) > 0U) {
    crypto_generichash_update(&hs, buf, n);
  }
  if (!feof(fp)) {
    exit_err(message_file);
  }
  xfclose(fp);
  message = xmalloc(crypto_generichash_BYTES_MAX);
  crypto_generichash_final(&hs, message, crypto_generichash_BYTES_MAX);
  *message_len = crypto_generichash_BYTES_MAX; // remove this

  return message;
}

static SigStruct *
sig_load(const char *sig_contents,
         unsigned char global_sig[crypto_sign_BYTES],
         char trusted_comment[TRUSTEDCOMMENTMAXBYTES],
         size_t trusted_comment_maxlen) {
  char comment[COMMENTMAXBYTES];
  SigStruct *sig_struct = NULL;
  char *global_sig_s = NULL;
  char *sig_s = NULL;
  size_t global_sig_len;
  size_t global_sig_s_size;
  size_t sig_s_size;
  size_t sig_struct_len;

  // duplicate contents so we can safely tokenize
  char *contents_copy = xstrdup(sig_contents);
  char *saveptr = NULL;
  char *line = strtok_r(contents_copy, "\n", &saveptr);

  if (line == NULL) {
    exit_msg("Empty signature input");
  }

  // first line: untrusted comment
  snprintf(comment, sizeof(comment), "%s", line);

  // second line: signature b64
  sig_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *sig_struct) + 2U;
  sig_s = xmalloc(sig_s_size);
  line = strtok_r(NULL, "\n", &saveptr);
  if (line == NULL) {
    exit_msg("Missing signature line");
  }
  snprintf(sig_s, sig_s_size, "%s", line);

  // third line: trusted comment
  line = strtok_r(NULL, "\n", &saveptr);
  if (line == NULL) {
    exit_msg("Trusted comment not present");
  }
  snprintf(trusted_comment, trusted_comment_maxlen, "%s", line);
  if (strncmp(trusted_comment, TRUSTED_COMMENT_PREFIX,
              (sizeof TRUSTED_COMMENT_PREFIX) - 1U) != 0) {
    exit_msg("Trusted signature comment should start with \"" TRUSTED_COMMENT_PREFIX "\"");
  }
  memmove(trusted_comment,
          trusted_comment + sizeof TRUSTED_COMMENT_PREFIX - 1U,
          strlen(trusted_comment + sizeof TRUSTED_COMMENT_PREFIX - 1U) + 1U);

  // fourth line: global signature b64
  global_sig_s_size = B64_MAX_LEN_FROM_BIN_LEN(crypto_sign_BYTES) + 2U;
  global_sig_s = xmalloc(global_sig_s_size);
  line = strtok_r(NULL, "\n", &saveptr);
  if (line == NULL) {
    exit_msg("Global signature not present");
  }
  snprintf(global_sig_s, global_sig_s_size, "%s", line);
  trim(global_sig_s);

  // no longer need the duplicated contents
  free(contents_copy);

  // convert base64 parts
  sig_struct = xmalloc(sizeof *sig_struct);
  if (b64_to_bin((unsigned char *) (void *) sig_struct, sig_s,
                 sizeof *sig_struct, strlen(sig_s),
                 &sig_struct_len) == NULL ||
      sig_struct_len != sizeof *sig_struct) {
    exit_msg("base64 conversion failed - was an actual signature given?");
  }
  free(sig_s);

  if (memcmp(sig_struct->sig_alg, SIGALG, sizeof sig_struct->sig_alg) == 0) {
    exit_msg("Unsupported signature algorithm");
  } else if (memcmp(sig_struct->sig_alg, SIGALG_HASHED, sizeof sig_struct->sig_alg) == 0) {
    // okidoki
  } else {
    exit_msg("Unsupported signature algorithm");
  }

  if (b64_to_bin(global_sig, global_sig_s,
                 crypto_sign_BYTES, strlen(global_sig_s),
                 &global_sig_len) == NULL ||
      global_sig_len != crypto_sign_BYTES) {
    exit_msg("base64 conversion failed - was an actual signature given?");
  }
  free(global_sig_s);

  return sig_struct;
}

static PubkeyStruct *
pubkey_load_string(const char *pubkey_s, int *res) {
  PubkeyStruct *pubkey_struct;
  size_t pubkey_struct_len;

  pubkey_struct = xsodium_malloc(sizeof *pubkey_struct);
  if (b64_to_bin((unsigned char *) (void *) pubkey_struct, pubkey_s, sizeof *pubkey_struct,
                 strlen(pubkey_s), &pubkey_struct_len) == NULL ||
      pubkey_struct_len != sizeof *pubkey_struct) {
    *res = 0;
    fprintf(stderr, "minisign: base64 conversion failed - was an actual public key given? %s\n", __func__);
  }
  if (memcmp(pubkey_struct->sig_alg, SIGALG, sizeof pubkey_struct->sig_alg) != 0) {
    *res = 0;
    fprintf(stderr, "minisign: Unsupported signature algorithm: %s\n", __func__);
  }
  *res = 1;
  return pubkey_struct;
}

PubkeyStruct *
pubkey_load_file(const char *pk_file, int *res) {
  char pk_comment[COMMENTMAXBYTES];
  PubkeyStruct *pubkey_struct = NULL;
  FILE *fp;
  char *pubkey_s = NULL;
  size_t pubkey_s_size;

  if ((fp = fopen(pk_file, "r")) == NULL) {
    fprintf(stderr, "minisign: error (%s): unable to open public key file: %s\n",
            __func__, pk_file);
    if (res)
      *res = 0;
    return NULL;
  }

  if (fgets(pk_comment, (int) sizeof(pk_comment), fp) == NULL) {
    fprintf(stderr, "minisign: error (%s): failed to read comment from public key file: %s\n",
            __func__, pk_file);
    fclose(fp);
    if (res)
      *res = 0;
    return NULL;
  }

  pubkey_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof(*pubkey_struct)) + 2U;
  pubkey_s = malloc(pubkey_s_size);
  if (!pubkey_s) {
    fprintf(stderr, "minisign: error (%s): memory allocation failed\n", __func__);
    fclose(fp);
    if (res)
      *res = 0;
    return NULL;
  }

  if (fgets(pubkey_s, (int) pubkey_s_size, fp) == NULL) {
    fprintf(stderr, "minisign: error (%s): failed to read public key from file: %s\n",
            __func__, pk_file);
    free(pubkey_s);
    fclose(fp);
    if (res)
      *res = 0;
    return NULL;
  }

  trim(pubkey_s);
  fclose(fp);

  pubkey_struct = pubkey_load_string(pubkey_s, res);
  free(pubkey_s);
  if (!res) {
    return NULL;
  }

  if (res)
    *res = 1;
  return pubkey_struct;
}

/* you need to free this pubkey struct */
PubkeyStruct *pubkey_load(const char *pubkey_s, int *res) {
  if (pubkey_s == NULL) {
    fprintf(stderr, "A public key is required");
    *res = 0;
    return NULL;
  }

  return pubkey_load_string(pubkey_s, res);
}

static void
seckey_compute_chk(unsigned char chk[crypto_generichash_BYTES], const SeckeyStruct *seckey_struct) {
  crypto_generichash_state hs;

  crypto_generichash_init(&hs, NULL, 0U, sizeof seckey_struct->keynum_sk.chk);
  crypto_generichash_update(&hs, seckey_struct->sig_alg, sizeof seckey_struct->sig_alg);
  crypto_generichash_update(&hs, seckey_struct->keynum_sk.keynum,
                            sizeof seckey_struct->keynum_sk.keynum);
  crypto_generichash_update(&hs, seckey_struct->keynum_sk.sk, sizeof seckey_struct->keynum_sk.sk);
  crypto_generichash_final(&hs, chk, sizeof seckey_struct->keynum_sk.chk);
}

static int
decrypt_key(char *const pwd, SeckeyStruct *const seckey_struct, unsigned char chk[crypto_generichash_BYTES]) {
  unsigned char *stream;

  stream = xsodium_malloc(sizeof seckey_struct->keynum_sk);
  if (crypto_pwhash_scryptsalsa208sha256(stream, sizeof seckey_struct->keynum_sk, pwd,
                                         strlen(pwd), seckey_struct->kdf_salt,
                                         le64_load(seckey_struct->kdf_opslimit_le),
                                         le64_load(seckey_struct->kdf_memlimit_le)) != 0) {
    fprintf(stderr, "Unable to complete key derivation - This probably means out of memory");
    return 0;
  }

  xor_buf((unsigned char *) (void *) &seckey_struct->keynum_sk, stream,
          sizeof seckey_struct->keynum_sk);
  sodium_free(stream);
  seckey_compute_chk(chk, seckey_struct);
  if (memcmp(chk, seckey_struct->keynum_sk.chk, crypto_generichash_BYTES) != 0) {
    fprintf(stderr, "Wrong password for that key");
    return 0;
  }
  sodium_memzero(chk, crypto_generichash_BYTES);
  return 1;
}

static void
encrypt_key(SeckeyStruct *const seckey_struct) {
  unsigned char *stream;
  unsigned long kdf_memlimit;
  unsigned long kdf_opslimit;

  stream = xsodium_malloc(sizeof seckey_struct->keynum_sk);
  randombytes_buf(seckey_struct->kdf_salt, sizeof seckey_struct->kdf_salt);
  kdf_opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE;
  kdf_memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE;

  while (crypto_pwhash_scryptsalsa208sha256(stream, sizeof seckey_struct->keynum_sk, PWD,
                                            strlen(PWD), seckey_struct->kdf_salt, kdf_opslimit,
                                            kdf_memlimit) != 0) {
    kdf_opslimit /= 2;
    kdf_memlimit /= 2;
    if (kdf_opslimit < crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN ||
        kdf_memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN) {
      exit_err("Unable to complete key derivation - More memory would be needed");
    }
  }

  if (kdf_memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE) {
    fprintf(stderr,
            "Warning: due to limited memory the KDF used less "
            "memory than the default\n");
  }
  le64_store(seckey_struct->kdf_opslimit_le, kdf_opslimit);
  le64_store(seckey_struct->kdf_memlimit_le, kdf_memlimit);
  seckey_compute_chk(seckey_struct->keynum_sk.chk, seckey_struct);
  xor_buf((unsigned char *) (void *) &seckey_struct->keynum_sk, stream,
          sizeof seckey_struct->keynum_sk);
  sodium_free(stream);
}

SeckeyStruct *
seckey_load(char *const pwd, char *const sk_comment_line, int* res) {
  char sk_comment_line_buf[COMMENTMAXBYTES];
  unsigned char chk[crypto_generichash_BYTES];
  SeckeyStruct *seckey_struct;
  FILE *fp;
  char *seckey_s;
  size_t seckey_s_size;
  size_t seckey_struct_len;

  if ((fp = fopen(PATH_SK, "r")) == NULL) {
    fprintf(stderr, "error: fopen: %s", PATH_SK);
  }
  if (fgets(sk_comment_line_buf, (int) sizeof sk_comment_line_buf, fp) == NULL) {
    fprintf(stderr, "Error while loading the secret key file");
    *res = 0;
    return NULL;
  }
  if (sk_comment_line != NULL) {
    memcpy(sk_comment_line, sk_comment_line_buf, sizeof sk_comment_line_buf);
  }
  sodium_memzero(sk_comment_line_buf, sizeof sk_comment_line_buf);
  seckey_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *seckey_struct) + 2U;
  seckey_s = xsodium_malloc(seckey_s_size);
  seckey_struct = xsodium_malloc(sizeof *seckey_struct);
  if (fgets(seckey_s, (int) seckey_s_size, fp) == NULL) {
    fprintf(stderr, "Error while loading the secret key file");
    *res = 0;
    return NULL;
  }
  trim(seckey_s);
  xfclose(fp);
  if (b64_to_bin((unsigned char *) (void *) seckey_struct, seckey_s, sizeof *seckey_struct,
                 strlen(seckey_s), &seckey_struct_len) == NULL ||
      seckey_struct_len != sizeof *seckey_struct) {
    fprintf(stderr, "base64 conversion failed - was an actual secret key given?");
    *res = 0;
    return NULL;
  }
  sodium_free(seckey_s);
  if (memcmp(seckey_struct->sig_alg, SIGALG, sizeof seckey_struct->sig_alg) != 0) {
    fprintf(stderr, "Unsupported signature algorithm");
    *res = 0;
    return NULL;
  }
  if (memcmp(seckey_struct->chk_alg, CHKALG, sizeof seckey_struct->chk_alg) != 0) {
    fprintf(stderr, "Unsupported checksum function");
    *res = 0;
    return NULL;
  }
  if (memcmp(seckey_struct->kdf_alg, KDFALG, sizeof seckey_struct->kdf_alg) == 0) {
    decrypt_key(pwd, seckey_struct, chk);
  } else if (memcmp(seckey_struct->kdf_alg, KDFNONE, sizeof seckey_struct->kdf_alg) != 0) {
    fprintf(stderr, "Unsupported key derivation function");
    *res = 0;
    return NULL;
  }

  *res = 1;
  return seckey_struct;
}

int
verify(const PubkeyStruct* pubkey_struct, const unsigned char* message_contents, const unsigned int message_size,
       const char* sig_contents) {
  char trusted_comment[TRUSTEDCOMMENTMAXBYTES];
  unsigned char global_sig[crypto_sign_BYTES];
  FILE *info_fp = stdout;
  unsigned char *sig_and_trusted_comment = NULL;
  SigStruct *sig_struct = NULL;
  unsigned char *message_hashed = NULL;
  size_t message_hashed_len = crypto_generichash_BYTES_MAX;
  size_t trusted_comment_len = 0;

  sig_struct = sig_load(sig_contents, global_sig, trusted_comment, sizeof trusted_comment);
  message_hashed = message_load_hashed(message_contents, message_size);

  if (memcmp(sig_struct->keynum, pubkey_struct->keynum_pk.keynum, sizeof sig_struct->keynum) != 0) {
    fprintf(stderr,
            "Signature key id is %016" PRIX64
            "\n"
            "but the key id in the public key is %016" PRIX64 "\n",
            le64_load(sig_struct->keynum),
            le64_load(pubkey_struct->keynum_pk.keynum));
    free(message_hashed);
    return 0;
  }

  if (crypto_sign_verify_detached(sig_struct->sig, message_hashed, message_hashed_len,
                                  pubkey_struct->keynum_pk.pk) != 0) {
    fprintf(stderr, "Signature verification failed\n");
    free(message_hashed);
    return 0;
  }
  free(message_hashed);

  trusted_comment_len = strlen(trusted_comment);
  sig_and_trusted_comment = xmalloc((sizeof sig_struct->sig) + trusted_comment_len);
  memcpy(sig_and_trusted_comment, sig_struct->sig, sizeof sig_struct->sig);
  memcpy(sig_and_trusted_comment + sizeof sig_struct->sig, trusted_comment, trusted_comment_len);
  if (crypto_sign_verify_detached(global_sig, sig_and_trusted_comment,
                                  (sizeof sig_struct->sig) + trusted_comment_len,
                                  pubkey_struct->keynum_pk.pk) != 0) {
    fprintf(stderr, "Comment signature verification failed\n");
    return 0;
  }

  free(sig_and_trusted_comment);
  free(sig_struct);
  return 1;
}

static char *
append_sig_suffix(const char *message_file) {
  char *sig_file;
  size_t message_file_len = strlen(message_file);

  sig_file = xmalloc(message_file_len + sizeof SIG_SUFFIX);
  memcpy(sig_file, message_file, message_file_len);
  memcpy(sig_file + message_file_len, SIG_SUFFIX, sizeof SIG_SUFFIX);

  return sig_file;
}

static char *
default_trusted_comment(const char *message_file, int hashed) {
  char *ret;
  time_t ts = time(NULL);
  const char *basename = file_basename(message_file);
  const char *hash_str = (hashed == 0) ? "" : "\thashed";

  // calculate required length (+1 for null terminator)
  int len = snprintf(NULL, 0, "timestamp:%lu\tfile:%s%s",
                     (unsigned long) ts, basename, hash_str) + 1;

  ret = malloc(len);
  if (!ret) {
    exit_err("malloc()");
  }

  // Fill the buffer
  if (snprintf(ret, len, "timestamp:%lu\tfile:%s%s",
               (unsigned long) ts, basename, hash_str) < 0) {
    free(ret);
    exit_err("snprintf()");
  }

  return ret;
}

int sign_memory(const PubkeyStruct *pubkey_struct,
                 const unsigned char *message_contents, size_t message_len,
                 const char *comment, const char *trusted_comment,
                 char **out_sig, size_t *out_sig_len,
                 int verification) {

  if (!comment || !trusted_comment) {
    fprintf(stderr, "minisign: error: comment and trusted comment are required\n");
    return 0;
  }

  // hash the input message
  unsigned char *hashed_message = message_load_hashed(message_contents, (unsigned int) message_len);
  if (!hashed_message) {
    fprintf(stderr, "minisign: error: unable to hash message\n");
    return 0;
  }

  // signature struct
  SigStruct sig_struct;
  memcpy(sig_struct.sig_alg, SIGALG_HASHED, sizeof sig_struct.sig_alg);
  memcpy(sig_struct.keynum, SECKEY->keynum_sk.keynum, sizeof sig_struct.keynum);

  // sign hashed message
  if (crypto_sign_detached(sig_struct.sig, NULL, hashed_message, crypto_generichash_BYTES_MAX,
                           SECKEY->keynum_sk.sk) != 0) {
    fprintf(stderr, "minisign: error: unable to sign message\n");
    free(hashed_message);
    return 0;
  }
  free(hashed_message);

  // global signature
  size_t trusted_comment_len = strlen(trusted_comment);
  unsigned char *sig_and_trusted_comment = xmalloc(sizeof sig_struct.sig + trusted_comment_len);
  if (!sig_and_trusted_comment) {
    fprintf(stderr, "minisign: error: memory allocation failed\n");
    return 0;
  }
  memcpy(sig_and_trusted_comment, sig_struct.sig, sizeof sig_struct.sig);
  memcpy(sig_and_trusted_comment + sizeof sig_struct.sig, trusted_comment, trusted_comment_len);

  unsigned char global_sig[crypto_sign_BYTES];
  if (crypto_sign_detached(global_sig, NULL, sig_and_trusted_comment,
                           sizeof sig_struct.sig + trusted_comment_len,
                           SECKEY->keynum_sk.sk) != 0) {
    fprintf(stderr, "minisign: error: unable to compute global signature\n");
    free(sig_and_trusted_comment);
    return 0;
  }

  /* optional verification */
  if (verification && pubkey_struct &&
      (memcmp(pubkey_struct->keynum_pk.keynum, SECKEY->keynum_sk.keynum, KEYNUMBYTES) != 0 ||
       crypto_sign_verify_detached(global_sig, sig_and_trusted_comment,
                                   sizeof sig_struct.sig + trusted_comment_len,
                                   pubkey_struct->keynum_pk.pk) != 0)) {
    fprintf(stderr, "minisign: error: verification would fail with the given public key\n");
    free(sig_and_trusted_comment);
    return 0;
  }

  free(sig_and_trusted_comment);

  // to memstream
  char *mem_buf = NULL;
  size_t mem_len = 0;
  FILE *fp = open_memstream(&mem_buf, &mem_len);
  if (!fp) {
    fprintf(stderr, "minisign: error: unable to open memory stream\n");
    return 0;
  }

  xfprintf(fp, "%s%s\n", COMMENT_PREFIX, comment);
  xfput_b64(fp, (unsigned char *) &sig_struct, sizeof sig_struct);
  xfprintf(fp, "%s%s\n", TRUSTED_COMMENT_PREFIX, trusted_comment);
  xfput_b64(fp, global_sig, sizeof global_sig);

  fflush(fp);
  fclose(fp);

  *out_sig = mem_buf;
  *out_sig_len = mem_len;

  return 1;
}

int sign_file(const PubkeyStruct *pubkey_struct, const char *path_message,
               const char *path_sig, const char *comment, const char *trusted_comment, int verification) {

  unsigned char global_sig[crypto_sign_BYTES];
  SigStruct sig_struct;
  FILE *fp;
  unsigned char *hashed_message;
  unsigned char *sig_and_trusted_comment;
  char *tmp_trusted_comment = NULL;
  size_t comment_len;
  size_t trusted_comment_len;
  size_t message_len;
  int hashed = 1;

  if (!comment || !trusted_comment) {
    fprintf(stderr, "minisign: error: comment and trusted comment are required\n");
    return 0;
  }

  hashed_message = message_load_hashed_file(&message_len, path_message);
  if (!hashed_message) {
    fprintf(stderr, "minisign: error: unable to load message file '%s'\n", path_message);
    free(tmp_trusted_comment);
    return 0;
  }

  memcpy(sig_struct.sig_alg, SIGALG_HASHED, sizeof sig_struct.sig_alg);
  memcpy(sig_struct.keynum, SECKEY->keynum_sk.keynum, sizeof sig_struct.keynum);

  if (crypto_sign_detached(sig_struct.sig, NULL, hashed_message, message_len, SECKEY->keynum_sk.sk) != 0) {
    fprintf(stderr, "minisign: error: unable to sign message\n");
    free(hashed_message);
    free(tmp_trusted_comment);
    return 0;
  }

  if ((fp = fopen(path_sig, "w")) == NULL) {
    fprintf(stderr, "minisign: error: unable to open signature file '%s'\n", path_sig);
    free(tmp_trusted_comment);
    return 0;
  }

  comment_len = strlen(comment);
  assert(strrchr(comment, '\r') == NULL && strrchr(comment, '\n') == NULL);
  assert(COMMENTMAXBYTES > sizeof COMMENT_PREFIX);
  if (comment_len >= COMMENTMAXBYTES - sizeof COMMENT_PREFIX) {
    fprintf(stderr,
            "minisign: warning: comment too long. This breaks compatibility with signify.\n");
  }

  xfprintf(fp, "%s%s\n", COMMENT_PREFIX, comment);
  xfput_b64(fp, (unsigned char *) (void *) &sig_struct, sizeof sig_struct);

  xfprintf(fp, "%s%s\n", TRUSTED_COMMENT_PREFIX, trusted_comment);
  trusted_comment_len = strlen(trusted_comment);
  assert(strrchr(trusted_comment, '\r') == NULL && strrchr(trusted_comment, '\n') == NULL);
  if (trusted_comment_len >= TRUSTEDCOMMENTMAXBYTES - sizeof TRUSTED_COMMENT_PREFIX) {
    fprintf(stderr, "minisign: error: trusted comment too long\n");
    fclose(fp);
    free(tmp_trusted_comment);
    return 0;
  }

  sig_and_trusted_comment = xmalloc((sizeof sig_struct.sig) + trusted_comment_len);
  if (!sig_and_trusted_comment) {
    fprintf(stderr, "minisign: error: memory allocation failed\n");
    fclose(fp);
    free(tmp_trusted_comment);
    return 0;
  }

  memcpy(sig_and_trusted_comment, sig_struct.sig, sizeof sig_struct.sig);
  memcpy(sig_and_trusted_comment + sizeof sig_struct.sig, trusted_comment, trusted_comment_len);

  if (crypto_sign_detached(global_sig, NULL, sig_and_trusted_comment,
                           (sizeof sig_struct.sig) + trusted_comment_len,
                           SECKEY->keynum_sk.sk) != 0) {
    fprintf(stderr, "minisign: error: unable to compute global signature\n");
    free(sig_and_trusted_comment);
    fclose(fp);
    free(tmp_trusted_comment);
    return 0;
  }

  if (verification && pubkey_struct != NULL &&
      (memcmp(pubkey_struct->keynum_pk.keynum, SECKEY->keynum_sk.keynum, KEYNUMBYTES) != 0 ||
       crypto_sign_verify_detached(global_sig, sig_and_trusted_comment,
                                   (sizeof sig_struct.sig) + trusted_comment_len,
                                   pubkey_struct->keynum_pk.pk) != 0)) {
    fprintf(stderr, "minisign: error: verification would fail with the given public key\n");
    free(sig_and_trusted_comment);
    fclose(fp);
    free(tmp_trusted_comment);
    return 0;
  }

  xfput_b64(fp, (unsigned char *) (void *) &global_sig, sizeof global_sig);
  xfclose(fp);

  free(hashed_message);
  free(sig_and_trusted_comment);
  free(tmp_trusted_comment);

  return 1;
}

static void
write_pk_file(const char *pk_file, const PubkeyStruct *pubkey_struct) {
  FILE *fp;

  if ((fp = fopen(pk_file, "w")) == NULL) {
    exit_err(pk_file);
  }
  xfprintf(fp, COMMENT_PREFIX "minisign public key %016" PRIX64 "\n",
           le64_load(pubkey_struct->keynum_pk.keynum));
  xfput_b64(fp, (const unsigned char *) (const void *) pubkey_struct, sizeof *pubkey_struct);
  xfclose(fp);
}

int generate_keys(const char *comment, int unencrypted_key) {
  SeckeyStruct *seckey_struct = xsodium_malloc(sizeof(SeckeyStruct));
  PubkeyStruct *pubkey_struct = xsodium_malloc(sizeof(PubkeyStruct));
  FILE *fp;

  memset(seckey_struct, 0, sizeof(SeckeyStruct));
  randombytes_buf(seckey_struct->keynum_sk.keynum, sizeof seckey_struct->keynum_sk.keynum);
  crypto_sign_keypair(pubkey_struct->keynum_pk.pk, seckey_struct->keynum_sk.sk);
  memcpy(seckey_struct->sig_alg, SIGALG, sizeof seckey_struct->sig_alg);
  memcpy(seckey_struct->kdf_alg, unencrypted_key ? KDFNONE : KDFALG,
         sizeof seckey_struct->kdf_alg);
  memcpy(seckey_struct->chk_alg, CHKALG, sizeof seckey_struct->chk_alg);
  memcpy(pubkey_struct->keynum_pk.keynum, seckey_struct->keynum_sk.keynum,
         sizeof pubkey_struct->keynum_pk.keynum);
  memcpy(pubkey_struct->sig_alg, SIGALG, sizeof pubkey_struct->sig_alg);
  if (unencrypted_key == 0) {
    encrypt_key(seckey_struct);
  }

  if ((fp = fopen_create_useronly(PATH_SK)) == NULL) {
    exit_err(PATH_SK);
  }
  xfprintf(fp, "%s%s\n", COMMENT_PREFIX, comment);
  xfput_b64(fp, (unsigned char *) (void *) seckey_struct, sizeof *seckey_struct);
  xfclose(fp);
  sodium_free(seckey_struct);

  write_pk_file(PATH_PK, pubkey_struct);
  return 1;
}

int set_config_directory(const char *config_dir) {
  if (!config_dir) {
    fprintf(stderr, "minisign [%s] error: config_dir is NULL\n", __func__);
    return 0;
  }

  // check if directory exists
  struct stat st;
  if (stat(config_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
    fprintf(stderr, "minisign [%s] error: directory '%s' does not exist\n", __func__, config_dir);
    return 0;
  }

  CONFIG_DIR = strdup(config_dir);
  if (!CONFIG_DIR) {
    fprintf(stderr, "minisign [%s] error: strdup failed for CONFIG_DIR\n", __func__);
    return 0;
  }

  // PATH_SK
  const size_t sk_len = strlen(CONFIG_DIR) + strlen("/minisign.key") + 1;
  PATH_SK = (char *) malloc(sk_len);
  if (!PATH_SK) {
    fprintf(stderr, "minisign [%s] error: malloc failed for SK_FILE\n", __func__);
    return 0;
  }
  snprintf(PATH_SK, sk_len, "%s/minisign.key", CONFIG_DIR);

  // PATH_PK
  const size_t pk_len = strlen(CONFIG_DIR) + strlen("/minisign.pub") + 1;
  PATH_PK = (char *) malloc(pk_len);
  if (!PATH_PK) {
    fprintf(stderr, "minisign [%s] error: malloc failed for PK_FILE\n", __func__);
    return 0;
  }
  snprintf(PATH_PK, pk_len, "%s/minisign.pub", CONFIG_DIR);

  return 1;
}
