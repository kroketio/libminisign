#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <termios.h>

#include "minisign/minisign.h"
#include "config-minisign.h"

static int
read_pass(char *buf, size_t n) {
  struct termios oldt, newt;
  if (tcgetattr(STDIN_FILENO, &oldt) != 0)
    return 0;
  newt = oldt;
  newt.c_lflag &= ~ECHO;
  if (tcsetattr(STDIN_FILENO,TCSANOW, &newt) != 0)
    return 0;
  if (!fgets(buf, n,stdin)) {
    tcsetattr(STDIN_FILENO,TCSANOW, &oldt);
    return 0;
  }
  tcsetattr(STDIN_FILENO,TCSANOW, &oldt);
  return 1;
}

static void
trim(char *s) {
  const size_t n = strlen(s);
  if (n && s[n - 1] == '\n')
    s[n - 1] = 0;
}

static int
read_file(const char *path, char **out) {
  FILE *f = fopen(path, "rb");
  long n;

  if (!f)
    return 0;

  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);

  *out = malloc(n + 1);
  if (!*out) {
    fclose(f);
    return 0;
  }

  if (fread(*out, 1, n, f) != (size_t) n) {
    fclose(f);
    free(*out);
    return 0;
  }

  fclose(f);
  (*out)[n] = 0;
  return 1;
}

int
main(const int argc, char **argv) {
  const char *out_path = 0;
  const char *pass_arg = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
      printf("sign-keygen %s\n", MINISIGN_VERSION);
      return 0;
    }
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      printf("sign-keygen %s\n", MINISIGN_VERSION);
      printf("  %s\n", "-o keyfile output path");
      printf("  %s\n", "-p password (optional)");
      return 0;
    }
    if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
      out_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      pass_arg = argv[++i];
      continue;
    }
  }

  char path[PATH_MAX];
  char priv_path[PATH_MAX];
  char key_dir[PATH_MAX];
  char key_name[PATH_MAX];
  char pub_path[PATH_MAX];
  char *slash;
  char *pub = 0;

  const char *home = getenv("HOME");
  if (!home)
    home = ".";

  if (out_path) {
    strncpy(path, out_path, sizeof(path) - 1);
    path[sizeof(path) - 1] = 0;
  } else {
    snprintf(path, sizeof(path), "%s/.minisign/id_ed25519", home);
    printf("Generating public/private key pair.\n");
    printf("Enter file in which to save the key (%s): ", path);
    if (fgets(path, sizeof(path),stdin))
      trim(path);
    if (!path[0])
      snprintf(path, sizeof(path), "%s/.minisign/id_ed25519", home);
  }

  strncpy(priv_path, path, sizeof(priv_path) - 1);
  priv_path[sizeof(priv_path) - 1] = 0;

  slash = strrchr(path, '/');
  if (slash) {
    *slash = 0;
    strncpy(key_dir, path, sizeof(key_dir) - 1);
    key_dir[sizeof(key_dir) - 1] = 0;
    strncpy(key_name, slash + 1, sizeof(key_name) - 1);
    key_name[sizeof(key_name) - 1] = 0;
    strcat(key_dir, "/");
  } else {
    strcpy(key_dir, "./");
    strncpy(key_name, path, sizeof(key_name) - 1);
    key_name[sizeof(key_name) - 1] = 0;
  }

  if (!minisign_init(key_dir)) {
    minisign_err("minisign_init failed");
    return 1;
  }

  const size_t len_dir = strlen(key_dir);
  const size_t len_name = strlen(key_name);
  if (len_dir + len_name + 4 >= sizeof(pub_path)) {
    minisign_err("public key path too long");
    return 1;
  }

  memcpy(pub_path, key_dir, len_dir);
  memcpy(pub_path + len_dir, key_name, len_name);
  memcpy(pub_path + len_dir + len_name, ".pub", 4);
  pub_path[len_dir + len_name + 4] = 0;

  if (access(priv_path,F_OK) == 0 || access(pub_path,F_OK) == 0) {
    minisign_err("key already exists! :^)");
    return 1;
  }

  char *pass1 = sodium_malloc(256);
  char *pass2 = sodium_malloc(256);
  if (!pass1 || !pass2) {
    minisign_err("failed to allocate secure memory");
    return 1;
  }

  if (out_path && !pass_arg) {
    printf("warning: -o used without -p, passphrase will be empty\n");
    pass1[0] = 0;
  } else if (pass_arg) {
    strncpy(pass1, pass_arg, 255);
    pass1[255] = 0;
  } else {
    if (strcmp(key_dir, "./") == 0)
      printf("Enter passphrase for \"%s\" (empty for no passphrase): ", key_name);
    else
      printf("Enter passphrase for \"%s%s\" (empty for no passphrase): ", key_dir, key_name);
    if (!read_pass(pass1, 256))
      return 1;
    printf("\nEnter same passphrase again: ");
    if (!read_pass(pass2, 256))
      return 1;
    printf("\n");
    trim(pass1);
    trim(pass2);
    if (strcmp(pass1, pass2) != 0) {
      minisign_err("passphrases do not match");
      return 1;
    }
  }

  if (!minisign_generate(key_name, key_dir, pass1[0] ? pass1 : 0)) {
    minisign_err("minisign_generate failed");
    return 1;
  }

  printf("success\n");
  printf("seckey: %s%s\n", key_dir, key_name);
  printf("pubkey: %s%s.pub", key_dir, key_name);

  if (!read_file(pub_path, &pub)) {
    minisign_err("failed to read generated public key");
    return 1;
  }

  char *second_line = strchr(pub, '\n');
  if (second_line) {
    second_line++;
    char *e = strchr(second_line, '\n');
    if (e)
      *e = 0;
    printf(" [%s]\n", second_line);
  } else {
    printf("\nPublic key: %s", pub);
  }
  free(pub);

  sodium_free(pass1);
  sodium_free(pass2);

  return 0;
}
