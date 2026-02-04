#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <libgen.h>

#include "minisign/minisign.h"
#include "config-minisign.h"

static void print_help(const char *prog) {
  const char *name = basename((char *) prog);
  printf("Usage:\n");
  printf("  %s [key] <file>\n\n", name);
  printf("Examples (all achieve the same):\n");
  printf("  %s /path/to/some_key.pub /path/to/file.sig\n", name);
  printf("  %s /path/to/some_key /path/to/file\n", name);
  printf("  %s some_key /path/to/file\n", name);
  printf("  %s /path/to/file\n\n", name);
  printf("Options:\n");
  printf("  -h, --help     Show this help message and exit\n");
  printf("  -v, --version  Show version information and exit\n");
}

static int ends_with(const char *s, const char *sfx) {
  const size_t sl = strlen(s);
  const size_t xl = strlen(sfx);

  if (sl < xl)
    return 0;

  return memcmp(s + sl - xl, sfx, xl) == 0;
}

static int safe_copy(char *dst, size_t n, const char *src) {
  const size_t l = strlen(src);

  if (l >= n)
    return 0;

  memcpy(dst, src, l + 1);
  return 1;
}

static int safe_join(char *dst, size_t n, const char *a, const char *b) {
  const size_t al = strlen(a);
  const size_t bl = strlen(b);

  if (al + bl >= n)
    return 0;

  memmove(dst, a, al);
  memmove(dst + al, b, bl);
  dst[al + bl] = 0;
  return 1;
}

static int normalize_dir(char *key_dir) {
  const size_t l = strlen(key_dir);
  if (l == 0)
    return 0;
  if (key_dir[l - 1] != '/') {
    if (l + 1 >= PATH_MAX)
      return 0;
    key_dir[l] = '/';
    key_dir[l + 1] = 0;
  }
  return 1;
}

static int reject_traversal(const char *p) {
  if (strstr(p, "/../") || strstr(p, "../") == p || strstr(p, "/..") == p + strlen(p) - 3)
    return 0;
  return 1;
}

int main(const int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
      printf("%s\n", MINISIGN_VERSION);
      return 0;
    }
    if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      print_help(argv[0]);
      return 0;
    }
  }

  const char *home = getenv("HOME");
  if (!home)
    home = ".";

  const char *input_key = 0;
  const char *input_file = 0;

  if (argc == 2)
    input_file = argv[1];
  else if (argc == 3) {
    input_key = argv[1];
    input_file = argv[2];
  } else if (argc > 3) {
    minisign_err("too many arguments");
    return 1;
  }

  char key_dir[PATH_MAX] = {0};
  char key_name[PATH_MAX] = {0};
  char pub_path[PATH_MAX] = {0};
  char file_path[PATH_MAX] = {0};
  char sig_path[PATH_MAX] = {0};

  if (input_file) {
    if (!safe_copy(file_path, sizeof(file_path), input_file)) {
      minisign_err("file path too long");
      return 1;
    }
  }

  if (input_key) {
    if (strchr(input_key, '/')) {
      if (!ends_with(input_key, ".pub")) {
        if (!safe_join(pub_path, sizeof(pub_path), input_key, ".pub")) {
          minisign_err("key path too long");
          return 1;
        }
      } else {
        if (!safe_copy(pub_path, sizeof(pub_path), input_key)) {
          minisign_err("key path too long");
          return 1;
        }
      }

      char tmp[PATH_MAX];
      if (!safe_copy(tmp, sizeof(tmp), pub_path)) {
        minisign_err("pubkey path too long");
        return 1;
      }

      char *b = basename(tmp);
      if (!ends_with(b, ".pub")) {
        minisign_err("invalid public key filename");
        return 1;
      }

      b[strlen(b) - 4] = 0;
      if (!safe_copy(key_name, sizeof(key_name), b)) {
        minisign_err("key name too long");
        return 1;
      }

      if (!safe_copy(tmp, sizeof(tmp), pub_path)) {
        minisign_err("pubkey path too long");
        return 1;
      }

      const char *d = dirname(tmp);
      if (!reject_traversal(d)) {
        minisign_err("directory traversal in key path");
        return 1;
      }

      if (!safe_copy(key_dir, sizeof(key_dir), d)) {
        minisign_err("key directory too long");
        return 1;
      }
    } else {
      if (!safe_join(key_dir, sizeof(key_dir), home, "/.minisign")) {
        minisign_err("home path too long");
        return 1;
      }

      if (!normalize_dir(key_dir)) {
        minisign_err("key directory too long");
        return 1;
      }

      if (!safe_copy(key_name, sizeof(key_name), input_key)) {
        minisign_err("key name too long");
        return 1;
      }

      if (!safe_join(pub_path, sizeof(pub_path), key_dir, key_name)) {
        minisign_err("pubkey path too long");
        return 1;
      }

      if (!safe_join(pub_path, sizeof(pub_path), pub_path, ".pub")) {
        minisign_err("pubkey path too long");
        return 1;
      }
    }
  } else {
    if (!safe_join(key_dir, sizeof(key_dir), home, "/.minisign")) {
      minisign_err("home path too long");
      return 1;
    }

    if (!normalize_dir(key_dir)) {
      minisign_err("key directory too long");
      return 1;
    }

    if (!safe_copy(key_name, sizeof(key_name), "id_ed25519")) {
      minisign_err("default key name too long");
      return 1;
    }

    if (!safe_join(pub_path, sizeof(pub_path), key_dir, key_name)) {
      minisign_err("pubkey path too long");
      return 1;
    }

    if (!safe_join(pub_path, sizeof(pub_path), pub_path, ".pub")) {
      minisign_err("pubkey path too long");
      return 1;
    }
  }

  if (access(pub_path, R_OK) != 0) {
    minisign_err("public key not accessible: %s", pub_path);
    return 1;
  }

  if (ends_with(file_path, ".sig")) {
    if (!safe_copy(sig_path, sizeof(sig_path), file_path)) {
      minisign_err("signature path too long");
      return 1;
    }

    file_path[strlen(file_path) - 4] = 0;
  } else {
    if (!safe_join(sig_path, sizeof(sig_path), file_path, ".sig")) {
      minisign_err("signature path too long");
      return 1;
    }
  }

  if (access(file_path, R_OK) != 0) {
    minisign_err("the input file to verify does not exist: %s", file_path);
    return 1;
  }

  if (access(sig_path, R_OK) != 0) {
    minisign_err("signature file does not exist: %s", sig_path);
    return 1;
  }

  if (sodium_init() != 0) {
    minisign_err("sodium init failed");
    return 1;
  }

  if (!normalize_dir(key_dir)) {
    minisign_err("invalid key_dir");
    return 1;
  }

  MINISIGN_INIT = 1;
  if (minisign_verify_file(key_name, key_dir, file_path, sig_path)) {
    printf("signature valid\n");
    return 0;
  }

  minisign_err("signature invalid");
  return 1;
}
