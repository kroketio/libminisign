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
  printf("  %s <file> [-p <password>] [-c 'trusted comment']\n", name);
  printf("  %s -i <key> <file> [-p <password>]\n\n", name);
  printf("Examples:\n");
  printf("  %s /path/to/file\n", name);
  printf("  %s /path/to/file -p secret\n", name);
  printf("  %s /path/to/file -p secret -c 'release build'\n", name);
  printf("  %s -i id_ed25519 /path/to/file -p secret\n", name);
  printf("  %s -i /path/to/key /path/to/file\n\n", name);
  printf("Options:\n");
  printf("  -i <key>      Secret key path or name (default: ~/.minisign/id_ed25519)\n");
  printf("  -p <pass>     Password for secret key (optional)\n");
  printf("  -c <comment>  Trusted comment (optional)\n");
  printf("  -h, --help    Show this help message and exit\n");
  printf("  -v, --version Show version information and exit\n");
}

static int normalize_dir(char *p) {
  const size_t l = strlen(p);
  if (l == 0)
    return 0;
  
  if (p[l - 1] != '/') {
    if (l + 1 >= PATH_MAX)
      return 0;
    
    p[l] = '/';
    p[l + 1] = 0;
  }
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

  const char *input_file = NULL;
  const char *input_key = NULL;
  const char *password = "";
  const char *trusted_comment = "";

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-i") && i + 1 < argc) {
      input_key = argv[++i];
    } else if (!strcmp(argv[i], "-p") && i + 1 < argc) {
      password = argv[++i];
    } else if (!strcmp(argv[i], "-c") && i + 1 < argc) {
      trusted_comment = argv[++i];
    } else if (!input_file) {
      input_file = argv[i];
    } else {
      minisign_err("invalid arguments");
      print_help(argv[0]);
      return 1;
    }
  }

  if (!input_file) {
    minisign_err("no input file");
    print_help(argv[0]);
    return 1;
  }

  char key_dir[PATH_MAX] = {0};
  char key_name[PATH_MAX] = {0};
  char file_path[PATH_MAX] = {0};
  char sig_path[PATH_MAX] = {0};
  char passbuf[1024] = {0};

  // copy input file path
  if (!safe_copy(file_path, sizeof(file_path), input_file)) {
    minisign_err("file path too long");
    return 1;
  }

  // handle key
  if (input_key) {
    if (strchr(input_key, '/')) {
      // full path
      char tmp[PATH_MAX];
      if (!safe_copy(tmp, sizeof(tmp), input_key)) {
        minisign_err("key path too long");
        return 1;
      }
      
      const char *b = basename(tmp);
      if (!safe_copy(key_name, sizeof(key_name), b)) {
        minisign_err("key name too long");
        return 1;
      }
      
      if (!safe_copy(tmp, sizeof(tmp), input_key)) {
        minisign_err("key path too long");
        return 1;
      }
      
      const char *d = dirname(tmp);
      if (!safe_copy(key_dir, sizeof(key_dir), d)) {
        minisign_err("key dir too long");
        return 1;
      }
    } else {
      // just key name, default dir
      if (!safe_copy(key_name, sizeof(key_name), input_key)) {
        minisign_err("key name too long");
        return 1;
      }
      
      if (!safe_join(key_dir, sizeof(key_dir), home, "/.minisign")) {
        minisign_err("key dir too long");
        return 1;
      }
    }
  } else {
    // default key
    if (!safe_copy(key_name, sizeof(key_name), "id_ed25519")) {
      minisign_err("key name too long");
      return 1;
    }
    
    if (!safe_join(key_dir, sizeof(key_dir), home, "/.minisign")) {
      minisign_err("key dir too long");
      return 1;
    }
  }

  if (!normalize_dir(key_dir)) {
    minisign_err("invalid key_dir");
    return 1;
  }

  if (!safe_join(sig_path, sizeof(sig_path), file_path, ".sig")) {
    minisign_err("signature path too long");
    return 1;
  }
  
  if (access(file_path, R_OK) != 0) {
    minisign_err("input file not accessible: %s", file_path);
    return 1;
  }
  
  if (!safe_copy(passbuf, sizeof(passbuf), password)) {
    minisign_err("password too long");
    return 1;
  }

  // expand ~/ in key_dir
  if (key_dir[0] == '~' && key_dir[1] == '/') {
    char tmp[PATH_MAX];
    if (!safe_join(tmp, sizeof(tmp), home, key_dir + 1)) {
      minisign_err("key dir too long");
      return 1;
    }
    if (!safe_copy(key_dir, sizeof(key_dir), tmp)) {
      minisign_err("key dir too long");
      return 1;
    }
  }

  if (sodium_init() != 0) {
    minisign_err("sodium init failed");
    return 1;
  }

  MINISIGN_INIT = 1;
  if (!minisign_sign_file(
      key_name,
      key_dir,
      passbuf,
      file_path,
      sig_path,
      "",
      trusted_comment,
      0)) {
    minisign_err("signing file failed");
    return 1;
  }

  printf("signature written to %s\n", sig_path);
  return 0;
}
