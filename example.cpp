#include <iostream>
#include <fstream>

extern "C" {
  #include "minisign/minisign.h"
}

int main() {
  int res = 0;
  char key_name[] = "test";
  char key_dir[] = "/tmp/minisign_test/";
  char test_file[] = "/tmp/minisign_test/test_file.txt";
  char test_file_sig[] = "/tmp/minisign_test/test_file.txt.sig";
  char password[] = "test";

  printf("=== init sodium, and keys directory %s\n", key_dir);
  res = minisign_init(key_dir);
  if (!res) exit(1);

  printf("=== generating /tmp/test.pub and /tmp/test\n");
  res = minisign_generate(key_name, key_dir, password);
  if (!res) exit(1);

  printf("=== creating test file: %s\n", test_file);
  std::ofstream ofs(test_file);
  ofs << "AAAA";
  ofs.close();

  printf("=== signing test file: %s\n", test_file_sig);
  res = minisign_sign_file(key_name, key_dir, password, test_file, test_file_sig, "foo: some untrusted comment", "bar: some trusted comment", 1);
  if (!res) exit(1);

  printf("=== verifying test file: %s with %s\n", test_file, test_file_sig);
  res = minisign_verify_file(key_name, key_dir, test_file, test_file_sig);
  if (!res) exit(1);

  printf("=== signing: in-memory buffer\n");
  const unsigned char message[] = "some message to sign";
  const char *comment = "foo: some untrusted comment";
  const char *trusted_comment = "bar: some trusted comment";
  char *signature = NULL;
  size_t signature_len = 0;
  res = minisign_sign(key_name, key_dir, password, message, sizeof(message) - 1, comment, trusted_comment, &signature, &signature_len, 1);
  if (!res) exit(1);
  // printf("======== SIGNATURE\n%s========\n", signature);

  printf("=== verify: in-memory buffer\n");
  const auto pubkey = minisign_read_pubkey(key_name, key_dir);  // read pubkey from disk
  if (!pubkey) exit(1);
  res = minisign_verify(pubkey, message, sizeof(message)-1, signature);
  if (!res) exit(1);

  printf("all examples passed");
  return 0;
}
