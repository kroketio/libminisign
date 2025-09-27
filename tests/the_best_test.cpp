#include <iostream>
#include <fstream>

extern "C" {
  #include "minisign/minisign.h"
}

int main() {
  bool res = false;
  constexpr char password[] = "test";

  printf("=== init\n");
  res = minisign_init("/tmp/", password);
  if (res) printf("minisign init\n");
  else return 1;

  printf("your keys: \n");
  const char* path_pk = minisign_get_pk_path();
  const char* path_sk = minisign_get_sk_path();
  printf("public key: %s\n", path_pk);
  printf("private key: %s\n", path_sk);
  puts("");

  // printf("=== signing: in-memory\n");
  const unsigned char message[] = "some message to sign";
  const char *comment = "foo: some untrusted comment";
  const char *trusted_comment = "bar: some trusted comment";
  char *signature = NULL;
  size_t signature_len = 0;
  res = minisign_sign(message, sizeof(message) - 1, comment, trusted_comment, &signature, &signature_len, NULL);
  if (res) printf("message signed in memory\n");
  else return 1;
  // note: do not forget `free(signature);`
  printf("%s\n", signature);

  // printf("=== signing: file\n");
  printf("writing test file: %s\n", "/tmp/minisign_test");
  std::ofstream ofs("/tmp/minisign_test");
  ofs << "AAAA";
  ofs.close();
  const char path_message[] = "/tmp/minisign_test";
  const char path_message_sig_output[] = "/tmp/minisign_test.minisig";
  res = minisign_sign_file(path_message, path_message_sig_output, "foo: some untrusted comment", "bar: some trusted comment", true);
  if (res) printf("file signed\n");
  else return 1;

  printf("=== verify: file\n");
  // optional: replace first arg NULL to provide a pubkey, e.g: 'RWTUq+ehU6RQJ23ML+CmKfrCb68Js0sSEOZtpO0soCkhC5AkGIV0x9HV'
  // when it is NULL, it will use the currently loaded pubkey
  res = minisign_verify_file(NULL, path_message, path_message_sig_output);
  if (res) printf("file verified\n");
  else return 1;

  // printf("=== verify: in-memory\n");
  res = minisign_verify(NULL, message, sizeof(message)-1, signature);
  if (res) printf("in-memory verified\n");
  else return 1;

  return 0;
}