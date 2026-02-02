# libminisign

`libminisign` is a C library of [Minisign](https://github.com/jedisct1/minisign) by Frank Denis. 

Minisign uses the Ed25519 public-key signature system with small, and fast signatures. 

Basically PGP, but easier to work with.

This project adds:

1. a way to *install* minisign so you can link against it
2. CMake and pkg-config (for e.g `find_package`)
3. in-memory signing, and verification so you never hit the disk
4. automatically set up pub/priv key to a specified directory

If you are looking for a Rust implementation, check out [jedisct1/rust-minisign](https://github.com/jedisct1/rust-minisign).

## API

The header is documented, see [minisign.h](include/minisign/minisign.h) for more info.

| Function | Description |
|----------|-------------|
| `minisign_init` | Initializes libsodium, sets up the keys directory, and loads or generates keys as needed, optionally using a password for the secret key. |
| `minisign_sign` | Signs a message buffer in memory and returns the signature, optionally embedding comments and verifying before returning. |
| `minisign_sign_file` | Signs a file and writes the signature to a separate file, optionally including comments and verifying the signature. |
| `minisign_verify` | Verifies an in-memory message buffer against a signature string using the provided public key. |
| `minisign_verify_file` | Verifies a file against a given signature file using the provided public key. |

## Example

```c
#include <minisign/minisign.h>

int main() {
    int res;
    const char* password = "some_password";

    // init
    res = minisign_init("/tmp/keys_directory/", password);
    if (res) printf("minisign init\n");
    else return 1;

    // print the paths
    printf("public key: %s\n", minisign_get_pk_path());
    printf("private key: %s\n", minisign_get_sk_path());

    // sign a string in-memory
    const unsigned char message[] = "some message to sign";
    const char *comment = "foo: some untrusted comment";
    const char *trusted_comment = "bar: some trusted comment";
    char *signature = NULL;
    size_t signature_len = 0;

    res = minisign_sign(message, sizeof(message) - 1, comment, trusted_comment, &signature, &signature_len, NULL);
    if (res) printf("message signed in memory\n");
    else return 1;

    // print signature
    printf("signature:\n%s\n", signature);

    // verify it
    res = minisign_verify(NULL, message, sizeof(message)-1, signature);
    if (res) printf("string verified\n");
    else return 1;

    free(signature);
    return 0;
}
```

## Limitations

The original MiniSign is a tool with very few features, hence 'mini', however 
this API limits the options even further. This library was made for my 
use-case ([kroketio/circus](https://github.com/kroketio/circus)):

- signing messages from disk, or in memory
- verifying messages on disk, or in memory
- only one private key active at any point in time

If you have other requirements, you might need to modify this 
library, or search for another implementation.

## Installation

```bash
sudo apt install -y cmake libsodium-dev

cmake -Bbuild .
make -Cbuild -j4
make -Cbuild install
```

#### Custom install prefix

pass `-DCMAKE_INSTALL_PREFIX=/tmp/xxx/` to CMake.

```text
-- Installing: /tmp/xxx/lib/libminisign.so
-- Installing: /tmp/xxx/include/minisign/minisign.h
-- Installing: /tmp/xxx/include/minisign/globals.h
-- Installing: /tmp/xxx/lib/cmake/minisign/minisignTargets.cmake
-- Installing: /tmp/xxx/lib/cmake/minisign/minisignTargets-debug.cmake
-- Installing: /tmp/xxx/lib/cmake/minisign/minisignConfig.cmake
-- Installing: /tmp/xxx/lib/cmake/minisign/minisignConfigVersion.cmake
-- Installing: /tmp/xxx/lib/pkgconfig/minisign.pc
```

### Consuming with CMake

```cmake
cmake_minimum_required(VERSION 3.30)
project(my_program)

find_package(minisign REQUIRED)

add_executable(my_program main.cpp)
target_link_libraries(my_program PUBLIC minisign::minisign)
```