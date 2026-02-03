# libminisign - Sign and Verify

libminisign is a dead simple library to sign files and verify signatures.

```c
char key_name[] = "test";
char key_dir[] = "/home/user/.minisign/";
char password[] = "test";
char test_file[] = "/tmp/test_file.txt";
char test_file_sig[] = "/tmp/test_file.txt.sig";
  
minisign_init(key_dir);
minisign_generate(key_name, key_dir, password);

minisign_sign_file(key_name, key_dir, password, test_file, test_file_sig, "foo", "bar", 1);

char* pubkey = minisign_read_pubkey(key_name, key_dir);
minisign_verify(pubkey, message, sizeof(message)-1, signature);
```

This is a library implementation of [Minisign](https://github.com/jedisct1/minisign). It provides a pkgconfig, and 
CMake config for consumption in other applications.

## License

Signify is distributed under the terms of the [ISC license](https://opensource.org/licenses/isc-license.txt).

## API

The header is documented, see [minisign.h](include/minisign/minisign.h) for more info.

| Function | Description |
|----------|-------------|
| `minisign_init` | Initializes libsodium and sets the key directory. Returns 1 on success, 0 on failure. |
| `minisign_generate` | Generates a new key pair in the specified directory, optionally using a password for the secret key. Returns 1 on success, 0 on failure. |
| `minisign_sign` | Signs an in-memory message buffer and returns the generated signature. Optional comments and trusted comments can be included, and the signature can be verified before returning. |
| `minisign_sign_file` | Signs a file and writes the signature to a separate file. Optional comments and trusted comments can be included, and verification can be performed before writing. |
| `minisign_verify` | Verifies an in-memory message buffer against a signature string using the provided public key. Returns 1 if valid, 0 otherwise. |
| `minisign_verify_file` | Verifies a file against a given signature file using the provided public key. Returns 1 if valid, 0 otherwise. |


## Example

See [example.cpp](example.cpp).

## Installation

```bash
sudo apt install -y g++ cmake libsodium-dev

cmake -Bbuild .
make -Cbuild -j6

# system-wide installation
sudo make -Cbuild install
```

#### Custom install prefix

pass `-DCMAKE_INSTALL_PREFIX=/tmp/test/` to CMake.

```text
cmake -Bbuild -DCMAKE_INSTALL_PREFIX=/tmp/test/ .
make -Cbuild -j6 install

-- Installing: /tmp/test/lib/libminisign.so
-- Installing: /tmp/test/include/minisign/minisign.h
-- Installing: /tmp/test/include/minisign/globals.h
-- Installing: /tmp/test/lib/cmake/minisign/minisignTargets.cmake
-- Installing: /tmp/test/lib/cmake/minisign/minisignTargets-debug.cmake
-- Installing: /tmp/test/lib/cmake/minisign/minisignConfig.cmake
-- Installing: /tmp/test/lib/cmake/minisign/minisignConfigVersion.cmake
-- Installing: /tmp/test/lib/pkgconfig/minisign.pc
```

## CMake

```cmake
cmake_minimum_required(VERSION 3.30)
project(my_program)

find_package(minisign REQUIRED)

add_executable(my_program main.cpp)
target_link_libraries(my_program PUBLIC minisign::minisign)
```

## Other implementations

- [jedisct1/rust-minisign](https://github.com/jedisct1/rust-minisign).

## Thanks

Frank Denis, the author of minisign.