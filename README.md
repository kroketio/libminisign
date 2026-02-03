# libminisign - Sign and Verify

Minisign uses the Ed25519 public-key signature system with small, and fast signatures.

This is the library version of [Minisign](https://github.com/jedisct1/minisign) by Frank Denis, as well 
as a CLI tool. It provides pkgconfig, and CMake config for consumption in other applications.

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

This library can be consumed by C and C++ programs. See [example.cpp](example.cpp).

## Installation

```bash
sudo apt install -y g++ cmake libsodium-dev

cmake -Bbuild .
make -Cbuild -j4

# system-wide installation
sudo make -Cbuild install
```

#### Custom install prefix

pass `-DCMAKE_INSTALL_PREFIX=/tmp/test/` to CMake.

```text
-- Installing: /tmp/test/lib/libminisign.so
-- Installing: /tmp/test/include/minisign/minisign.h
-- Installing: /tmp/test/include/minisign/globals.h
-- Installing: /tmp/test/lib/cmake/minisign/minisignTargets.cmake
-- Installing: /tmp/test/lib/cmake/minisign/minisignTargets-debug.cmake
-- Installing: /tmp/test/lib/cmake/minisign/minisignConfig.cmake
-- Installing: /tmp/test/lib/cmake/minisign/minisignConfigVersion.cmake
-- Installing: /tmp/test/lib/pkgconfig/minisign.pc
```

### Consuming with CMake

```cmake
cmake_minimum_required(VERSION 3.30)
project(my_program)

find_package(minisign REQUIRED)

add_executable(my_program main.cpp)
target_link_libraries(my_program PUBLIC minisign::minisign)
```

## Other implementations

- [jedisct1/rust-minisign](https://github.com/jedisct1/rust-minisign).