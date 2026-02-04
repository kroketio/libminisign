# minisign-tools - Sign and Verify

minisign-tools is both a library, and a collection of CLI tools for signing files and verify 
signatures. It provides pkgconfig, and CMake config for integration into your application.

It is similar to [signify](https://github.com/aperezdc/signify) from OpenBSD, but based 
on [minisign](https://github.com/jedisct1/minisign).

**warning:** this project is still in beta.

## License

Minisign is distributed under the terms of the [ISC license](https://opensource.org/licenses/isc-license.txt).

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

## Tools

#### sign-keygen

Similar to `ssh-keygen`.

```text
$ sign-keygen 
Generating public/private key pair.
Enter file in which to save the key (/home/user/.minisign/id_ed25519): 
Enter passphrase for "/home/user/.minisign/id_ed25519" (empty for no passphrase): 
Enter same passphrase again: 
success
seckey: /home/user/.minisign/id_ed25519
pubkey: /home/user/.minisign/id_ed25519.pub [RWR8WcW+J8S9CiTxbDlSlSjmwgXRpXmbCkhLK6nCdg/YU9dorVZUbo9a]
```

A non-interactive mode is also available, see `--help`.

#### sign

Sign a file using a private key.

```text
$ sign
Usage:
  sign <file> [-p <password>] [-c 'trusted comment']
  sign -i <key> <file> [-p <password>]

Examples:
  sign /path/to/file
  sign /path/to/file -p secret
  sign /path/to/file -p secret -c 'release build'
  sign -i id_ed25519 /path/to/file -p secret
  sign -i /path/to/key /path/to/file

Options:
  -i <key>      Secret key path or name (default: ~/.minisign/id_ed25519)
  -p <pass>     Password for secret key (optional)
  -c <comment>  Trusted comment (optional)
  -h, --help    Show this help message and exit
  -v, --version Show version information and exit
```

#### sign-verify

Verify a signed file against a public key.

```text
$ sign-verify
Usage:
  sign-verify [key] <file>

Examples (all achieve the same):
  sign-verify /path/to/some_key.pub /path/to/file.sig
  sign-verify /path/to/some_key /path/to/file
  sign-verify some_key /path/to/file
  sign-verify /path/to/file

Options:
  -h, --help     Show this help message and exit
  -v, --version  Show version information and exit
```

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

-- Installing: /tmp/test/lib/libminisign.so.1.3
-- Installing: /tmp/test/lib/libminisign.so.1
-- Up-to-date: /tmp/test/lib/libminisign.so
-- Installing: /tmp/test/include/minisign/minisign.h
-- Installing: /tmp/test/include/minisign/globals.h
-- Installing: /tmp/test/lib/cmake/minisign/minisignTargets.cmake
-- Installing: /tmp/test/lib/cmake/minisign/minisignTargets-noconfig.cmake
-- Installing: /tmp/test/lib/cmake/minisign/minisignConfig.cmake
-- Installing: /tmp/test/lib/cmake/minisign/minisignConfigVersion.cmake
-- Installing: /tmp/test/lib/pkgconfig/minisign.pc
-- Installing: /tmp/test/bin/sign-keygen
-- Installing: /tmp/test/bin/sign-verify
-- Installing: /tmp/test/bin/sign
```

## C++ library usage

See [example.cpp](example.cpp).

#### CMake

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