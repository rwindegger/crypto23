# crypto23
[![codecov](https://codecov.io/gh/rwindegger/crypto23/graph/badge.svg?token=qzdShQ58dx)](https://codecov.io/gh/rwindegger/crypto23)
[![covdbg](https://covdbg.com/badge.svg/)](https://covdbg.com/)

`crypto23` is a modern C++23, header-only implementation of Rijndael (including AES variants).

## What this library does

- Provides a templated `crypto23::rijndael<BlockMode, KeyMode>` implementation.
- Includes convenient aliases for AES block mode:
	- `crypto23::aes_128`
	- `crypto23::aes_192`
	- `crypto23::aes_256`
- Supports compile-time and runtime encryption/decryption APIs.
- Works on contiguous byte-like buffers (`std::array`, `std::vector`, `std::string`, `std::span`, etc.).

## Requirements

- C++23 compiler
- CMake 3.31+

## Add to your project

### Option 1: `add_subdirectory`

```cmake
add_subdirectory(path/to/crypto23)
target_link_libraries(your_target PRIVATE crypto23::crypto23)
```

### Option 2: install + `find_package`

After installing `crypto23`, use:

```cmake
find_package(crypto23 CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE crypto23::crypto23)
```

## Usage

```cpp
#include <array>
#include <cstddef>
#include <crypto23/rijndael.h>
#include <string>

int main() {
	constexpr auto key = std::array{
		std::byte{0x2b}, std::byte{0x7e}, std::byte{0x15}, std::byte{0x16},
		std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
		std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88},
		std::byte{0x09}, std::byte{0xcf}, std::byte{0x4f}, std::byte{0x3c}
	};

	// Runtime API
	std::string message = "Hello, World!";
	auto encrypted = crypto23::aes_128::encrypt(message, key);
	auto decrypted = crypto23::aes_128::decrypt(encrypted, key);

	// Compile-time friendly API for string literals
	constexpr auto encrypted_literal = crypto23::aes_128::encrypt_string("Hello, World!", key);
	auto decrypted_literal = crypto23::aes_128::decrypt_string(encrypted_literal, key);

	return (decrypted_literal == "Hello, World!" && decrypted.size() == message.size()) ? 0 : 1;
}
```

## API at a glance

- `encrypt_string` / `decrypt_string`: string-literal focused helpers.
- `encrypt_buffer` / `decrypt_buffer`: fixed-size buffer helpers.
- `encrypt` / `decrypt`: generic contiguous range helpers.

All helpers apply padding so plaintext size does not need to be block-aligned.

## Security notes

- The current API encrypts blocks independently (ECB-style behavior).
- For production-sensitive data, prefer a mode with IV/nonce and authentication (for example, GCM or CTR + MAC) at a higher layer.
- Always use unpredictable keys and keep them out of source control.

## Running tests

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Contributing

Contributions, bug reports, and feature requests are welcome. Open an [issue](https://github.com/rwindegger/crypto23/issues) or submit a pull request.

1. Fork it
2. Create your feature branch: `git checkout -b feature/my-new-feature`
3. Commit your changes: `git commit -am "Add some feature"`
4. Push to the branch: `git push origin feature/my-new-feature`
5. Submit a pull request

## License

This project is licensed under the [MIT License](LICENSE).