//
// Created by Rene Windegger on 27/05/2026.
//

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <crypto23/rijndael.h>
#include <gtest/gtest.h>

namespace {
    TEST(aes_256, single_block_string_test) {
        std::string const input = "Hello, World!";
        static constexpr auto key = std::array{
            std::byte{0x2b}, std::byte{0x7e}, std::byte{0x15}, std::byte{0x16},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88},
            std::byte{0x09}, std::byte{0xcf}, std::byte{0x4f}, std::byte{0x3c},
            std::byte{0x18}, std::byte{0x9f}, std::byte{0xb6}, std::byte{0x41},
            std::byte{0x1c}, std::byte{0x3f}, std::byte{0x9d}, std::byte{0xf8},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88}
        };

        constexpr auto encrypted = crypto23::aes_256::encrypt_string("Hello, World!", key);

        constexpr auto empty = std::array{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
        };

        constexpr auto unencrypted = std::array{
            std::byte{'H'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'},
            std::byte{'o'}, std::byte{','}, std::byte{' '}, std::byte{'W'},
            std::byte{'o'}, std::byte{'r'}, std::byte{'l'}, std::byte{'d'},
            std::byte{'!'}, std::byte{0x03}, std::byte{0x03}, std::byte{0x03}
        };

        constexpr auto expected = std::array{
            std::byte{0x70}, std::byte{0xd5}, std::byte{0x4a}, std::byte{0x1e},
            std::byte{0xdc}, std::byte{0x7d}, std::byte{0xb0}, std::byte{0xde},
            std::byte{0x29}, std::byte{0x1f}, std::byte{0x29}, std::byte{0x17},
            std::byte{0x43}, std::byte{0x6d}, std::byte{0xf3}, std::byte{0xb2}
        };

        EXPECT_EQ(encrypted, expected);
        EXPECT_NE(encrypted, empty);
        EXPECT_NE(encrypted, unencrypted);

        auto const decrypted = crypto23::aes_256::decrypt_string(encrypted, key);
        EXPECT_EQ(decrypted, input);
    }

    TEST(aes_256, exact_block_size_string_test) {
        std::string const input = "Hello, World!   ";
        static constexpr auto key = std::array{
            std::byte{0x2b}, std::byte{0x7e}, std::byte{0x15}, std::byte{0x16},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88},
            std::byte{0x09}, std::byte{0xcf}, std::byte{0x4f}, std::byte{0x3c},
            std::byte{0x18}, std::byte{0x9f}, std::byte{0xb6}, std::byte{0x41},
            std::byte{0x1c}, std::byte{0x3f}, std::byte{0x9d}, std::byte{0xf8},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88}
        };

        constexpr auto encrypted = crypto23::aes_256::encrypt_string("Hello, World!   ", key);

        constexpr auto expected = std::array{
            std::byte{0x62}, std::byte{0xc1}, std::byte{0x7d}, std::byte{0x59},
            std::byte{0x9c}, std::byte{0x1c}, std::byte{0x7d}, std::byte{0x84},
            std::byte{0x0d}, std::byte{0xb3}, std::byte{0x3e}, std::byte{0x25},
            std::byte{0x8c}, std::byte{0x8a}, std::byte{0x6a}, std::byte{0x1d},
            std::byte{0x2a}, std::byte{0x6e}, std::byte{0x51}, std::byte{0xd9},
            std::byte{0x43}, std::byte{0x86}, std::byte{0x61}, std::byte{0xfd},
            std::byte{0xb9}, std::byte{0x9c}, std::byte{0x3e}, std::byte{0x55},
            std::byte{0xfa}, std::byte{0xb0}, std::byte{0x16}, std::byte{0xc7}
        };

        EXPECT_EQ(encrypted, expected);

        auto const decrypted = crypto23::aes_256::decrypt_string(encrypted, key);
        EXPECT_EQ(decrypted, input);
    }
}
