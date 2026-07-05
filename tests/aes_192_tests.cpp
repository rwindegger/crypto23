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
    TEST(aes_192, single_block_string_test) {
        std::string const input = "Hello, World!";
        static constexpr auto key = std::array{
            std::byte{0x2b}, std::byte{0x7e}, std::byte{0x15}, std::byte{0x16},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88},
            std::byte{0x09}, std::byte{0xcf}, std::byte{0x4f}, std::byte{0x3c},
            std::byte{0x18}, std::byte{0x9f}, std::byte{0xb6}, std::byte{0x41},
            std::byte{0x1c}, std::byte{0x3f}, std::byte{0x9d}, std::byte{0xf8}
        };

        constexpr auto encrypted = crypto23::aes_192::encrypt_string("Hello, World!", key);

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
            std::byte{0x37}, std::byte{0xc5}, std::byte{0x64}, std::byte{0x7d},
            std::byte{0xd5}, std::byte{0xb5}, std::byte{0x79}, std::byte{0x45},
            std::byte{0x2a}, std::byte{0x7b}, std::byte{0xeb}, std::byte{0x69},
            std::byte{0xf0}, std::byte{0xac}, std::byte{0x91}, std::byte{0x5f}
        };

        EXPECT_EQ(encrypted, expected);
        EXPECT_NE(encrypted, empty);
        EXPECT_NE(encrypted, unencrypted);

        auto const decrypted = crypto23::aes_192::decrypt_string(encrypted, key);
        EXPECT_EQ(decrypted, input);
    }

    TEST(aes_192, exact_block_size_string_test) {
        std::string const input = "Hello, World!   ";
        static constexpr auto key = std::array{
            std::byte{0x2b}, std::byte{0x7e}, std::byte{0x15}, std::byte{0x16},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88},
            std::byte{0x09}, std::byte{0xcf}, std::byte{0x4f}, std::byte{0x3c},
            std::byte{0x18}, std::byte{0x9f}, std::byte{0xb6}, std::byte{0x41},
            std::byte{0x1c}, std::byte{0x3f}, std::byte{0x9d}, std::byte{0xf8}
        };

        constexpr auto encrypted = crypto23::aes_192::encrypt_string("Hello, World!   ", key);

        constexpr auto expected = std::array{
            std::byte{0xd9}, std::byte{0x84}, std::byte{0x81}, std::byte{0xec},
            std::byte{0x4c}, std::byte{0x46}, std::byte{0x10}, std::byte{0xe9},
            std::byte{0xf8}, std::byte{0x26}, std::byte{0x6e}, std::byte{0x47},
            std::byte{0xec}, std::byte{0xcd}, std::byte{0xf1}, std::byte{0x52},
            std::byte{0xea}, std::byte{0x76}, std::byte{0x62}, std::byte{0x9b},
            std::byte{0x1c}, std::byte{0xf3}, std::byte{0x73}, std::byte{0x15},
            std::byte{0xac}, std::byte{0x72}, std::byte{0x67}, std::byte{0x0e},
            std::byte{0xad}, std::byte{0x73}, std::byte{0x75}, std::byte{0x65}
        };

        EXPECT_EQ(encrypted, expected);

        auto const decrypted = crypto23::aes_192::decrypt_string(encrypted, key);
        EXPECT_EQ(decrypted, input);
    }
}
