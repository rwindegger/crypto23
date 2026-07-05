//
// Created by Rene Windegger on 27/05/2026.
//

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <crypto23/rijndael.h>
#include <gtest/gtest.h>

namespace {
    TEST(aes_128, single_block_string_test) {
        std::string const input = "Hello, World!";
        static constexpr auto key = std::array{
            std::byte{0x2b}, std::byte{0x7e}, std::byte{0x15}, std::byte{0x16},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88},
            std::byte{0x09}, std::byte{0xcf}, std::byte{0x4f}, std::byte{0x3c}
        };
        
        constexpr auto encrypted = crypto23::aes_128::encrypt_string("Hello, World!", key);

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
            std::byte{0xcb}, std::byte{0x1e}, std::byte{0x00}, std::byte{0xf7},
            std::byte{0x1e}, std::byte{0xf6}, std::byte{0x9b}, std::byte{0x68},
            std::byte{0xe6}, std::byte{0x9b}, std::byte{0x64}, std::byte{0xb2},
            std::byte{0x0e}, std::byte{0xea}, std::byte{0x9b}, std::byte{0xaf}
        };

        EXPECT_EQ(encrypted, expected);
        EXPECT_NE(encrypted, empty);
        EXPECT_NE(encrypted, unencrypted);

        auto const decrypted = crypto23::aes_128::decrypt_string(encrypted, key);
        EXPECT_EQ(decrypted, input);
    }

    TEST(aes_128, exact_block_size_string_test) {
        std::string const input = "Hello, World!   ";
        static constexpr auto key = std::array{
            std::byte{0x2b}, std::byte{0x7e}, std::byte{0x15}, std::byte{0x16},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88},
            std::byte{0x09}, std::byte{0xcf}, std::byte{0x4f}, std::byte{0x3c}
        };

        constexpr auto encrypted = crypto23::aes_128::encrypt_string("Hello, World!   ", key);

        constexpr auto expected = std::array{
            std::byte{0x0a}, std::byte{0x47}, std::byte{0x34}, std::byte{0xe9},
            std::byte{0x75}, std::byte{0xf8}, std::byte{0x11}, std::byte{0x54},
            std::byte{0x50}, std::byte{0xdc}, std::byte{0x98}, std::byte{0x86},
            std::byte{0x09}, std::byte{0x0d}, std::byte{0x9f}, std::byte{0xc1},
            std::byte{0xa2}, std::byte{0x54}, std::byte{0xbe}, std::byte{0x88},
            std::byte{0xe0}, std::byte{0x37}, std::byte{0xdd}, std::byte{0xd9},
            std::byte{0xd7}, std::byte{0x9f}, std::byte{0xb6}, std::byte{0x41},
            std::byte{0x1c}, std::byte{0x3f}, std::byte{0x9d}, std::byte{0xf8}
        };

        EXPECT_EQ(encrypted, expected);

        auto const decrypted = crypto23::aes_128::decrypt_string(encrypted, key);
        EXPECT_EQ(decrypted, input);
    }

    TEST(aes_128, multiple_blocks_buffer_test) {
        static constexpr auto input = std::array{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x03},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x05},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x06}
        };

        static constexpr auto key = std::array{
            std::byte{0x2b}, std::byte{0x7e}, std::byte{0x15}, std::byte{0x16},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88},
            std::byte{0x09}, std::byte{0xcf}, std::byte{0x4f}, std::byte{0x3c}
        };

        constexpr auto encrypted = crypto23::aes_128::encrypt_buffer(std::span{input}, key);

        static constexpr auto expected = std::array{
            std::byte{0x96}, std::byte{0xe5}, std::byte{0xba}, std::byte{0xad},
            std::byte{0x4d}, std::byte{0x51}, std::byte{0x95}, std::byte{0x5f},
            std::byte{0x58}, std::byte{0xc1}, std::byte{0xef}, std::byte{0xe2},
            std::byte{0x8b}, std::byte{0x68}, std::byte{0x90}, std::byte{0x02},
            std::byte{0x59}, std::byte{0x83}, std::byte{0x43}, std::byte{0x40},
            std::byte{0x0e}, std::byte{0x56}, std::byte{0xdb}, std::byte{0x40},
            std::byte{0xb1}, std::byte{0x11}, std::byte{0xf1}, std::byte{0x98},
            std::byte{0xa4}, std::byte{0x67}, std::byte{0xea}, std::byte{0x7b}
        };

        EXPECT_EQ(encrypted, expected);

        auto const decrypted = crypto23::aes_128::decrypt_buffer(std::span{encrypted}, key);

        EXPECT_EQ(decrypted, std::vector(input.begin(), input.end()));
    }

    TEST(aes_128, multiple_blocks_vector_test) {
        auto const input = std::vector{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x03},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x05},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x06}
        };

        static constexpr auto key = std::array{
            std::byte{0x2b}, std::byte{0x7e}, std::byte{0x15}, std::byte{0x16},
            std::byte{0x28}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xa6},
            std::byte{0xab}, std::byte{0xf7}, std::byte{0x15}, std::byte{0x88},
            std::byte{0x09}, std::byte{0xcf}, std::byte{0x4f}, std::byte{0x3c}
        };

        auto const encrypted = crypto23::aes_128::encrypt(input, key);

        auto const expected = std::vector{
            std::byte{0x96}, std::byte{0xe5}, std::byte{0xba}, std::byte{0xad},
            std::byte{0x4d}, std::byte{0x51}, std::byte{0x95}, std::byte{0x5f},
            std::byte{0x58}, std::byte{0xc1}, std::byte{0xef}, std::byte{0xe2},
            std::byte{0x8b}, std::byte{0x68}, std::byte{0x90}, std::byte{0x02},
            std::byte{0x59}, std::byte{0x83}, std::byte{0x43}, std::byte{0x40},
            std::byte{0x0e}, std::byte{0x56}, std::byte{0xdb}, std::byte{0x40},
            std::byte{0xb1}, std::byte{0x11}, std::byte{0xf1}, std::byte{0x98},
            std::byte{0xa4}, std::byte{0x67}, std::byte{0xea}, std::byte{0x7b}
        };

        EXPECT_EQ(encrypted, expected);

        auto const decrypted = crypto23::aes_128::decrypt(encrypted, key);

        EXPECT_EQ(decrypted, input);
    }
}
