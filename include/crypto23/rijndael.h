//
// Created by Rene Windegger on 27/05/2026.
//

#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <ranges>
#include <vector>

namespace crypto23 {
    enum class rijndael_key_mode {
        K128,
        K160,
        K192,
        K224,
        K256,
    };

    enum class rijndael_block_mode {
        B128,
        B160,
        B192,
        B224,
        B256,
    };

    namespace detail {
        consteval std::array<std::byte, 256> calculate_substitution_box() {
            std::array<std::byte, 256> result{};

            std::uint8_t p = 1;
            std::uint8_t q = 1;

            do {
                p = static_cast<std::uint8_t>(p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0));

                q ^= q << 1;
                q ^= q << 2;
                q ^= q << 4;
                q ^= q & 0x80 ? 0x09 : 0;

                auto const affine_transformed = q ^
                                                std::rotl(q, 1) ^
                                                std::rotl(q, 2) ^
                                                std::rotl(q, 3) ^
                                                std::rotl(q, 4);
                result[p] = static_cast<std::byte>(affine_transformed ^ 0x63);
            } while (p != 1);

            result[0] = std::byte{0x63};
            return result;
        }

        static constexpr auto substitution_box = calculate_substitution_box();

        consteval std::array<std::byte, 256> calculate_inverse_substitution_box() {
            std::array<std::byte, 256> result{};
            for (std::size_t i = 0; i < 256; ++i) {
                auto const it = std::ranges::find(substitution_box, static_cast<std::byte>(i));
                auto index = std::distance(substitution_box.begin(), it);
                result[i] = static_cast<std::byte>(index);
            }
            return result;
        }

        static constexpr auto reverse_substitution_box = calculate_inverse_substitution_box();

        consteval std::byte calculate_rcon(std::size_t round) {
            auto c = std::byte{1};
            if (round == 0) {
                return std::byte{0};
            }
            while (round != 1) {
                auto const b = c & std::byte{0x80};
                c <<= 1;
                if (b == std::byte{0x80}) {
                    c ^= std::byte{0x1b};
                }
                --round;
            }
            return c;
        }

        consteval std::array<std::byte, 11> calculate_rcon_table() {
            std::array<std::byte, 11> result{};
            for (std::size_t i = 0; i < 11; ++i) {
                result[i] = calculate_rcon(i);
            }
            return result;
        }

        static constexpr auto rcon = calculate_rcon_table();

        constexpr std::byte gmul(std::byte a, std::byte b) {
            std::byte result{};
            for (std::size_t i = 0; i < 8; ++i) {
                if (static_cast<bool>(b & std::byte{1})) {
                    result ^= a;
                }
                bool const hi = static_cast<bool>(a & std::byte{0x80});
                a <<= 1;
                if (hi) {
                    a ^= std::byte{0x1b};
                }
                b >>= 1;
            }
            return result;
        }

        constexpr void rotate(std::span<std::byte, 4> in) {
            auto const temp = in[0];
            for (std::size_t c = 0; c < 3; ++c) {
                in[c] = in[c + 1];
            }
            in[3] = temp;
        }

        constexpr void schedule_core(std::span<std::byte, 4> in, std::size_t const i) {
            rotate(in);
            for (std::size_t c = 0; c < 4; ++c) {
                in[c] = substitution_box[std::to_integer<std::size_t>(in[c])];
            }
            in[0] ^= rcon[i];
        }

        template<std::size_t KeySize, std::size_t ExpandedKeySize>
        constexpr std::array<std::byte, ExpandedKeySize> key_expansion(std::span<std::byte const, KeySize> const &key) {
            std::array<std::byte, ExpandedKeySize> result{};
            std::copy_n(key.begin(), KeySize, result.begin());

            auto c = KeySize;
            auto i = 1uz;
            while (c < ExpandedKeySize) {
                std::array<std::byte, 4> temp{};

                for (auto a = 0uz; a < 4uz; ++a) {
                    temp[a] = result[a + c - 4];
                }
                if (c % KeySize == 0) {
                    std::span<std::byte, 4> const temp_span{temp.begin(), temp.end()};
                    schedule_core(temp_span, i);
                    ++i;
                }
                if constexpr (KeySize > 24uz) {
                    if (c % KeySize == 16) {
                        for (auto a = 0uz; a < 4uz; ++a) {
                            temp[a] = substitution_box[std::to_integer<std::size_t>(temp[a])];
                        }
                    }
                }
                for (auto a = 0uz; a < 4uz; ++a) {
                    result[c] = result[c - KeySize] ^ temp[a];
                    ++c;
                }
            }

            return result;
        }

        template<rijndael_block_mode BlockSize, rijndael_key_mode KeySize>
        class rijndael_constants {
        public:
            static constexpr auto is_valid = false;
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B128, rijndael_key_mode::K128> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 16uz;
            static constexpr auto block_size = 16uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B128, rijndael_key_mode::K160> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 20uz;
            static constexpr auto block_size = 16uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B128, rijndael_key_mode::K192> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 24uz;
            static constexpr auto block_size = 16uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B128, rijndael_key_mode::K224> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 28uz;
            static constexpr auto block_size = 16uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B128, rijndael_key_mode::K256> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 32uz;
            static constexpr auto block_size = 16uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B160, rijndael_key_mode::K128> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 16uz;
            static constexpr auto block_size = 20uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B160, rijndael_key_mode::K160> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 20uz;
            static constexpr auto block_size = 20uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B160, rijndael_key_mode::K192> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 24uz;
            static constexpr auto block_size = 20uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B160, rijndael_key_mode::K224> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 28uz;
            static constexpr auto block_size = 20uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B160, rijndael_key_mode::K256> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 32uz;
            static constexpr auto block_size = 20uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B192, rijndael_key_mode::K128> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 16uz;
            static constexpr auto block_size = 24uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B192, rijndael_key_mode::K160> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 20uz;
            static constexpr auto block_size = 24uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B192, rijndael_key_mode::K192> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 24uz;
            static constexpr auto block_size = 24uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B192, rijndael_key_mode::K224> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 28uz;
            static constexpr auto block_size = 24uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B192, rijndael_key_mode::K256> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 32uz;
            static constexpr auto block_size = 24uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B224, rijndael_key_mode::K128> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 16uz;
            static constexpr auto block_size = 28uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B224, rijndael_key_mode::K160> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 20uz;
            static constexpr auto block_size = 28uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B224, rijndael_key_mode::K192> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 24uz;
            static constexpr auto block_size = 28uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B224, rijndael_key_mode::K224> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 28uz;
            static constexpr auto block_size = 28uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B224, rijndael_key_mode::K256> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 32uz;
            static constexpr auto block_size = 28uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B256, rijndael_key_mode::K128> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 16uz;
            static constexpr auto block_size = 32uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B256, rijndael_key_mode::K160> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 20uz;
            static constexpr auto block_size = 32uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B256, rijndael_key_mode::K192> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 24uz;
            static constexpr auto block_size = 32uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B256, rijndael_key_mode::K224> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 28uz;
            static constexpr auto block_size = 32uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };

        template<>
        class rijndael_constants<rijndael_block_mode::B256, rijndael_key_mode::K256> {
        public:
            static constexpr auto is_valid = true;
            static constexpr auto key_size = 32uz;
            static constexpr auto block_size = 32uz;
            static constexpr auto round_count = std::max(key_size, block_size) / 4 + 6;
            static constexpr auto expanded_key_size = block_size * (round_count + 1);
        };
    }

    template<rijndael_block_mode BlockSize, rijndael_key_mode KeySize>
    class rijndael {
    private:
        static_assert(detail::rijndael_constants<BlockSize, KeySize>::is_valid, "Invalid Rijndael mode");

        static constexpr auto block_size = detail::rijndael_constants<BlockSize, KeySize>::block_size;
        static constexpr auto round_count = detail::rijndael_constants<BlockSize, KeySize>::round_count;
        static constexpr auto key_size = detail::rijndael_constants<BlockSize, KeySize>::key_size;
        static constexpr auto expanded_key_size = detail::rijndael_constants<BlockSize, KeySize>::expanded_key_size;

        static constexpr void add_round_key(
            std::span<std::byte, block_size> &state,
            std::span<std::byte const, expanded_key_size> const &w,
            std::size_t const round
        ) {
            for (auto i = 0uz; i < block_size; ++i) {
                state[i] ^= w[round * block_size + i];
            }
        }

        static constexpr void sub_bytes(std::span<std::byte, block_size> &state) {
            for (auto i = 0uz; i < 16uz; ++i) {
                state[i] = detail::substitution_box[static_cast<std::size_t>(state[i])];
            }
        }

        static constexpr void inverse_sub_bytes(std::span<std::byte, block_size> &state) {
            for (auto i = 0uz; i < 16uz; ++i) {
                state[i] = detail::reverse_substitution_box[static_cast<std::size_t>(state[i])];
            }
        }

        static constexpr void shift_rows(std::span<std::byte, block_size> &state) {
            std::array<std::byte, 16> temp{};
            std::copy_n(state.begin(), block_size, temp.begin());
            state[1] = temp[5];
            state[5] = temp[9];
            state[9] = temp[13];
            state[13] = temp[1];
            state[2] = temp[10];
            state[6] = temp[14];
            state[10] = temp[2];
            state[14] = temp[6];
            state[3] = temp[15];
            state[7] = temp[3];
            state[11] = temp[7];
            state[15] = temp[11];
        }

        static constexpr void inverse_shift_rows(std::span<std::byte, block_size> &state) {
            std::array<std::byte, 16> temp{};
            std::copy_n(state.begin(), block_size, temp.begin());
            state[1] = temp[13];
            state[5] = temp[1];
            state[9] = temp[5];
            state[13] = temp[9];
            state[2] = temp[10];
            state[6] = temp[14];
            state[10] = temp[2];
            state[14] = temp[6];
            state[3] = temp[7];
            state[7] = temp[11];
            state[11] = temp[15];
            state[15] = temp[3];
        }

        static constexpr void mix_columns(std::span<std::byte, block_size> &state) {
            std::array<std::byte, block_size> temp{};
            std::copy_n(state.begin(), block_size, temp.begin());
            for (std::size_t i = 0; i < 4; ++i) {
                state[4 * i + 0] = detail::gmul(temp[4 * i + 0], std::byte{2}) ^
                                   detail::gmul(temp[4 * i + 1], std::byte{3}) ^
                                   temp[4 * i + 2] ^
                                   temp[4 * i + 3];
                state[4 * i + 1] = temp[4 * i + 0] ^
                                   detail::gmul(temp[4 * i + 1], std::byte{2}) ^
                                   detail::gmul(temp[4 * i + 2], std::byte{3}) ^
                                   temp[4 * i + 3];
                state[4 * i + 2] = temp[4 * i + 0] ^
                                   temp[4 * i + 1] ^
                                   detail::gmul(temp[4 * i + 2], std::byte{2}) ^
                                   detail::gmul(temp[4 * i + 3], std::byte{3});
                state[4 * i + 3] = detail::gmul(temp[4 * i + 0], std::byte{3}) ^
                                   temp[4 * i + 1] ^
                                   temp[4 * i + 2] ^
                                   detail::gmul(temp[4 * i + 3], std::byte{2});
            }
        }

        static constexpr void inverse_mix_columns(std::span<std::byte, block_size> state) {
            std::array<std::byte, block_size> temp{};
            std::copy_n(state.begin(), block_size, temp.begin());
            for (std::size_t i = 0; i < 4; ++i) {
                state[4 * i + 0] = detail::gmul(temp[4 * i + 0], std::byte{0x0e}) ^
                                   detail::gmul(temp[4 * i + 1], std::byte{0x0b}) ^
                                   detail::gmul(temp[4 * i + 2], std::byte{0x0d}) ^
                                   detail::gmul(temp[4 * i + 3], std::byte{0x09});
                state[4 * i + 1] = detail::gmul(temp[4 * i + 0], std::byte{0x09}) ^
                                   detail::gmul(temp[4 * i + 1], std::byte{0x0e}) ^
                                   detail::gmul(temp[4 * i + 2], std::byte{0x0b}) ^
                                   detail::gmul(temp[4 * i + 3], std::byte{0x0d});
                state[4 * i + 2] = detail::gmul(temp[4 * i + 0], std::byte{0x0d}) ^
                                   detail::gmul(temp[4 * i + 1], std::byte{0x09}) ^
                                   detail::gmul(temp[4 * i + 2], std::byte{0x0e}) ^
                                   detail::gmul(temp[4 * i + 3], std::byte{0x0b});
                state[4 * i + 3] = detail::gmul(temp[4 * i + 0], std::byte{0x0b}) ^
                                   detail::gmul(temp[4 * i + 1], std::byte{0x0d}) ^
                                   detail::gmul(temp[4 * i + 2], std::byte{0x09}) ^
                                   detail::gmul(temp[4 * i + 3], std::byte{0x0e});
            }
        }

        static constexpr void encrypt_block(
            std::span<std::byte, block_size> &block,
            std::span<std::byte const, key_size> const &key
        ) {
            auto const w = detail::key_expansion<key_size, expanded_key_size>(key);
            add_round_key(block, w, 0);
            for (auto round = 1uz; round < round_count; ++round) {
                sub_bytes(block);
                shift_rows(block);
                mix_columns(block);
                add_round_key(block, w, round);
            }
            sub_bytes(block);
            shift_rows(block);
            add_round_key(block, w, round_count);
        }

        static constexpr void decrypt_block(
            std::span<std::byte, block_size> &block,
            std::span<std::byte const, key_size> const &key
        ) {
            auto const w = detail::key_expansion<key_size, expanded_key_size>(key);
            add_round_key(block, w, round_count);
            for (auto round = round_count - 1; round > 0; --round) {
                inverse_shift_rows(block);
                inverse_sub_bytes(block);
                add_round_key(block, w, round);
                inverse_mix_columns(block);
            }
            inverse_shift_rows(block);
            inverse_sub_bytes(block);
            add_round_key(block, w, 0);
        }

        static constexpr std::size_t calculate_blocks(std::size_t const size) {
            return (size + block_size) / block_size;
        }

    public:
        template<std::size_t N>
        [[nodiscard]] static constexpr std::array<std::byte, calculate_blocks(N) * block_size> encrypt_buffer(
            std::span<std::byte const, N> const &buffer,
            std::span<std::byte const, key_size> const &key
        ) {
            std::array<std::byte, N> temp{};
            std::copy_n(buffer.begin(), N, temp.begin());
            return encrypt_buffer(temp, key);
        }

        template<std::size_t N>
        [[nodiscard]] static constexpr std::array<std::byte, calculate_blocks(N) * block_size> encrypt_buffer(
            std::array<std::byte, N> const &buffer,
            std::span<std::byte const, key_size> const &key
        ) {
            static constexpr auto blocks = calculate_blocks(N);
            static constexpr auto cipher_size = blocks * block_size;
            static constexpr auto padding_value = cipher_size - N;

            std::array<std::byte, cipher_size> result{};
            std::copy_n(buffer.begin(), N, result.begin());
            std::fill_n(result.begin() + N, padding_value, std::byte{padding_value});

            for (auto b = 0uz; b < blocks; ++b) {
                std::span<std::byte, block_size> block{result.begin() + b * block_size, block_size};
                encrypt_block(block, key);
            }
            return result;
        }

        template<typename T>
            requires std::ranges::contiguous_range<T>
                     and std::ranges::sized_range<T>
                     and (sizeof(std::ranges::range_value_t<T>) == 1)
        [[nodiscard]] static std::vector<std::byte> encrypt(
            T const &buffer,
            std::span<std::byte const, key_size> const &key
        ) {
            auto const N = std::ranges::size(buffer);
            auto const blocks = calculate_blocks(N);
            auto const cipher_size = blocks * block_size;
            auto const padding_value = cipher_size - N;

            std::vector<std::byte> result{};
            result.resize(cipher_size);
            std::copy_n(buffer.begin(), N, result.begin());
            std::fill_n(
                result.begin() + static_cast<std::vector<std::byte>::difference_type>(N),
                padding_value,
                static_cast<std::byte>(padding_value)
            );

            for (auto b = 0uz; b < blocks; ++b) {
                std::span<std::byte, block_size> block{
                    result.begin() + static_cast<std::vector<std::byte>::difference_type>(b * block_size),
                    block_size
                };
                encrypt_block(block, key);
            }
            return result;
        }

        template<std::size_t N>
        [[nodiscard]] static constexpr std::array<std::byte, calculate_blocks(N - 1) * block_size> encrypt_string(
            char const (&str)[N],
            std::span<std::byte const, key_size> const &key
        ) {
            static constexpr auto blocks = calculate_blocks(N - 1);
            static constexpr auto cipher_size = blocks * block_size;
            static constexpr auto padding_value = cipher_size - (N - 1);

            std::array<std::byte, cipher_size> result{};
            for (auto i = 0uz; i < N - 1; ++i) {
                result[i] = static_cast<std::byte>(str[i]);
            }
            std::fill_n(result.begin() + N - 1, padding_value, std::byte{padding_value});

            for (auto b = 0uz; b < blocks; ++b) {
                std::span<std::byte, block_size> block{result.begin() + b * block_size, block_size};
                encrypt_block(block, key);
            }
            return result;
        }

        template<std::size_t N>
        [[nodiscard]] static std::vector<std::byte> decrypt_buffer(
            std::span<std::byte const, N> const &buffer,
            std::span<std::byte const, key_size> const &key
        ) {
            std::array<std::byte, N> temp{};
            std::copy_n(buffer.begin(), N, temp.begin());
            return decrypt_buffer(temp, key);
        }

        template<std::size_t N>
        [[nodiscard]] static std::vector<std::byte> decrypt_buffer(
            std::array<std::byte, N> const &buffer,
            std::span<std::byte const, key_size> const &key
        ) {
            std::vector<std::byte> result(buffer.begin(), buffer.end());
            for (auto b = 0uz; b < N / block_size; ++b) {
                std::span<std::byte, block_size> block{
                    result.begin() + static_cast<std::vector<std::byte>::difference_type>(b * block_size),
                    block_size
                };
                decrypt_block(block, key);
            }

            auto const padding_value = std::to_integer<std::size_t>(result[N - 1]);
            result.resize(N - padding_value);
            return result;
        }

        template<typename T>
            requires std::ranges::contiguous_range<T>
                     and std::ranges::sized_range<T>
                     and (sizeof(std::ranges::range_value_t<T>) == 1)
        [[nodiscard]] static std::vector<std::byte> decrypt(
            T const &buffer,
            std::span<std::byte const, key_size> const &key
        ) {
            auto const N = std::ranges::size(buffer);
            std::vector<std::byte> result(buffer.begin(), buffer.end());
            for (auto b = 0uz; b < N / block_size; ++b) {
                std::span<std::byte, block_size> block{
                    result.begin() + static_cast<std::vector<std::byte>::difference_type>(b * block_size),
                    block_size
                };
                decrypt_block(block, key);
            }

            auto const padding_value = std::to_integer<std::size_t>(result[N - 1]);
            result.resize(N - padding_value);
            return result;
        }

        template<std::size_t N>
        [[nodiscard]] static std::string decrypt_string(
            std::array<std::byte, N> data,
            std::span<std::byte const, key_size> const &key
        ) {
            for (auto b = 0uz; b < N / block_size; ++b) {
                std::span<std::byte, block_size> block{
                    data.begin() + static_cast<std::array<std::byte, N>::difference_type>(b * block_size),
                    block_size
                };
                decrypt_block(block, key);
            }

            auto const padding_value = std::to_integer<std::size_t>(data[N - 1]);
            auto const length = N - padding_value;

            std::array<char, N> str{};
            for (auto i = 0uz; i < length; ++i) {
                str[i] = std::to_integer<char>(data[i]);
            }
            return std::string(str.data(), length);
        }
    };

    using aes_128 = rijndael<rijndael_block_mode::B128, rijndael_key_mode::K128>;
    using aes_192 = rijndael<rijndael_block_mode::B128, rijndael_key_mode::K192>;
    using aes_256 = rijndael<rijndael_block_mode::B128, rijndael_key_mode::K256>;
}
