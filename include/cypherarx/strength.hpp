#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace cypherarx {

inline constexpr std::size_t kMasterPasswordMinLength = 12;

enum class PasswordVerdict { TooShort, Rejected, Warn, Advise, Ok };

struct PasswordStrength {
    std::size_t length = 0;
    double guesses_log10 = 0.0;
    int score = 0;
    PasswordVerdict verdict = PasswordVerdict::TooShort;
};

PasswordStrength master_password_strength(std::span<const std::uint8_t> password);

}
