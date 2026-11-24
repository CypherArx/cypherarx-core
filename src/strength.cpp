#include "cypherarx/strength.hpp"

#include "cypherarx/secret.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>

extern "C" {
#include <zxcvbn.h>
}

namespace cypherarx {

namespace {

constexpr std::array<double, 4> kScoreGuessesLog10{3.0, 6.0, 8.0, 10.0};

std::size_t code_points(std::span<const std::uint8_t> text) {
    return static_cast<std::size_t>(
        std::ranges::count_if(text, [](std::uint8_t byte) { return (byte & 0xC0) != 0x80; }));
}

}

PasswordStrength master_password_strength(std::span<const std::uint8_t> password) {
    PasswordStrength out;
    out.length = code_points(password);
    if (!password.empty()) {
        Secret text(password.size() + 1);
        std::memcpy(text.data(), password.data(), password.size());
        text.data()[password.size()] = 0;
        const double bits = ZxcvbnMatch(reinterpret_cast<const char*>(text.data()), nullptr, nullptr);
        out.guesses_log10 = std::max(0.0, bits) * std::log10(2.0);
    }
    out.score = static_cast<int>(std::ranges::count_if(
        kScoreGuessesLog10, [&](double limit) { return out.guesses_log10 >= limit; }));
    if (out.length < kMasterPasswordMinLength) {
        out.verdict = PasswordVerdict::TooShort;
    } else if (out.score <= 1) {
        out.verdict = PasswordVerdict::Rejected;
    } else if (out.score == 2) {
        out.verdict = PasswordVerdict::Warn;
    } else if (out.score == 3) {
        out.verdict = PasswordVerdict::Advise;
    } else {
        out.verdict = PasswordVerdict::Ok;
    }
    return out;
}

}
