#pragma once

#include <cstddef>
#include <expected>
#include <string>

#include "cypherarx/secret.hpp"

namespace cypherarx {

enum class PasswordError {
    InvalidPolicy,  ///< No character class enabled, bad length range, or min counts > length.
};

/// Password generation policy (mirrors the `password_policies` table, design §11).
struct PasswordPolicy {
    std::size_t min_length = 16;
    std::size_t max_length = 16;  ///< Length is chosen uniformly in [min_length, max_length].

    bool use_upper = true;
    bool use_lower = true;
    bool use_digits = true;
    bool use_symbols = true;
    std::string allowed_symbols = "!@#$%^&*()-_=+[]{}:;,.?";  ///< Used only if use_symbols.

    std::size_t min_lower = 0;
    std::size_t min_upper = 0;
    std::size_t min_digits = 0;
    std::size_t min_symbols = 0;
};

/// Generate a password into guarded memory using a cryptographic RNG. Guarantees the
/// requested minimum count of each enabled class, then fills and shuffles the rest.
std::expected<Secret, PasswordError> generate_password(const PasswordPolicy& policy);

} // namespace cypherarx
