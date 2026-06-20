#include "cypherarx/passgen.hpp"

#include <cstring>
#include <string>
#include <vector>

#include <sodium.h>

namespace cypherarx {

namespace {

std::uint32_t uniform(std::size_t n) {
    return randombytes_uniform(static_cast<std::uint32_t>(n));
}

struct CharClass {
    const std::string* chars;
    std::size_t min_count;
};

} // namespace

std::expected<Secret, PasswordError> generate_password(const PasswordPolicy& policy) {
    if (policy.min_length == 0 || policy.min_length > policy.max_length) {
        return std::unexpected(PasswordError::InvalidPolicy);
    }

    static const std::string lower = "abcdefghijklmnopqrstuvwxyz";
    static const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const std::string digits = "0123456789";
    const std::string symbols = policy.use_symbols ? policy.allowed_symbols : std::string();

    std::vector<CharClass> classes;
    if (policy.use_lower) classes.push_back({&lower, policy.min_lower});
    if (policy.use_upper) classes.push_back({&upper, policy.min_upper});
    if (policy.use_digits) classes.push_back({&digits, policy.min_digits});
    if (policy.use_symbols && !symbols.empty()) classes.push_back({&symbols, policy.min_symbols});
    if (classes.empty()) {
        return std::unexpected(PasswordError::InvalidPolicy);
    }

    std::size_t min_required = 0;
    for (const auto& c : classes) {
        min_required += c.min_count;
    }

    const std::size_t span = policy.max_length - policy.min_length + 1;
    const std::size_t length = policy.min_length + uniform(span);
    if (min_required > length) {
        return std::unexpected(PasswordError::InvalidPolicy);
    }

    std::string pool;
    for (const auto& c : classes) {
        pool += *c.chars;
    }

    std::vector<char> buf;
    buf.reserve(length);
    for (const auto& c : classes) {
        for (std::size_t k = 0; k < c.min_count; ++k) {
            buf.push_back((*c.chars)[uniform(c.chars->size())]);
        }
    }
    while (buf.size() < length) {
        buf.push_back(pool[uniform(pool.size())]);
    }

    // Fisher-Yates shuffle so the guaranteed-class characters are not clustered up front.
    for (std::size_t i = buf.size(); i > 1; --i) {
        const std::size_t j = uniform(i);
        std::swap(buf[i - 1], buf[j]);
    }

    Secret out(buf.size());
    std::memcpy(out.data(), buf.data(), buf.size());
    sodium_memzero(buf.data(), buf.size()); // wipe the temporary plaintext
    return out;
}

} // namespace cypherarx
