#include "cypherarx/kdf.hpp"

#include <optional>

#include <sodium.h>

namespace cypherarx {

static_assert(kdf::salt_bytes == crypto_pwhash_SALTBYTES);
static_assert(kdf::kek_bytes >= crypto_pwhash_BYTES_MIN);

KdfParams KdfParams::interactive() {
    return {crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE};
}

KdfParams KdfParams::moderate() {
    return {crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE};
}

KdfParams KdfParams::sensitive() {
    return {crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE};
}

std::string KdfParams::to_string() const {
    return "argon2id,ops=" + std::to_string(ops_limit) + ",mem=" + std::to_string(mem_limit);
}

std::expected<KdfParams, KdfError> KdfParams::from_string(std::string_view text) {
    if (!text.starts_with("argon2id")) {
        return std::unexpected(KdfError::InvalidParams);
    }

    const auto read_u64 = [text](std::string_view key) -> std::optional<std::uint64_t> {
        const auto pos = text.find(key);
        if (pos == std::string_view::npos) {
            return std::nullopt;
        }
        std::size_t i = pos + key.size();
        if (i >= text.size() || text[i] < '0' || text[i] > '9') {
            return std::nullopt;
        }
        std::uint64_t value = 0;
        for (; i < text.size() && text[i] >= '0' && text[i] <= '9'; ++i) {
            value = value * 10 + static_cast<std::uint64_t>(text[i] - '0');
        }
        return value;
    };

    const auto ops = read_u64("ops=");
    const auto mem = read_u64("mem=");
    if (!ops || !mem) {
        return std::unexpected(KdfError::InvalidParams);
    }
    return KdfParams{*ops, static_cast<std::size_t>(*mem)};
}

std::expected<void, KdfError> generate_salt(std::span<std::uint8_t> salt) {
    if (salt.size() != kdf::salt_bytes) {
        return std::unexpected(KdfError::InvalidSaltSize);
    }
    randombytes_buf(salt.data(), salt.size());
    return {};
}

std::expected<Secret, KdfError>
derive_kek(std::span<const std::uint8_t> password,
           std::span<const std::uint8_t> salt,
           const KdfParams& params) {
    if (salt.size() != kdf::salt_bytes) {
        return std::unexpected(KdfError::InvalidSaltSize);
    }

    Secret kek(kdf::kek_bytes);
    const int rc = crypto_pwhash(
        kek.data(), kek.size(),
        reinterpret_cast<const char*>(password.data()), password.size(),
        salt.data(),
        params.ops_limit, params.mem_limit,
        crypto_pwhash_ALG_ARGON2ID13);
    if (rc != 0) {
        return std::unexpected(KdfError::DerivationFailed);
    }
    return kek;
}

} // namespace cypherarx
