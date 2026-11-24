#include "cypherarx/kdf.hpp"

#include <algorithm>
#include <chrono>
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

namespace {

constexpr std::size_t kMemUnit = 1024;

std::optional<double> time_derivation(const KdfParams& params) {
    static constexpr std::array<std::uint8_t, 16> password{};
    static constexpr std::array<std::uint8_t, kdf::salt_bytes> salt{};
    const auto start = std::chrono::steady_clock::now();
    const auto kek = derive_kek(password, salt, params);
    if (!kek) {
        return std::nullopt;
    }
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

std::size_t whole_units(double bytes, std::size_t low, std::size_t high) {
    const double clamped = std::clamp(bytes, static_cast<double>(low), static_cast<double>(high));
    return std::max(low, static_cast<std::size_t>(clamped) / kMemUnit * kMemUnit);
}

}

std::expected<KdfChoices, KdfError> benchmark_kdf(const KdfBenchmarkOptions& options) {
    if (options.budget_seconds <= 0.0 || options.ops_limit == 0 || options.min_mem < kMemUnit ||
        options.max_mem < options.min_mem) {
        return std::unexpected(KdfError::InvalidParams);
    }
    const KdfParams smallest{options.ops_limit, options.min_mem};
    const auto reference = time_derivation(smallest);
    if (!reference) {
        return std::unexpected(KdfError::DerivationFailed);
    }
    const double per_byte = std::max(*reference, 1e-9) / static_cast<double>(options.min_mem);
    KdfChoices out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        const double target = options.budget_seconds * options.shares[i];
        KdfParams params{options.ops_limit, whole_units(target / per_byte, options.min_mem, options.max_mem)};
        std::optional<double> seconds = params == smallest ? reference : time_derivation(params);
        while (!seconds && params.mem_limit > options.min_mem) {
            params.mem_limit = whole_units(static_cast<double>(params.mem_limit) / 2.0, options.min_mem,
                                           options.max_mem);
            seconds = params == smallest ? reference : time_derivation(params);
        }
        if (!seconds) {
            return std::unexpected(KdfError::DerivationFailed);
        }
        if (*seconds > target * options.overshoot && params.mem_limit > options.min_mem) {
            params.mem_limit = whole_units(static_cast<double>(params.mem_limit) * target / *seconds,
                                           options.min_mem, options.max_mem);
            seconds = params == smallest ? reference : time_derivation(params);
            if (!seconds) {
                return std::unexpected(KdfError::DerivationFailed);
            }
        }
        if (i > 0 && params.mem_limit < out[i - 1].params.mem_limit) {
            out[i] = out[i - 1];
        } else {
            out[i] = {params, *seconds};
        }
    }
    return out;
}

} // namespace cypherarx
