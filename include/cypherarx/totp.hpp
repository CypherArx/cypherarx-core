#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cypherarx {

enum class TotpError {
    InvalidSecret,  ///< Empty key, or invalid base32 input.
    InvalidParams,  ///< digits out of 1..9 or period == 0.
};

enum class TotpAlgorithm { Sha1, Sha256, Sha512 };

/// TOTP parameters (RFC 6238). Defaults match the de-facto authenticator standard.
struct TotpParams {
    TotpAlgorithm algorithm = TotpAlgorithm::Sha1;
    std::uint32_t digits = 6;
    std::uint32_t period = 30;  ///< seconds
};

/// Decode an RFC-4648 base32 secret (as found in otpauth URIs). Spaces, dashes and '='
/// padding are ignored; case-insensitive. Invalid characters are rejected.
std::expected<std::vector<std::uint8_t>, TotpError> base32_decode(std::string_view text);

/// Generate the TOTP code for the given Unix time (seconds).
std::expected<std::string, TotpError>
totp_at(std::span<const std::uint8_t> key, std::uint64_t unix_seconds,
        const TotpParams& params = {});

/// Generate the TOTP code for the current system time.
std::expected<std::string, TotpError>
totp_now(std::span<const std::uint8_t> key, const TotpParams& params = {});

/// Seconds remaining in the current period (for countdown UI).
std::uint32_t totp_seconds_remaining(std::uint64_t unix_seconds, std::uint32_t period = 30);

} // namespace cypherarx
