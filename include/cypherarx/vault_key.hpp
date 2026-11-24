#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <utility>
#include <vector>

#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"

namespace cypherarx {

/// Failure modes for the KEK/DEK key hierarchy.
enum class VaultKeyError {
    InvalidInput,    ///< Wrong salt/key size, or malformed wrapped DEK.
    KdfFailed,       ///< Argon2id (KEK derivation) failed.
    WrongPassword,   ///< KEK could not unwrap the DEK (bad master password).
    Internal,        ///< Unexpected lower-layer error.
};

/// Non-secret material needed to unlock a vault. Maps to `crypto_meta` rows:
/// `salt` -> kdf_salt, `params` -> kdf_params, `wrapped_dek` -> wrapped_dek.
/// `wrapped_dek` is a self-describing AEAD blob (the nonce is embedded), so the
/// design's separate `wrap_nonce` column is unnecessary.
struct VaultKeyMaterial {
    std::vector<std::uint8_t> salt;
    KdfParams params{};
    std::vector<std::uint8_t> wrapped_dek;
};

// --- Low-level: wrap/unwrap a DEK with a KEK ---

/// Encrypt (wrap) a DEK under a KEK. Returns a self-describing AEAD blob.
std::expected<std::vector<std::uint8_t>, VaultKeyError>
wrap_dek(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> dek);

/// Decrypt (unwrap) a DEK blob with a KEK, into guarded memory.
std::expected<Secret, VaultKeyError>
unwrap_dek(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> wrapped_dek);

// --- High-level: vault lifecycle ---

/// Create a brand-new vault key set from a master password: fresh salt, a random DEK,
/// a KEK derived via Argon2id, and the DEK wrapped under the KEK. Returns the live DEK
/// (guarded) and the material to persist.
std::expected<std::pair<Secret, VaultKeyMaterial>, VaultKeyError>
create_vault_keys(std::span<const std::uint8_t> password, const KdfParams& params);

/// Unlock an existing vault: derive the KEK from the password + material and unwrap the DEK.
std::expected<Secret, VaultKeyError>
unlock_vault(std::span<const std::uint8_t> password, const VaultKeyMaterial& material);

} // namespace cypherarx
