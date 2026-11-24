#include "cypherarx/vault_key.hpp"

#include "cypherarx/crypto.hpp"

namespace cypherarx {

namespace {

/// Domain-separation tag bound as AAD when wrapping the DEK, so a DEK blob can never be
/// confused with any other ciphertext in the vault.
std::span<const std::uint8_t> dek_aad() {
    static constexpr char tag[] = "cypherarx/dek-wrap/v1";
    return {reinterpret_cast<const std::uint8_t*>(tag), sizeof(tag) - 1};
}

VaultKeyError map_encrypt_error(CryptoError e) {
    return e == CryptoError::InvalidKeySize ? VaultKeyError::InvalidInput : VaultKeyError::Internal;
}

VaultKeyError map_decrypt_error(CryptoError e) {
    switch (e) {
        case CryptoError::DecryptionFailed:
            return VaultKeyError::WrongPassword;
        case CryptoError::InvalidKeySize:
        case CryptoError::InvalidCiphertext:
            return VaultKeyError::InvalidInput;
        default:
            return VaultKeyError::Internal;
    }
}

} // namespace

std::expected<std::vector<std::uint8_t>, VaultKeyError>
wrap_dek(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> dek) {
    auto blob = aead_encrypt(kek, dek, dek_aad());
    if (!blob) {
        return std::unexpected(map_encrypt_error(blob.error()));
    }
    return std::move(blob).value();
}

std::expected<Secret, VaultKeyError>
unwrap_dek(std::span<const std::uint8_t> kek, std::span<const std::uint8_t> wrapped_dek) {
    auto dek = aead_decrypt(kek, wrapped_dek, dek_aad());
    if (!dek) {
        return std::unexpected(map_decrypt_error(dek.error()));
    }
    return std::move(dek).value();
}

std::expected<std::pair<Secret, VaultKeyMaterial>, VaultKeyError>
create_vault_keys(std::span<const std::uint8_t> password, const KdfParams& params) {
    VaultKeyMaterial material;
    material.params = params;
    material.salt.resize(kdf::salt_bytes);
    if (!generate_salt(material.salt)) {
        return std::unexpected(VaultKeyError::Internal);
    }

    const auto kek = derive_kek(password, material.salt, params);
    if (!kek) {
        return std::unexpected(VaultKeyError::KdfFailed);
    }

    Secret dek = generate_key();
    auto wrapped = wrap_dek(kek->bytes(), dek.bytes());
    if (!wrapped) {
        return std::unexpected(wrapped.error());
    }
    material.wrapped_dek = std::move(wrapped).value();

    return std::pair<Secret, VaultKeyMaterial>{std::move(dek), std::move(material)};
}

std::expected<Secret, VaultKeyError>
unlock_vault(std::span<const std::uint8_t> password, const VaultKeyMaterial& material) {
    if (material.salt.size() != kdf::salt_bytes) {
        return std::unexpected(VaultKeyError::InvalidInput);
    }
    const auto kek = derive_kek(password, material.salt, material.params);
    if (!kek) {
        return std::unexpected(VaultKeyError::KdfFailed);
    }
    return unwrap_dek(kek->bytes(), material.wrapped_dek);
}

} // namespace cypherarx
