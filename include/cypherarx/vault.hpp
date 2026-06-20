#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>

#include "cypherarx/kdf.hpp"

namespace cypherarx {

/// Failure modes for opening/creating an on-disk vault.
enum class VaultError {
    CannotOpenFile,       ///< SQLite could not open/create the file.
    AlreadyInitialized,   ///< create() called on an existing file.
    NotInitialized,       ///< open() called on a missing/empty file.
    Corrupt,              ///< Required crypto_meta rows are missing/unparseable.
    WrongPassword,        ///< Master password did not unwrap the DEK.
    KdfFailed,            ///< Argon2id failed.
    DatabaseError,        ///< Unexpected SQLite error.
    NotUnlocked,          ///< Operation requires an unlocked vault.
};

/// An encrypted vault backed by a single SQLite file. Owns the in-memory DEK once
/// unlocked. Move-only; the DEK is wiped on destruction. This is the persistence entry
/// point on top of the KEK/DEK key hierarchy; entry/field storage builds on it.
class Vault {
public:
    Vault(Vault&&) noexcept;
    Vault& operator=(Vault&&) noexcept;
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;
    ~Vault();

    /// Create a new vault file (must not already exist) and leave it unlocked.
    static std::expected<Vault, VaultError>
    create(const std::string& path, std::span<const std::uint8_t> password,
           const KdfParams& params);

    /// Open an existing vault file and unlock it with the master password.
    static std::expected<Vault, VaultError>
    open(const std::string& path, std::span<const std::uint8_t> password);

    /// Change the master password: KEK is regenerated, the DEK (and all data) is unchanged.
    std::expected<void, VaultError>
    change_master_password(std::span<const std::uint8_t> old_password,
                           std::span<const std::uint8_t> new_password,
                           const KdfParams& new_params);

    [[nodiscard]] bool is_unlocked() const noexcept;

private:
    Vault();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace cypherarx
