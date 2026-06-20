#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace cypherarx {

/// A vault entry (service / persona / account / child). Text columns that are encrypted at
/// rest are presented here already decrypted. Structural columns (entry_type) are plaintext.
struct Entry {
    std::int64_t id = 0;                     ///< 0 = not yet persisted.
    std::optional<std::int64_t> parent_id;   ///< Service-axis parent (an account's service; a child's account).
    std::optional<std::int64_t> persona_id;  ///< Persona-axis parent. An account = service x persona (§10.1.1).
    std::string entry_type;                  ///< "service"/"persona"/"account"/"child" (plaintext).
    std::string label;                      ///< Display name, e.g. a bank name.
    std::string url;
    std::string login_url;
    std::string display_name;
    std::string notes;
    std::string uuid;                       ///< Stable cross-device id (set on insert).
};

/// A free-form field of an entry. The secret `value` is NOT carried here; fetch it on demand
/// with `Vault::field_value()` so plaintext secrets are not materialized during listing.
struct Field {
    std::int64_t id = 0;
    std::int64_t entry_id = 0;
    std::string label;        ///< Decrypted label, e.g. "login ID".
    std::string field_type;   ///< "text"/"password"/"totp"/... (plaintext).
    std::string notes;
    std::string uuid;
};

/// How you log in to an entry. The reference-link layer of the model (§10.1.1): an entry may log
/// in via another entry (OAuth / "log in with GitHub"), recorded by `linked_entry_id`.
struct LoginMethod {
    std::int64_t id = 0;
    std::int64_t entry_id = 0;                        ///< The entry this login method belongs to.
    std::string method_type;                          ///< "email"/"google"/"github"/... (plaintext).
    std::optional<std::int64_t> linked_entry_id;      ///< The account you log in via (OAuth source).
    std::string notes;                                ///< Decrypted notes.
    std::string uuid;
};

} // namespace cypherarx
