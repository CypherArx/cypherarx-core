#pragma once

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cypherarx {

struct ImportedLogin {
    std::string_view name;
    std::string_view url;
    std::string_view username;
    std::string_view password;
    std::string_view totp;
    std::string_view notes;
};

enum class ImportError {
    NoHeader,
    NoSecretColumn,
    Malformed,
};

std::expected<std::vector<ImportedLogin>, ImportError> parse_logins_csv(std::span<char> data);

std::string_view import_site(std::string_view url);
std::string_view totp_secret(std::string_view value);

struct ImportOptions {
    std::string password_label = "Password";
    std::string totp_label = "TOTP";
    std::string password_type = "password";
    std::string totp_type = "totp";
};

struct ImportSummary {
    std::size_t services = 0;
    std::size_t accounts = 0;
    std::size_t fields = 0;
    std::size_t skipped_existing = 0;
    std::size_t skipped_empty = 0;

    bool operator==(const ImportSummary&) const = default;
};

}
