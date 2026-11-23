#include "cypherarx/import.hpp"

#include <array>
#include <optional>

namespace cypherarx {

namespace {

enum class Role { name, url, username, email, password, totp, notes };

struct Alias {
    std::string_view header;
    Role role;
};

constexpr std::array kAliases{
    Alias{"name", Role::name},
    Alias{"title", Role::name},
    Alias{"url", Role::url},
    Alias{"uri", Role::url},
    Alias{"login_uri", Role::url},
    Alias{"website", Role::url},
    Alias{"username", Role::username},
    Alias{"login_username", Role::username},
    Alias{"login", Role::username},
    Alias{"email", Role::email},
    Alias{"password", Role::password},
    Alias{"login_password", Role::password},
    Alias{"totp", Role::totp},
    Alias{"login_totp", Role::totp},
    Alias{"otpauth", Role::totp},
    Alias{"otpsecret", Role::totp},
    Alias{"otpurl", Role::totp},
    Alias{"note", Role::notes},
    Alias{"notes", Role::notes},
    Alias{"extra", Role::notes},
    Alias{"comments", Role::notes},
};

constexpr char kQuote = '"';
constexpr char kComma = ',';
constexpr std::string_view kByteOrderMark = "\xEF\xBB\xBF";
constexpr std::string_view kBlanks = " \t";
constexpr std::string_view kWhitespace = " \t\r\n";
constexpr std::string_view kSchemeMark = "://";
constexpr std::string_view kAuthorityEnd = "/?#";
constexpr std::string_view kOtpAuthScheme = "otpauth://";
constexpr std::string_view kSecretParameter = "secret=";
constexpr std::string_view kParameterMarks = "?&";

char lower(char c) {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

bool equals_ignoring_case(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (lower(a[i]) != lower(b[i])) {
            return false;
        }
    }
    return true;
}

std::string_view trimmed(std::string_view s) {
    const auto first = s.find_first_not_of(kBlanks);
    if (first == std::string_view::npos) {
        return {};
    }
    return s.substr(first, s.find_last_not_of(kBlanks) - first + 1);
}

std::optional<Role> role_of(std::string_view header) {
    for (const Alias& alias : kAliases) {
        if (equals_ignoring_case(trimmed(header), alias.header)) {
            return alias.role;
        }
    }
    return std::nullopt;
}

struct Rows {
    std::vector<std::vector<std::string_view>> rows;
    bool malformed = false;
};

Rows split(std::span<char> data) {
    Rows out;
    char* const begin = data.data();
    char* const end = begin + data.size();
    char* read = begin;
    if (std::string_view(begin, data.size()).starts_with(kByteOrderMark)) {
        read += kByteOrderMark.size();
    }
    char* write = read;
    std::vector<std::string_view> row;
    while (read < end) {
        char* const field = write;
        if (*read == kQuote) {
            ++read;
            bool closed = false;
            while (read < end) {
                if (*read != kQuote) {
                    *write++ = *read++;
                } else if (read + 1 < end && read[1] == kQuote) {
                    *write++ = kQuote;
                    read += 2;
                } else {
                    ++read;
                    closed = true;
                    break;
                }
            }
            if (!closed || (read < end && *read != kComma && *read != '\r' && *read != '\n')) {
                out.malformed = true;
                return out;
            }
        } else {
            while (read < end && *read != kComma && *read != '\r' && *read != '\n') {
                *write++ = *read++;
            }
        }
        row.emplace_back(field, static_cast<std::size_t>(write - field));
        if (read < end && *read == kComma) {
            ++read;
            if (read == end) {
                row.emplace_back();
            } else {
                continue;
            }
        }
        if (read < end && *read == '\r') {
            ++read;
        }
        if (read < end && *read == '\n') {
            ++read;
        }
        if (row.size() > 1 || !row.front().empty()) {
            out.rows.push_back(std::move(row));
        }
        row.clear();
    }
    return out;
}

}

std::expected<std::vector<ImportedLogin>, ImportError> parse_logins_csv(std::span<char> data) {
    const Rows parsed = split(data);
    if (parsed.malformed) {
        return std::unexpected(ImportError::Malformed);
    }
    if (parsed.rows.empty()) {
        return std::unexpected(ImportError::NoHeader);
    }
    std::vector<std::optional<Role>> roles;
    bool has_secret = false;
    for (const std::string_view header : parsed.rows.front()) {
        roles.push_back(role_of(header));
        has_secret = has_secret || roles.back() == Role::password || roles.back() == Role::totp;
    }
    if (!has_secret) {
        return std::unexpected(ImportError::NoSecretColumn);
    }
    std::vector<ImportedLogin> logins;
    for (std::size_t r = 1; r < parsed.rows.size(); ++r) {
        const std::vector<std::string_view>& row = parsed.rows[r];
        ImportedLogin login;
        std::string_view email;
        for (std::size_t c = 0; c < row.size() && c < roles.size(); ++c) {
            if (!roles[c] || row[c].empty()) {
                continue;
            }
            switch (*roles[c]) {
            case Role::name:
                login.name = row[c];
                break;
            case Role::url:
                login.url = row[c];
                break;
            case Role::username:
                login.username = row[c];
                break;
            case Role::email:
                email = row[c];
                break;
            case Role::password:
                login.password = row[c];
                break;
            case Role::totp:
                login.totp = row[c];
                break;
            case Role::notes:
                login.notes = row[c];
                break;
            }
        }
        if (login.username.empty()) {
            login.username = email;
        }
        logins.push_back(login);
    }
    return logins;
}

std::string_view import_site(std::string_view url) {
    std::string_view rest = trimmed(url);
    if (const auto scheme = rest.find(kSchemeMark); scheme != std::string_view::npos) {
        rest.remove_prefix(scheme + kSchemeMark.size());
    }
    rest = rest.substr(0, rest.find_first_of(kAuthorityEnd));
    if (const auto user = rest.rfind('@'); user != std::string_view::npos) {
        rest.remove_prefix(user + 1);
    }
    return rest.substr(0, rest.find(':'));
}

bool is_email_shaped(std::string_view text) {
    const auto at = text.find('@');
    if (at == std::string_view::npos || at == 0 || text.find('@', at + 1) != std::string_view::npos) {
        return false;
    }
    if (text.find_first_of(kWhitespace) != std::string_view::npos) {
        return false;
    }
    const std::string_view domain = text.substr(at + 1);
    const auto dot = domain.find('.');
    return dot != std::string_view::npos && dot > 0 && domain.back() != '.' &&
           domain.find("..") == std::string_view::npos;
}

std::string import_origin(std::string_view url) {
    const std::string_view text = trimmed(url);
    const auto scheme = text.find(kSchemeMark);
    if (scheme == std::string_view::npos) {
        return std::string(import_site(text));
    }
    std::string_view authority = text.substr(scheme + kSchemeMark.size());
    authority = authority.substr(0, authority.find_first_of(kAuthorityEnd));
    if (const auto user = authority.rfind('@'); user != std::string_view::npos) {
        authority.remove_prefix(user + 1);
    }
    if (authority.empty()) {
        return {};
    }
    std::string out(text.substr(0, scheme + kSchemeMark.size()));
    out += authority;
    return out;
}

std::string_view totp_secret(std::string_view value) {
    const std::string_view text = trimmed(value);
    if (text.size() < kOtpAuthScheme.size() ||
        !equals_ignoring_case(text.substr(0, kOtpAuthScheme.size()), kOtpAuthScheme)) {
        return text;
    }
    std::size_t at = 0;
    while ((at = text.find(kSecretParameter, at)) != std::string_view::npos) {
        if (at > 0 && kParameterMarks.find(text[at - 1]) != std::string_view::npos) {
            const std::string_view secret = text.substr(at + kSecretParameter.size());
            return secret.substr(0, secret.find('&'));
        }
        at += kSecretParameter.size();
    }
    return {};
}

}
