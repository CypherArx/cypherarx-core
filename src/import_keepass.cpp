#include "cypherarx/import.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>

namespace cypherarx {

namespace {

constexpr std::size_t kMaxDepth = 256;
constexpr std::string_view kByteOrderMark = "\xEF\xBB\xBF";
constexpr std::string_view kSpace = " \t\r\n";
constexpr std::string_view kCommentOpen = "<!--";
constexpr std::string_view kCommentClose = "-->";
constexpr std::string_view kCdataOpen = "<![CDATA[";
constexpr std::string_view kCdataClose = "]]>";
constexpr std::string_view kInstructionOpen = "<?";
constexpr std::string_view kInstructionClose = "?>";
constexpr std::string_view kDeclarationOpen = "<!";
constexpr std::string_view kCloseOpen = "</";

constexpr std::string_view kRoot = "KeePassFile";
constexpr std::string_view kMeta = "Meta";
constexpr std::string_view kRecycleBinEnabled = "RecycleBinEnabled";
constexpr std::string_view kRecycleBinUuid = "RecycleBinUUID";
constexpr std::string_view kGroup = "Group";
constexpr std::string_view kUuid = "UUID";
constexpr std::string_view kEntry = "Entry";
constexpr std::string_view kHistory = "History";
constexpr std::string_view kString = "String";
constexpr std::string_view kKey = "Key";
constexpr std::string_view kValue = "Value";
constexpr std::string_view kProtected = "Protected";
constexpr std::string_view kTrue = "True";
constexpr std::string_view kFalse = "False";

enum class Slot { name, username, password, url, notes, totp };

struct KeyName {
    std::string_view key;
    Slot slot;
};

constexpr std::array kKeys{
    KeyName{"Title", Slot::name},
    KeyName{"UserName", Slot::username},
    KeyName{"Password", Slot::password},
    KeyName{"URL", Slot::url},
    KeyName{"Notes", Slot::notes},
    KeyName{"otp", Slot::totp},
    KeyName{"TimeOtp-Secret-Base32", Slot::totp},
    KeyName{"TOTP Seed", Slot::totp},
};

struct Entity {
    std::string_view name;
    char value;
};

constexpr std::array kEntities{
    Entity{"lt", '<'}, Entity{"gt", '>'}, Entity{"amp", '&'}, Entity{"quot", '"'}, Entity{"apos", '\''},
};

constexpr std::uint32_t kMaxCodePoint = 0x10FFFF;
constexpr std::uint32_t kSurrogateFirst = 0xD800;
constexpr std::uint32_t kSurrogateLast = 0xDFFF;

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

char* put_code_point(char* out, std::uint32_t c) {
    if (c < 0x80) {
        *out++ = static_cast<char>(c);
    } else if (c < 0x800) {
        *out++ = static_cast<char>(0xC0 | (c >> 6));
        *out++ = static_cast<char>(0x80 | (c & 0x3F));
    } else if (c < 0x10000) {
        *out++ = static_cast<char>(0xE0 | (c >> 12));
        *out++ = static_cast<char>(0x80 | ((c >> 6) & 0x3F));
        *out++ = static_cast<char>(0x80 | (c & 0x3F));
    } else {
        *out++ = static_cast<char>(0xF0 | (c >> 18));
        *out++ = static_cast<char>(0x80 | ((c >> 12) & 0x3F));
        *out++ = static_cast<char>(0x80 | ((c >> 6) & 0x3F));
        *out++ = static_cast<char>(0x80 | (c & 0x3F));
    }
    return out;
}

std::optional<std::uint32_t> code_point(std::string_view reference) {
    int base = 10;
    if (!reference.empty() && (reference.front() == 'x' || reference.front() == 'X')) {
        base = 16;
        reference.remove_prefix(1);
    }
    if (reference.empty()) {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (const char c : reference) {
        int digit = -1;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (base == 16 && lower(c) >= 'a' && lower(c) <= 'f') {
            digit = lower(c) - 'a' + 10;
        }
        if (digit < 0) {
            return std::nullopt;
        }
        value = value * static_cast<std::uint32_t>(base) + static_cast<std::uint32_t>(digit);
        if (value > kMaxCodePoint) {
            return std::nullopt;
        }
    }
    if (value == 0 || (value >= kSurrogateFirst && value <= kSurrogateLast)) {
        return std::nullopt;
    }
    return value;
}

std::optional<std::size_t> decode(char* begin, char* end) {
    char* out = begin;
    for (char* read = begin; read < end;) {
        if (*read == '\r') {
            *out++ = '\n';
            ++read;
            if (read < end && *read == '\n') {
                ++read;
            }
        } else if (*read != '&') {
            *out++ = *read++;
        } else {
            const std::string_view rest(read + 1, static_cast<std::size_t>(end - read - 1));
            const auto stop = rest.find(';');
            if (stop == std::string_view::npos) {
                return std::nullopt;
            }
            const std::string_view name = rest.substr(0, stop);
            if (!name.empty() && name.front() == '#') {
                const auto c = code_point(name.substr(1));
                if (!c) {
                    return std::nullopt;
                }
                out = put_code_point(out, *c);
            } else {
                bool known = false;
                for (const Entity& entity : kEntities) {
                    if (name == entity.name) {
                        *out++ = entity.value;
                        known = true;
                        break;
                    }
                }
                if (!known) {
                    return std::nullopt;
                }
            }
            read += stop + 2;
        }
    }
    return static_cast<std::size_t>(out - begin);
}

std::optional<std::string_view> attribute(std::string_view attributes, std::string_view wanted) {
    std::size_t at = 0;
    while (true) {
        at = attributes.find_first_not_of(kSpace, at);
        if (at == std::string_view::npos) {
            return std::nullopt;
        }
        const auto name_end = attributes.find_first_of("= \t\r\n", at);
        if (name_end == std::string_view::npos) {
            return std::nullopt;
        }
        const std::string_view name = attributes.substr(at, name_end - at);
        at = attributes.find_first_not_of(kSpace, name_end);
        if (at == std::string_view::npos || attributes[at] != '=') {
            return std::nullopt;
        }
        at = attributes.find_first_not_of(kSpace, at + 1);
        if (at == std::string_view::npos || (attributes[at] != '"' && attributes[at] != '\'')) {
            return std::nullopt;
        }
        const auto close = attributes.find(attributes[at], at + 1);
        if (close == std::string_view::npos) {
            return std::nullopt;
        }
        if (name == wanted) {
            return attributes.substr(at + 1, close - at - 1);
        }
        at = close + 1;
    }
}

enum class Token { open, close, text, end, error };

struct Markup {
    Token kind = Token::error;
    std::string_view name;
    std::string_view attributes;
    char* text = nullptr;
    std::size_t size = 0;
    bool self_closing = false;
};

class Reader {
public:
    Reader(char* begin, char* end) : at_(begin), end_(end) {}

    Markup next() {
        while (at_ < end_) {
            if (*at_ != '<') {
                char* const begin = at_;
                while (at_ < end_ && *at_ != '<') {
                    ++at_;
                }
                const auto size = decode(begin, at_);
                if (!size) {
                    return {};
                }
                return {.kind = Token::text, .text = begin, .size = *size};
            }
            const std::string_view rest(at_, static_cast<std::size_t>(end_ - at_));
            if (rest.starts_with(kCommentOpen)) {
                if (!skip_past(kCommentClose, kCommentOpen.size())) {
                    return {};
                }
            } else if (rest.starts_with(kCdataOpen)) {
                const auto close = rest.find(kCdataClose, kCdataOpen.size());
                if (close == std::string_view::npos) {
                    return {};
                }
                char* const begin = at_ + kCdataOpen.size();
                at_ += close + kCdataClose.size();
                return {.kind = Token::text, .text = begin, .size = close - kCdataOpen.size()};
            } else if (rest.starts_with(kInstructionOpen)) {
                if (!skip_past(kInstructionClose, kInstructionOpen.size())) {
                    return {};
                }
            } else if (rest.starts_with(kDeclarationOpen)) {
                if (!skip_past(">", kDeclarationOpen.size())) {
                    return {};
                }
            } else if (rest.starts_with(kCloseOpen)) {
                const auto close = rest.find('>');
                if (close == std::string_view::npos) {
                    return {};
                }
                std::string_view name = rest.substr(kCloseOpen.size(), close - kCloseOpen.size());
                name = name.substr(0, name.find_first_of(kSpace));
                at_ += close + 1;
                if (name.empty()) {
                    return {};
                }
                return {.kind = Token::close, .name = name};
            } else {
                return open(rest);
            }
        }
        return {.kind = Token::end};
    }

private:
    bool skip_past(std::string_view mark, std::size_t from) {
        const std::string_view rest(at_, static_cast<std::size_t>(end_ - at_));
        const auto close = rest.find(mark, from);
        if (close == std::string_view::npos) {
            return false;
        }
        at_ += close + mark.size();
        return true;
    }

    Markup open(std::string_view rest) {
        std::size_t close = 1;
        char quote = 0;
        for (; close < rest.size(); ++close) {
            const char c = rest[close];
            if (quote != 0) {
                if (c == quote) {
                    quote = 0;
                }
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '>') {
                break;
            } else if (c == '<') {
                return {};
            }
        }
        if (close == rest.size()) {
            return {};
        }
        std::string_view inside = rest.substr(1, close - 1);
        Markup markup{.kind = Token::open};
        if (!inside.empty() && inside.back() == '/') {
            markup.self_closing = true;
            inside.remove_suffix(1);
        }
        const auto name_end = inside.find_first_of(kSpace);
        markup.name = inside.substr(0, name_end);
        if (name_end != std::string_view::npos) {
            markup.attributes = inside.substr(name_end);
        }
        at_ += close + 1;
        if (markup.name.empty()) {
            return {};
        }
        return markup;
    }

    char* at_;
    char* end_;
};

struct Text {
    char* begin = nullptr;
    std::size_t size = 0;

    void append(char* piece, std::size_t n) {
        if (!begin) {
            begin = piece;
            size = n;
            return;
        }
        std::memmove(begin + size, piece, n);
        size += n;
    }

    std::string_view view() const { return begin ? std::string_view(begin, size) : std::string_view(); }
};

void assign(ImportedLogin& login, std::string_view key, std::string_view value) {
    for (const KeyName& known : kKeys) {
        if (key != known.key) {
            continue;
        }
        switch (known.slot) {
        case Slot::name:
            login.name = value;
            break;
        case Slot::username:
            login.username = value;
            break;
        case Slot::password:
            login.password = value;
            break;
        case Slot::url:
            login.url = value;
            break;
        case Slot::notes:
            login.notes = value;
            break;
        case Slot::totp:
            if (login.totp.empty()) {
                login.totp = value;
            }
            break;
        }
        return;
    }
}

}

std::expected<std::vector<ImportedLogin>, ImportError> parse_logins_keepass_xml(std::span<char> data) {
    char* begin = data.data();
    char* const end = begin + data.size();
    if (std::string_view(begin, data.size()).starts_with(kByteOrderMark)) {
        begin += kByteOrderMark.size();
    }
    Reader reader(begin, end);
    std::vector<ImportedLogin> logins;
    std::vector<std::string_view> path;
    std::vector<bool> skipped;
    std::string_view recycle_bin;
    bool recycle_enabled = true;
    bool seen_root = false;
    int history = 0;
    std::optional<ImportedLogin> current;
    std::size_t entry_level = 0;
    std::string_view key;
    std::string_view value;
    bool collecting = false;
    bool protected_value = false;
    Text text;

    const auto parent_is = [&](std::string_view name) {
        return path.size() >= 2 && path[path.size() - 2] == name;
    };
    const auto in_entry_string = [&] {
        return current && history == 0 && path.size() == entry_level + 2 && parent_is(kString);
    };

    const auto close = [&](std::string_view name) -> std::optional<ImportError> {
        if (path.empty() || path.back() != name) {
            return ImportError::Malformed;
        }
        if (collecting) {
            if (name == kKey) {
                key = text.view();
            } else if (name == kValue) {
                value = text.view();
                if (protected_value && !value.empty()) {
                    return ImportError::Protected;
                }
            } else if (name == kRecycleBinUuid) {
                recycle_bin = text.view();
            } else if (name == kRecycleBinEnabled) {
                recycle_enabled = !equals_ignoring_case(text.view(), kFalse);
            } else if (name == kUuid) {
                if (recycle_enabled && !recycle_bin.empty() && text.view() == recycle_bin && !skipped.empty()) {
                    skipped.back() = true;
                }
            }
        } else if (name == kString) {
            if (current && history == 0 && path.size() == entry_level + 1) {
                assign(*current, key, value);
            }
        } else if (name == kHistory) {
            --history;
        } else if (name == kEntry) {
            if (current && history == 0 && path.size() == entry_level) {
                if (skipped.empty() || !skipped.back()) {
                    logins.push_back(*current);
                }
                current.reset();
            }
        } else if (name == kGroup) {
            skipped.pop_back();
        }
        path.pop_back();
        collecting = false;
        return std::nullopt;
    };

    while (true) {
        const Markup markup = reader.next();
        switch (markup.kind) {
        case Token::error:
            return std::unexpected(ImportError::Malformed);
        case Token::end:
            if (!path.empty()) {
                return std::unexpected(ImportError::Malformed);
            }
            if (!seen_root) {
                return std::unexpected(ImportError::Unsupported);
            }
            return logins;
        case Token::text:
            if (collecting) {
                text.append(markup.text, markup.size);
            }
            break;
        case Token::open: {
            if (path.empty()) {
                if (seen_root) {
                    return std::unexpected(ImportError::Malformed);
                }
                if (markup.name != kRoot) {
                    return std::unexpected(ImportError::Unsupported);
                }
                seen_root = true;
            }
            if (path.size() >= kMaxDepth) {
                return std::unexpected(ImportError::Malformed);
            }
            path.push_back(markup.name);
            collecting = false;
            if (markup.name == kGroup) {
                skipped.push_back(!skipped.empty() && skipped.back());
            } else if (markup.name == kHistory) {
                ++history;
            } else if (markup.name == kEntry) {
                if (!current && history == 0) {
                    current.emplace();
                    entry_level = path.size();
                }
            } else if (markup.name == kString) {
                if (current && history == 0 && path.size() == entry_level + 1) {
                    key = {};
                    value = {};
                }
            } else if (markup.name == kKey || markup.name == kValue) {
                collecting = in_entry_string();
            } else if (markup.name == kUuid) {
                collecting = parent_is(kGroup);
            } else if (markup.name == kRecycleBinUuid || markup.name == kRecycleBinEnabled) {
                collecting = parent_is(kMeta);
            }
            if (collecting) {
                text = {};
                const auto flag = attribute(markup.attributes, kProtected);
                protected_value = markup.name == kValue && flag && equals_ignoring_case(*flag, kTrue);
            }
            if (markup.self_closing) {
                if (const auto error = close(markup.name)) {
                    return std::unexpected(*error);
                }
            }
            break;
        }
        case Token::close:
            if (const auto error = close(markup.name)) {
                return std::unexpected(*error);
            }
            break;
        }
    }
}

}
