#include "cypherarx/import.hpp"

#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>

#include <miniz.h>
#include <sodium.h>

namespace cypherarx {

namespace {

constexpr std::string_view kDataName = "export.data";

constexpr std::uint32_t kEndSignature = 0x06054b50;
constexpr std::uint32_t kCentralSignature = 0x02014b50;
constexpr std::uint32_t kLocalSignature = 0x04034b50;
constexpr std::size_t kEndSize = 22;
constexpr std::size_t kEndCommentMax = 0xFFFF;
constexpr std::size_t kEndEntries = 10;
constexpr std::size_t kEndDirectorySize = 12;
constexpr std::size_t kEndDirectoryOffset = 16;
constexpr std::size_t kCentralSize = 46;
constexpr std::size_t kCentralFlags = 8;
constexpr std::size_t kCentralMethod = 10;
constexpr std::size_t kCentralChecksum = 16;
constexpr std::size_t kCentralPacked = 20;
constexpr std::size_t kCentralUnpacked = 24;
constexpr std::size_t kCentralNameLength = 28;
constexpr std::size_t kCentralExtraLength = 30;
constexpr std::size_t kCentralCommentLength = 32;
constexpr std::size_t kCentralLocalOffset = 42;
constexpr std::size_t kLocalSize = 30;
constexpr std::size_t kLocalNameLength = 26;
constexpr std::size_t kLocalExtraLength = 28;
constexpr std::uint16_t kFlagEncrypted = 1;
constexpr std::uint16_t kMethodStored = 0;
constexpr std::uint16_t kMethodDeflated = 8;
constexpr std::uint32_t kWide32 = 0xFFFFFFFF;
constexpr std::uint16_t kWide16 = 0xFFFF;

constexpr std::size_t kMaxDepth = 64;
constexpr std::size_t kNone = std::numeric_limits<std::size_t>::max();
constexpr std::string_view kJsonSpace = " \t\r\n";
constexpr std::string_view kNumberCharacters = "+-0123456789.eE";
constexpr std::string_view kByteOrderMark = "\xEF\xBB\xBF";
constexpr std::uint32_t kHighSurrogateFirst = 0xD800;
constexpr std::uint32_t kHighSurrogateLast = 0xDBFF;
constexpr std::uint32_t kLowSurrogateFirst = 0xDC00;
constexpr std::uint32_t kLowSurrogateLast = 0xDFFF;
constexpr std::uint32_t kSupplementaryBase = 0x10000;

constexpr std::string_view kAccounts = "accounts";
constexpr std::string_view kVaults = "vaults";
constexpr std::string_view kItems = "items";
constexpr std::string_view kOverview = "overview";
constexpr std::string_view kTitle = "title";
constexpr std::string_view kUrl = "url";
constexpr std::string_view kUrls = "urls";
constexpr std::string_view kDetails = "details";
constexpr std::string_view kLoginFields = "loginFields";
constexpr std::string_view kDesignation = "designation";
constexpr std::string_view kDesignationUsername = "username";
constexpr std::string_view kDesignationPassword = "password";
constexpr std::string_view kFieldValue = "value";
constexpr std::string_view kPassword = "password";
constexpr std::string_view kNotes = "notesPlain";
constexpr std::string_view kSections = "sections";
constexpr std::string_view kFields = "fields";
constexpr std::string_view kTotp = "totp";

std::uint16_t read16(std::span<const char> data, std::size_t at) {
    const auto b = [&](std::size_t i) { return static_cast<std::uint16_t>(static_cast<unsigned char>(data[at + i])); };
    return static_cast<std::uint16_t>(b(0) | (b(1) << 8));
}

std::uint32_t read32(std::span<const char> data, std::size_t at) {
    const auto b = [&](std::size_t i) { return static_cast<std::uint32_t>(static_cast<unsigned char>(data[at + i])); };
    return b(0) | (b(1) << 8) | (b(2) << 16) | (b(3) << 24);
}

struct Member {
    std::uint16_t method = 0;
    std::uint32_t checksum = 0;
    std::size_t unpacked = 0;
    std::span<const char> packed;
};

std::expected<Member, ImportError> find_data(std::span<const char> archive) {
    if (archive.size() < kEndSize) {
        return std::unexpected(ImportError::Malformed);
    }
    std::size_t end = archive.size() - kEndSize;
    const std::size_t lowest = end > kEndCommentMax ? end - kEndCommentMax : 0;
    while (read32(archive, end) != kEndSignature) {
        if (end == lowest) {
            return std::unexpected(ImportError::Malformed);
        }
        --end;
    }
    const std::uint16_t entries = read16(archive, end + kEndEntries);
    const std::uint32_t directory_size = read32(archive, end + kEndDirectorySize);
    const std::uint32_t directory_offset = read32(archive, end + kEndDirectoryOffset);
    if (entries == kWide16 || directory_size == kWide32 || directory_offset == kWide32) {
        return std::unexpected(ImportError::Unsupported);
    }
    if (directory_offset > end || directory_size > end - directory_offset) {
        return std::unexpected(ImportError::Malformed);
    }
    std::size_t at = directory_offset;
    const std::size_t stop = at + directory_size;
    for (std::uint16_t i = 0; i < entries; ++i) {
        if (stop - at < kCentralSize || read32(archive, at) != kCentralSignature) {
            return std::unexpected(ImportError::Malformed);
        }
        const std::size_t name_length = read16(archive, at + kCentralNameLength);
        const std::size_t extra_length = read16(archive, at + kCentralExtraLength);
        const std::size_t comment_length = read16(archive, at + kCentralCommentLength);
        if (stop - at - kCentralSize < name_length + extra_length + comment_length) {
            return std::unexpected(ImportError::Malformed);
        }
        const std::string_view name(archive.data() + at + kCentralSize, name_length);
        if (name != kDataName) {
            at += kCentralSize + name_length + extra_length + comment_length;
            continue;
        }
        const std::uint32_t packed = read32(archive, at + kCentralPacked);
        const std::uint32_t unpacked = read32(archive, at + kCentralUnpacked);
        const std::uint32_t local = read32(archive, at + kCentralLocalOffset);
        if (packed == kWide32 || unpacked == kWide32 || local == kWide32 ||
            (read16(archive, at + kCentralFlags) & kFlagEncrypted) != 0) {
            return std::unexpected(ImportError::Unsupported);
        }
        Member member{.method = read16(archive, at + kCentralMethod),
                      .checksum = read32(archive, at + kCentralChecksum),
                      .unpacked = unpacked};
        if (member.method != kMethodStored && member.method != kMethodDeflated) {
            return std::unexpected(ImportError::Unsupported);
        }
        if (local > archive.size() || archive.size() - local < kLocalSize ||
            read32(archive, local) != kLocalSignature) {
            return std::unexpected(ImportError::Malformed);
        }
        const std::size_t skip = kLocalSize + read16(archive, local + kLocalNameLength) +
                                 read16(archive, local + kLocalExtraLength);
        if (archive.size() - local < skip || archive.size() - local - skip < packed) {
            return std::unexpected(ImportError::Malformed);
        }
        member.packed = archive.subspan(local + skip, packed);
        return member;
    }
    return std::unexpected(ImportError::Unsupported);
}

enum class Kind { null, boolean, number, string, array, object };

struct Node {
    Kind kind = Kind::null;
    std::string_view text;
    std::string_view key;
    std::size_t child = kNone;
    std::size_t next = kNone;
};

class Json {
public:
    Json(char* begin, char* end) : at_(begin), end_(end) {}

    std::optional<std::size_t> parse() {
        const auto root = value(0);
        skip_space();
        if (!root || at_ != end_) {
            return std::nullopt;
        }
        return root;
    }

    const Node& node(std::size_t index) const { return nodes_[index]; }

    std::size_t member(std::size_t object, std::string_view key) const {
        if (object == kNone || nodes_[object].kind != Kind::object) {
            return kNone;
        }
        for (std::size_t i = nodes_[object].child; i != kNone; i = nodes_[i].next) {
            if (nodes_[i].key == key) {
                return i;
            }
        }
        return kNone;
    }

    std::size_t first(std::size_t array) const {
        return array != kNone && nodes_[array].kind == Kind::array ? nodes_[array].child : kNone;
    }

    std::size_t next(std::size_t index) const { return nodes_[index].next; }

    std::string_view string(std::size_t index) const {
        return index != kNone && nodes_[index].kind == Kind::string ? nodes_[index].text : std::string_view();
    }

private:
    void skip_space() {
        while (at_ < end_ && kJsonSpace.find(*at_) != std::string_view::npos) {
            ++at_;
        }
    }

    bool take(char c) {
        skip_space();
        if (at_ < end_ && *at_ == c) {
            ++at_;
            return true;
        }
        return false;
    }

    bool literal(std::string_view word) {
        if (std::string_view(at_, static_cast<std::size_t>(end_ - at_)).starts_with(word)) {
            at_ += word.size();
            return true;
        }
        return false;
    }

    std::optional<std::uint32_t> hex4() {
        if (end_ - at_ < 4) {
            return std::nullopt;
        }
        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = *at_++;
            std::uint32_t digit = 0;
            if (c >= '0' && c <= '9') {
                digit = static_cast<std::uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                digit = static_cast<std::uint32_t>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                digit = static_cast<std::uint32_t>(c - 'A' + 10);
            } else {
                return std::nullopt;
            }
            value = value * 16 + digit;
        }
        return value;
    }

    static char* put(char* out, std::uint32_t c) {
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

    std::optional<std::string_view> quoted() {
        if (!take('"')) {
            return std::nullopt;
        }
        char* const begin = at_;
        char* out = at_;
        while (at_ < end_) {
            const char c = *at_++;
            if (c == '"') {
                return std::string_view(begin, static_cast<std::size_t>(out - begin));
            }
            if (static_cast<unsigned char>(c) < 0x20) {
                return std::nullopt;
            }
            if (c != '\\') {
                *out++ = c;
                continue;
            }
            if (at_ == end_) {
                return std::nullopt;
            }
            switch (*at_++) {
            case '"':
                *out++ = '"';
                break;
            case '\\':
                *out++ = '\\';
                break;
            case '/':
                *out++ = '/';
                break;
            case 'b':
                *out++ = '\b';
                break;
            case 'f':
                *out++ = '\f';
                break;
            case 'n':
                *out++ = '\n';
                break;
            case 'r':
                *out++ = '\r';
                break;
            case 't':
                *out++ = '\t';
                break;
            case 'u': {
                auto unit = hex4();
                if (!unit) {
                    return std::nullopt;
                }
                std::uint32_t c32 = *unit;
                if (c32 >= kHighSurrogateFirst && c32 <= kHighSurrogateLast) {
                    if (end_ - at_ < 2 || at_[0] != '\\' || at_[1] != 'u') {
                        return std::nullopt;
                    }
                    at_ += 2;
                    const auto low = hex4();
                    if (!low || *low < kLowSurrogateFirst || *low > kLowSurrogateLast) {
                        return std::nullopt;
                    }
                    c32 = kSupplementaryBase + ((c32 - kHighSurrogateFirst) << 10) + (*low - kLowSurrogateFirst);
                } else if (c32 >= kLowSurrogateFirst && c32 <= kLowSurrogateLast) {
                    return std::nullopt;
                }
                out = put(out, c32);
                break;
            }
            default:
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::optional<std::size_t> value(std::size_t depth) {
        if (depth > kMaxDepth) {
            return std::nullopt;
        }
        skip_space();
        if (at_ == end_) {
            return std::nullopt;
        }
        const std::size_t index = nodes_.size();
        nodes_.emplace_back();
        const char c = *at_;
        if (c == '"') {
            const auto text = quoted();
            if (!text) {
                return std::nullopt;
            }
            nodes_[index].kind = Kind::string;
            nodes_[index].text = *text;
            return index;
        }
        if (c == '{' || c == '[') {
            const bool object = c == '{';
            const char close = object ? '}' : ']';
            ++at_;
            nodes_[index].kind = object ? Kind::object : Kind::array;
            if (take(close)) {
                return index;
            }
            std::size_t last = kNone;
            while (true) {
                std::string_view key;
                if (object) {
                    const auto name = quoted();
                    if (!name || !take(':')) {
                        return std::nullopt;
                    }
                    key = *name;
                }
                const auto child = value(depth + 1);
                if (!child) {
                    return std::nullopt;
                }
                nodes_[*child].key = key;
                if (last == kNone) {
                    nodes_[index].child = *child;
                } else {
                    nodes_[last].next = *child;
                }
                last = *child;
                if (take(',')) {
                    continue;
                }
                if (take(close)) {
                    return index;
                }
                return std::nullopt;
            }
        }
        if (literal("true") || literal("false")) {
            nodes_[index].kind = Kind::boolean;
            return index;
        }
        if (literal("null")) {
            return index;
        }
        char* const begin = at_;
        while (at_ < end_ && kNumberCharacters.find(*at_) != std::string_view::npos) {
            ++at_;
        }
        if (at_ == begin) {
            return std::nullopt;
        }
        nodes_[index].kind = Kind::number;
        nodes_[index].text = std::string_view(begin, static_cast<std::size_t>(at_ - begin));
        return index;
    }

    char* at_;
    char* end_;
    std::vector<Node> nodes_;
};

ImportedLogin login_of(const Json& json, std::size_t item) {
    ImportedLogin login;
    const std::size_t overview = json.member(item, kOverview);
    login.name = json.string(json.member(overview, kTitle));
    login.url = json.string(json.member(overview, kUrl));
    for (std::size_t u = json.first(json.member(overview, kUrls)); u != kNone && login.url.empty(); u = json.next(u)) {
        login.url = json.string(json.member(u, kUrl));
    }
    const std::size_t details = json.member(item, kDetails);
    for (std::size_t f = json.first(json.member(details, kLoginFields)); f != kNone; f = json.next(f)) {
        const std::string_view designation = json.string(json.member(f, kDesignation));
        const std::string_view value = json.string(json.member(f, kFieldValue));
        if (designation == kDesignationUsername && login.username.empty()) {
            login.username = value;
        } else if (designation == kDesignationPassword && login.password.empty()) {
            login.password = value;
        }
    }
    if (login.password.empty()) {
        login.password = json.string(json.member(details, kPassword));
    }
    login.notes = json.string(json.member(details, kNotes));
    for (std::size_t s = json.first(json.member(details, kSections)); s != kNone; s = json.next(s)) {
        for (std::size_t f = json.first(json.member(s, kFields)); f != kNone && login.totp.empty(); f = json.next(f)) {
            login.totp = json.string(json.member(json.member(f, kFieldValue), kTotp));
        }
    }
    return login;
}

}

std::expected<std::size_t, ImportError> onepux_data_size(std::span<const char> archive) {
    const auto member = find_data(archive);
    if (!member) {
        return std::unexpected(member.error());
    }
    return member->unpacked;
}

std::expected<void, ImportError> onepux_extract_data(std::span<const char> archive, std::span<char> out) {
    const auto member = find_data(archive);
    if (!member) {
        return std::unexpected(member.error());
    }
    if (out.size() != member->unpacked) {
        return std::unexpected(ImportError::Malformed);
    }
    if (member->method == kMethodStored) {
        if (member->packed.size() != out.size()) {
            return std::unexpected(ImportError::Malformed);
        }
        if (!out.empty()) {
            std::memcpy(out.data(), member->packed.data(), out.size());
        }
    } else {
        tinfl_decompressor state;
        tinfl_init(&state);
        std::size_t in_size = member->packed.size();
        std::size_t out_size = out.size();
        auto* const target = reinterpret_cast<mz_uint8*>(out.data());
        const tinfl_status status =
            tinfl_decompress(&state, reinterpret_cast<const mz_uint8*>(member->packed.data()), &in_size, target,
                             target, &out_size, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
        sodium_memzero(&state, sizeof state);
        if (status != TINFL_STATUS_DONE || out_size != out.size()) {
            return std::unexpected(ImportError::Malformed);
        }
    }
    const mz_ulong checksum =
        mz_crc32(MZ_CRC32_INIT, reinterpret_cast<const unsigned char*>(out.data()), out.size());
    if (static_cast<std::uint32_t>(checksum) != member->checksum) {
        return std::unexpected(ImportError::Malformed);
    }
    return {};
}

std::expected<std::vector<ImportedLogin>, ImportError> parse_logins_onepux(std::span<char> data) {
    char* begin = data.data();
    char* const end = begin + data.size();
    if (std::string_view(begin, data.size()).starts_with(kByteOrderMark)) {
        begin += kByteOrderMark.size();
    }
    Json json(begin, end);
    const auto root = json.parse();
    if (!root) {
        return std::unexpected(ImportError::Malformed);
    }
    const std::size_t accounts = json.member(*root, kAccounts);
    if (accounts == kNone || json.node(accounts).kind != Kind::array) {
        return std::unexpected(ImportError::Unsupported);
    }
    std::vector<ImportedLogin> logins;
    for (std::size_t a = json.first(accounts); a != kNone; a = json.next(a)) {
        for (std::size_t v = json.first(json.member(a, kVaults)); v != kNone; v = json.next(v)) {
            for (std::size_t i = json.first(json.member(v, kItems)); i != kNone; i = json.next(i)) {
                logins.push_back(login_of(json, i));
            }
        }
    }
    return logins;
}

}
