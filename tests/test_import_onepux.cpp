#include "cypherarx/import.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>
#include <miniz.h>

namespace {

using namespace cypherarx;

struct Parsed {
    std::string text;
    std::expected<std::vector<ImportedLogin>, ImportError> logins;

    explicit Parsed(std::string json) : text(std::move(json)), logins(parse_logins_onepux(text)) {}
};

std::string wrap(std::string_view items) {
    std::string out = R"({"accounts":[{"attrs":{"name":"Example"},"vaults":[{"attrs":{"name":"Private"},"items":[)";
    out += items;
    out += "]}]}]}";
    return out;
}

constexpr std::string_view kLogin = R"({
  "uuid": "aaaa", "favIndex": 1, "createdAt": 1614298956, "updatedAt": 1635346445,
  "state": "active", "categoryUuid": "001",
  "details": {
    "loginFields": [
      {"value": "user@example.com", "id": "", "name": "email", "fieldType": "E", "designation": "username"},
      {"value": "pw \"one\" あ😀", "id": "", "name": "password", "fieldType": "P", "designation": "password"},
      {"value": "other", "id": "", "name": "remember", "fieldType": "T", "designation": ""}
    ],
    "notesPlain": "first\nsecond",
    "sections": [
      {"title": "Security", "name": "Section_x", "fields": [
        {"title": "PIN", "id": "pin", "value": {"concealed": "12345"}, "indexAtSource": 0, "guarded": false},
        {"title": "one-time password", "id": "TOTP_x", "value": {"totp": "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP"}}
      ]}
    ],
    "passwordHistory": [{"value": "12345password", "time": 1458322355}]
  },
  "overview": {"subtitle": "", "urls": [{"label": "", "url": "https://example.com/login"}],
               "title": "Example", "url": "https://example.com/login", "ps": 100, "pbe": 86.1, "pgrng": true}
})";

TEST(ImportOnePux, ReadsALogin) {
    const Parsed p(wrap(kLogin));
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 1u);
    const ImportedLogin& a = p.logins->front();
    EXPECT_EQ(a.name, "Example");
    EXPECT_EQ(a.url, "https://example.com/login");
    EXPECT_EQ(a.username, "user@example.com");
    EXPECT_EQ(a.password, "pw \"one\" \xE3\x81\x82\xF0\x9F\x98\x80");
    EXPECT_EQ(a.notes, "first\nsecond");
    EXPECT_EQ(a.totp, "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP");
}

TEST(ImportOnePux, ReadsAPasswordItemAndTheFirstOfTheUrls) {
    const Parsed p(wrap(R"({"categoryUuid":"005","details":{"password":"only","loginFields":[],"sections":[]},)"
                        R"("overview":{"title":"Wi-Fi","url":"","urls":[{"label":"","url":""},{"label":"","url":"https://example.org/"}]}},)"
                        R"({"categoryUuid":"003","details":{"notesPlain":"a note"},"overview":{"title":"Note"}})"));
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 2u);
    EXPECT_EQ((*p.logins)[0].name, "Wi-Fi");
    EXPECT_EQ((*p.logins)[0].password, "only");
    EXPECT_EQ((*p.logins)[0].url, "https://example.org/");
    EXPECT_EQ((*p.logins)[1].name, "Note");
    EXPECT_TRUE((*p.logins)[1].password.empty());
    EXPECT_EQ((*p.logins)[1].notes, "a note");
}

TEST(ImportOnePux, ReadsEveryAccountAndVault) {
    const Parsed p(R"({"accounts":[{"vaults":[{"items":[{"overview":{"title":"A"}}]},{"items":[{"overview":{"title":"B"}}]}]},)"
                   R"({"vaults":[{"items":[]},{"items":[{"overview":{"title":"C"}}]}]}]})");
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 3u);
    EXPECT_EQ((*p.logins)[2].name, "C");
}

TEST(ImportOnePux, RefusesOtherAndBrokenDocuments) {
    EXPECT_EQ(Parsed(R"({"items":[]})").logins.error(), ImportError::Unsupported);
    EXPECT_EQ(Parsed(R"([1,2,3])").logins.error(), ImportError::Unsupported);
    EXPECT_EQ(Parsed(R"({"accounts":[)").logins.error(), ImportError::Malformed);
    EXPECT_EQ(Parsed(R"({"accounts":[]} x)").logins.error(), ImportError::Malformed);
    const std::string open = "{\"accounts\":[],\"a\":\"";
    const std::string lone_surrogate = open + '\\' + "ud83d\"}";
    const std::string unknown_escape = open + '\\' + "q\"}";
    EXPECT_EQ(Parsed(lone_surrogate).logins.error(), ImportError::Malformed);
    EXPECT_EQ(Parsed(unknown_escape).logins.error(), ImportError::Malformed);
    EXPECT_EQ(Parsed(std::string(100, '[')).logins.error(), ImportError::Malformed);
}

void put16(std::string& out, std::uint32_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
}

void put32(std::string& out, std::uint32_t v) {
    put16(out, v & 0xFFFF);
    put16(out, v >> 16);
}

struct File {
    std::string name;
    std::string data;
    bool deflate = false;
};

std::string archive(const std::vector<File>& files, std::uint32_t checksum_xor = 0) {
    std::string out;
    std::string directory;
    for (const File& f : files) {
        std::string packed = f.data;
        if (f.deflate) {
            packed.assign(f.data.size() + 64, '\0');
            const std::size_t n = tdefl_compress_mem_to_mem(packed.data(), packed.size(), f.data.data(),
                                                            f.data.size(), TDEFL_DEFAULT_MAX_PROBES);
            packed.resize(n);
        }
        const auto crc = static_cast<std::uint32_t>(mz_crc32(
                             MZ_CRC32_INIT, reinterpret_cast<const unsigned char*>(f.data.data()), f.data.size())) ^
                         checksum_xor;
        const auto offset = static_cast<std::uint32_t>(out.size());
        const std::uint32_t method = f.deflate ? 8 : 0;
        put32(out, 0x04034b50);
        put16(out, 20);
        put16(out, 0);
        put16(out, method);
        put32(out, 0);
        put32(out, crc);
        put32(out, static_cast<std::uint32_t>(packed.size()));
        put32(out, static_cast<std::uint32_t>(f.data.size()));
        put16(out, static_cast<std::uint32_t>(f.name.size()));
        put16(out, 0);
        out += f.name;
        out += packed;
        put32(directory, 0x02014b50);
        put16(directory, 20);
        put16(directory, 20);
        put16(directory, 0);
        put16(directory, method);
        put32(directory, 0);
        put32(directory, crc);
        put32(directory, static_cast<std::uint32_t>(packed.size()));
        put32(directory, static_cast<std::uint32_t>(f.data.size()));
        put16(directory, static_cast<std::uint32_t>(f.name.size()));
        put16(directory, 0);
        put16(directory, 0);
        put16(directory, 0);
        put16(directory, 0);
        put32(directory, 0);
        put32(directory, offset);
        directory += f.name;
    }
    const auto directory_offset = static_cast<std::uint32_t>(out.size());
    out += directory;
    put32(out, 0x06054b50);
    put16(out, 0);
    put16(out, 0);
    put16(out, static_cast<std::uint32_t>(files.size()));
    put16(out, static_cast<std::uint32_t>(files.size()));
    put32(out, static_cast<std::uint32_t>(directory.size()));
    put32(out, directory_offset);
    put16(out, 0);
    return out;
}

std::expected<std::string, ImportError> extract(const std::string& zip) {
    const auto size = onepux_data_size(zip);
    if (!size) {
        return std::unexpected(size.error());
    }
    std::string out(*size, '\0');
    const auto done = onepux_extract_data(zip, out);
    if (!done) {
        return std::unexpected(done.error());
    }
    return out;
}

TEST(ImportOnePuxArchive, ExtractsStoredAndDeflatedData) {
    const std::string json = wrap(kLogin);
    for (const bool deflate : {false, true}) {
        const std::string zip = archive({{"export.attributes", R"({"version":3})", deflate},
                                         {"export.data", json, deflate},
                                         {"files/x", "binary", false}});
        EXPECT_EQ(import_format(zip), ImportFormat::OnePux);
        const auto out = extract(zip);
        ASSERT_TRUE(out.has_value());
        EXPECT_EQ(*out, json);
        Parsed p(*out);
        ASSERT_TRUE(p.logins.has_value());
        EXPECT_EQ(p.logins->size(), 1u);
    }
}

TEST(ImportOnePuxArchive, RefusesAnArchiveWithoutTheData) {
    EXPECT_EQ(extract(archive({{"other.txt", "x", false}})).error(), ImportError::Unsupported);
    EXPECT_EQ(extract(archive({})).error(), ImportError::Unsupported);
}

TEST(ImportOnePuxArchive, RefusesDamagedArchives) {
    const std::string json = wrap(kLogin);
    EXPECT_EQ(extract("PK\x03\x04 not an archive at all").error(), ImportError::Malformed);
    EXPECT_EQ(extract("PK").error(), ImportError::Malformed);
    EXPECT_EQ(extract(archive({{"export.data", json, true}}, 1)).error(), ImportError::Malformed);

    std::string cut = archive({{"export.data", json, true}});
    cut[60] = static_cast<char>(cut[60] ^ 0x55);
    cut[61] = static_cast<char>(cut[61] ^ 0x55);
    EXPECT_FALSE(extract(cut).has_value());

    const std::string zip = archive({{"export.data", json, true}});
    std::string small(json.size() - 1, '\0');
    EXPECT_EQ(onepux_extract_data(zip, small).error(), ImportError::Malformed);
}

}
