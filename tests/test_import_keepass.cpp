#include "cypherarx/import.hpp"

#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

struct Parsed {
    std::string text;
    std::expected<std::vector<ImportedLogin>, ImportError> logins;

    explicit Parsed(std::string xml) : text(std::move(xml)), logins(parse_logins_keepass_xml(text)) {}
};

std::string field(std::string_view key, std::string_view value, std::string_view attributes = "") {
    std::string out = "<String><Key>";
    out += key;
    out += "</Key><Value";
    out += attributes;
    out += ">";
    out += value;
    out += "</Value></String>";
    return out;
}

std::string entry(std::string_view body) {
    std::string out = "<Entry><UUID>ZW50cnk=</UUID>";
    out += body;
    out += "</Entry>";
    return out;
}

std::string file(std::string_view groups, std::string_view meta = "") {
    std::string out = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\r\n<KeePassFile><Meta>";
    out += meta;
    out += "</Meta><Root><Group><UUID>cm9vdA==</UUID><Name>Root</Name>";
    out += groups;
    out += "</Group></Root></KeePassFile>";
    return out;
}

TEST(ImportKeePass, ReadsTheStandardStrings) {
    const Parsed p(file(entry(field("Notes", "first line\r\nsecond") + field("Password", "pw1", " ProtectInMemory=\"True\"") +
                              field("Title", "Example") + field("URL", "https://example.com/login") +
                              field("UserName", "user@example.com"))));
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 1u);
    const ImportedLogin& a = p.logins->front();
    EXPECT_EQ(a.name, "Example");
    EXPECT_EQ(a.url, "https://example.com/login");
    EXPECT_EQ(a.username, "user@example.com");
    EXPECT_EQ(a.password, "pw1");
    EXPECT_EQ(a.notes, "first line\nsecond");
    EXPECT_TRUE(a.totp.empty());
}

TEST(ImportKeePass, DecodesEntitiesAndCharacterData) {
    const Parsed p(file(entry(field("Password", "a&lt;b&gt;c&amp;d&quot;e&apos;f&#x3042;&#12356;") +
                              field("Title", "one <![CDATA[<two>]]> three"))));
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 1u);
    EXPECT_EQ(p.logins->front().password, "a<b>c&d\"e'f\xE3\x81\x82\xE3\x81\x84");
    EXPECT_EQ(p.logins->front().name, "one <two> three");
}

TEST(ImportKeePass, ReadsTheOneTimePasswordStrings) {
    const Parsed p(file(entry(field("Title", "A") + field("otp", "otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&amp;period=30")) +
                        entry(field("Title", "B") + field("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP")) +
                        entry(field("Title", "C") + field("TOTP Seed", "JBSWY3DPEHPK3PXP"))));
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 3u);
    EXPECT_EQ((*p.logins)[0].totp, "otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&period=30");
    EXPECT_EQ((*p.logins)[1].totp, "JBSWY3DPEHPK3PXP");
    EXPECT_EQ((*p.logins)[2].totp, "JBSWY3DPEHPK3PXP");
}

TEST(ImportKeePass, LeavesOutTheHistory) {
    const Parsed p(file(entry(field("Title", "Now") + field("Password", "new") + "<History>" +
                              entry(field("Title", "Before") + field("Password", "old")) + "</History>")));
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 1u);
    EXPECT_EQ(p.logins->front().name, "Now");
    EXPECT_EQ(p.logins->front().password, "new");
}

TEST(ImportKeePass, ReadsNestedGroupsAndLeavesOutTheRecycleBin) {
    const std::string groups = entry(field("Title", "Top")) + "<Group><UUID>aW5uZXI=</UUID><Name>Inner</Name>" +
                               entry(field("Title", "Inside")) + "</Group>" +
                               "<Group><UUID>YmluYmlu</UUID><Name>Recycle Bin</Name>" + entry(field("Title", "Deleted")) +
                               "<Group><UUID>ZGVlcA==</UUID>" + entry(field("Title", "Deeper")) + "</Group></Group>" +
                               entry(field("Title", "After"));
    const Parsed p(file(groups, "<RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>YmluYmlu</RecycleBinUUID>"));
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 3u);
    EXPECT_EQ((*p.logins)[0].name, "Top");
    EXPECT_EQ((*p.logins)[1].name, "Inside");
    EXPECT_EQ((*p.logins)[2].name, "After");

    const Parsed off(file(groups, "<RecycleBinEnabled>False</RecycleBinEnabled><RecycleBinUUID>YmluYmlu</RecycleBinUUID>"));
    ASSERT_TRUE(off.logins.has_value());
    EXPECT_EQ(off.logins->size(), 5u);
}

TEST(ImportKeePass, IgnoresUnknownStringsAndEmptyValues) {
    const Parsed p(file(entry(field("Title", "A") + field("Custom", "x") + "<String><Key>Password</Key><Value /></String>")));
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 1u);
    EXPECT_EQ(p.logins->front().name, "A");
    EXPECT_TRUE(p.logins->front().password.empty());
}

TEST(ImportKeePass, RefusesValuesThatAreStillEncrypted) {
    const Parsed p(file(entry(field("Title", "A") + field("Password", "AAAA", " Protected=\"True\""))));
    ASSERT_FALSE(p.logins.has_value());
    EXPECT_EQ(p.logins.error(), ImportError::Protected);
}

TEST(ImportKeePass, RefusesOtherDocuments) {
    EXPECT_EQ(Parsed("<html><body>x</body></html>").logins.error(), ImportError::Unsupported);
    EXPECT_EQ(Parsed("  \n").logins.error(), ImportError::Unsupported);
}

TEST(ImportKeePass, RefusesBrokenMarkup) {
    EXPECT_EQ(Parsed("<KeePassFile><Root></KeePassFile>").logins.error(), ImportError::Malformed);
    EXPECT_EQ(Parsed("<KeePassFile><Root>").logins.error(), ImportError::Malformed);
    EXPECT_EQ(Parsed(file(entry(field("Title", "a &unknown; b")))).logins.error(), ImportError::Malformed);
    EXPECT_EQ(Parsed(file(entry(field("Title", "a &#xD800; b")))).logins.error(), ImportError::Malformed);
    EXPECT_EQ(Parsed("<KeePassFile><Root><Group").logins.error(), ImportError::Malformed);
}

TEST(ImportFormat, IsToldFromTheFirstBytes) {
    const auto of = [](std::string_view s) { return import_format({s.data(), s.size()}); };
    EXPECT_EQ(of("PK\x03\x04rest"), ImportFormat::OnePux);
    EXPECT_EQ(of("\xEF\xBB\xBF\r\n <?xml version=\"1.0\"?>"), ImportFormat::KeePassXml);
    EXPECT_EQ(of("name,url,username,password\n"), ImportFormat::Csv);
    EXPECT_EQ(of(""), ImportFormat::Csv);
}

}
