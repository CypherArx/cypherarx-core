#include "cypherarx/import.hpp"

#include "cypherarx/entry.hpp"
#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"
#include "cypherarx/vault.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

std::vector<std::uint8_t> bytes(std::string_view s) {
    return {s.begin(), s.end()};
}

struct Parsed {
    std::string text;
    std::expected<std::vector<ImportedLogin>, ImportError> logins;

    explicit Parsed(std::string csv) : text(std::move(csv)), logins(parse_logins_csv(text)) {}
};

TEST(ImportCsv, ReadsABrowserExport) {
    const Parsed p("name,url,username,password,note\n"
                   "Example,https://example.com/login,user@example.com,pw1,first note\n"
                   "Other,https://other.example/,me,pw2,\n");
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 2u);
    const ImportedLogin& a = p.logins->front();
    EXPECT_EQ(a.name, "Example");
    EXPECT_EQ(a.url, "https://example.com/login");
    EXPECT_EQ(a.username, "user@example.com");
    EXPECT_EQ(a.password, "pw1");
    EXPECT_EQ(a.notes, "first note");
    EXPECT_TRUE(a.totp.empty());
    EXPECT_EQ(p.logins->back().password, "pw2");
    EXPECT_TRUE(p.logins->back().notes.empty());
}

TEST(ImportCsv, FindsColumnsByNameInAnyOrderAndCase) {
    const Parsed p("folder,favorite,type,Name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
                   "Work,,login,Example,n,,0,https://example.com,me,pw,JBSWY3DPEHPK3PXP\n");
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 1u);
    const ImportedLogin& a = p.logins->front();
    EXPECT_EQ(a.name, "Example");
    EXPECT_EQ(a.url, "https://example.com");
    EXPECT_EQ(a.username, "me");
    EXPECT_EQ(a.password, "pw");
    EXPECT_EQ(a.totp, "JBSWY3DPEHPK3PXP");
    EXPECT_EQ(a.notes, "n");
}

TEST(ImportCsv, UsesTheEmailWhenThereIsNoUsername) {
    const Parsed p("type,name,url,email,username,password\n"
                   "login,A,https://a.example,a@example.com,,pw\n"
                   "login,B,https://b.example,b@example.com,bee,pw\n");
    ASSERT_TRUE(p.logins.has_value());
    EXPECT_EQ(p.logins->at(0).username, "a@example.com");
    EXPECT_EQ(p.logins->at(1).username, "bee");
}

TEST(ImportCsv, HandlesQuotesCommasLineBreaksAndEscapedQuotes) {
    const Parsed p("\xEF\xBB\xBFname,url,username,password,note\r\n"
                   "\"Example, Inc.\",https://example.com,me,\"p\"\"w,1\",\"line one\nline two\"\r\n"
                   "\r\n"
                   "Last,https://last.example,me,pw,");
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 2u);
    EXPECT_EQ(p.logins->at(0).name, "Example, Inc.");
    EXPECT_EQ(p.logins->at(0).password, "p\"w,1");
    EXPECT_EQ(p.logins->at(0).notes, "line one\nline two");
    EXPECT_EQ(p.logins->at(1).name, "Last");
    EXPECT_EQ(p.logins->at(1).password, "pw");
}

TEST(ImportCsv, ShortRowsLeaveTheMissingColumnsEmpty) {
    const Parsed p("url,username,password\nhttps://example.com,me\n");
    ASSERT_TRUE(p.logins.has_value());
    ASSERT_EQ(p.logins->size(), 1u);
    EXPECT_EQ(p.logins->front().username, "me");
    EXPECT_TRUE(p.logins->front().password.empty());
}

TEST(ImportCsv, ReportsWhatIsWrongWithTheFile) {
    EXPECT_EQ(Parsed("").logins.error(), ImportError::NoHeader);
    EXPECT_EQ(Parsed("\n\n").logins.error(), ImportError::NoHeader);
    EXPECT_EQ(Parsed("name,url,username\nA,https://a.example,me\n").logins.error(),
              ImportError::NoSecretColumn);
    EXPECT_EQ(Parsed("name,password\n\"open,pw\n").logins.error(), ImportError::Malformed);
    EXPECT_EQ(Parsed("name,password\n\"a\"b,pw\n").logins.error(), ImportError::Malformed);
}

TEST(ImportCsv, HeaderOnlyGivesNoLogins) {
    const Parsed p("name,url,username,password\n");
    ASSERT_TRUE(p.logins.has_value());
    EXPECT_TRUE(p.logins->empty());
}

TEST(ImportSite, TakesTheHostOfAUrl) {
    EXPECT_EQ(import_site("https://example.com/login?x=1"), "example.com");
    EXPECT_EQ(import_site("https://example.com"), "example.com");
    EXPECT_EQ(import_site("http://example.com:8080/a"), "example.com");
    EXPECT_EQ(import_site("https://user:pw@example.com/a"), "example.com");
    EXPECT_EQ(import_site("example.com/path"), "example.com");
    EXPECT_EQ(import_site("android://hash==@com.example.app/"), "com.example.app");
    EXPECT_EQ(import_site("  https://example.com#top "), "example.com");
    EXPECT_EQ(import_site(""), "");
}

TEST(TotpSecret, TakesTheSecretOfAnOtpAuthUrl) {
    EXPECT_EQ(totp_secret("JBSWY3DPEHPK3PXP"), "JBSWY3DPEHPK3PXP");
    EXPECT_EQ(totp_secret(" JBSWY3DPEHPK3PXP "), "JBSWY3DPEHPK3PXP");
    EXPECT_EQ(totp_secret("otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example"),
              "JBSWY3DPEHPK3PXP");
    EXPECT_EQ(totp_secret("otpauth://totp/Example:me?issuer=Example&secret=ABC"), "ABC");
    EXPECT_EQ(totp_secret("OTPAUTH://totp/x?notsecret=1&secret=ABC"), "ABC");
    EXPECT_EQ(totp_secret("otpauth://totp/Example:me?issuer=Example"), "");
    EXPECT_EQ(totp_secret(""), "");
}

TEST(EmailShape, TellsAnAddressFromAPlainId) {
    EXPECT_TRUE(is_email_shaped("user@example.com"));
    EXPECT_TRUE(is_email_shaped("first.last+tag@mail.example.co.jp"));
    EXPECT_FALSE(is_email_shaped("user"));
    EXPECT_FALSE(is_email_shaped("@handle"));
    EXPECT_FALSE(is_email_shaped("user@"));
    EXPECT_FALSE(is_email_shaped("user@localhost"));
    EXPECT_FALSE(is_email_shaped("user@.com"));
    EXPECT_FALSE(is_email_shaped("user@example."));
    EXPECT_FALSE(is_email_shaped("user@example..com"));
    EXPECT_FALSE(is_email_shaped("a@b@example.com"));
    EXPECT_FALSE(is_email_shaped("user name@example.com"));
    EXPECT_FALSE(is_email_shaped("090-1234-5678"));
    EXPECT_FALSE(is_email_shaped(""));
}

class ImportVaultTest : public ::testing::Test {
protected:
    std::filesystem::path path_;
    std::optional<Vault> vault_;

    void SetUp() override {
        init_crypto();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                ("cypherarx_import_" + std::string(info->name()) + ".db");
        cleanup();
        auto v = Vault::create(path_, bytes("master-pass"), KdfParams::interactive());
        ASSERT_TRUE(v.has_value());
        vault_ = std::move(*v);
    }
    void TearDown() override {
        vault_.reset();
        cleanup();
    }
    void cleanup() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
        std::filesystem::remove(std::filesystem::path(path_) += "-wal", ec);
        std::filesystem::remove(std::filesystem::path(path_) += "-shm", ec);
        std::filesystem::remove(std::filesystem::path(path_) += "-journal", ec);
    }

    ImportSummary import(std::string csv) {
        const Parsed p(std::move(csv));
        EXPECT_TRUE(p.logins.has_value());
        const auto summary = vault_->import_logins(*p.logins);
        EXPECT_TRUE(summary.has_value());
        return summary.value_or(ImportSummary{});
    }

    std::vector<Entry> of_type(std::string_view type) {
        std::vector<Entry> out;
        for (Entry& e : vault_->list_entries().value()) {
            if (e.entry_type == type) {
                out.push_back(std::move(e));
            }
        }
        return out;
    }

    std::string value_of(const Field& field) {
        const Secret s = vault_->field_value(field.id).value();
        return std::string(s.bytes().begin(), s.bytes().end());
    }
};

TEST_F(ImportVaultTest, GroupsAccountsUnderOneServicePerSite) {
    const ImportSummary summary =
        import("name,url,username,password,note\n"
               "Example,https://example.com/login,first@example.com,pw1,note one\n"
               "Example again,https://EXAMPLE.com/other,second@example.com,pw2,\n"
               "Other,https://other.example,me,pw3,\n");
    EXPECT_EQ(summary, (ImportSummary{.services = 2, .accounts = 3, .fields = 6}));

    const std::vector<Entry> services = of_type("service");
    ASSERT_EQ(services.size(), 2u);
    EXPECT_EQ(services[0].label, "Example");
    EXPECT_EQ(services[0].url, "https://example.com/login");
    EXPECT_EQ(services[1].label, "Other");

    const std::vector<Entry> accounts = of_type("account");
    ASSERT_EQ(accounts.size(), 3u);
    EXPECT_EQ(accounts[0].parent_id, services[0].id);
    EXPECT_EQ(accounts[1].parent_id, services[0].id);
    EXPECT_EQ(accounts[2].parent_id, services[1].id);
    EXPECT_EQ(accounts[0].label, "first@example.com");
    EXPECT_EQ(accounts[0].notes, "note one");
    EXPECT_EQ(accounts[0].login_url, "https://example.com/login");

    const std::vector<Field> fields = vault_->list_fields(accounts[0].id).value();
    ASSERT_EQ(fields.size(), 2u);
    EXPECT_EQ(fields[0].label, "Email");
    EXPECT_EQ(fields[0].field_type, "text");
    EXPECT_EQ(value_of(fields[0]), "first@example.com");
    EXPECT_EQ(fields[1].label, "Password");
    EXPECT_EQ(fields[1].field_type, "password");
    EXPECT_EQ(value_of(fields[1]), "pw1");

    const std::vector<Field> plain = vault_->list_fields(accounts[2].id).value();
    ASSERT_EQ(plain.size(), 2u);
    EXPECT_EQ(plain[0].label, "ID");
    EXPECT_EQ(value_of(plain[0]), "me");
}

TEST_F(ImportVaultTest, StoresTheTotpSecretAsItsOwnField) {
    const ImportSummary summary =
        import("Title,URL,Username,Password,Notes,OTPAuth\n"
               "Example,https://example.com,me,pw,,otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example\n"
               "Code only,https://code.example,me,,,JBSWY3DPEHPK3PXP\n");
    EXPECT_EQ(summary, (ImportSummary{.services = 2, .accounts = 2, .fields = 5}));
    const std::vector<Entry> accounts = of_type("account");
    const std::vector<Field> fields = vault_->list_fields(accounts[0].id).value();
    ASSERT_EQ(fields.size(), 3u);
    EXPECT_EQ(fields[2].label, "TOTP");
    EXPECT_EQ(fields[2].field_type, "totp");
    EXPECT_EQ(value_of(fields[2]), "JBSWY3DPEHPK3PXP");
    const std::vector<Field> code_only = vault_->list_fields(accounts[1].id).value();
    ASSERT_EQ(code_only.size(), 2u);
    EXPECT_EQ(code_only[1].field_type, "totp");
}

TEST_F(ImportVaultTest, SkipsRowsWithNothingToStore) {
    const ImportSummary summary = import("name,url,username,password,note\n"
                                         "A note,,,,just text\n"
                                         "No secret,https://example.com,me,,\n"
                                         ",,me,pw,\n"
                                         "Kept,https://kept.example,me,pw,\n");
    EXPECT_EQ(summary, (ImportSummary{.services = 1, .accounts = 1, .fields = 2, .skipped_empty = 3}));
}

TEST_F(ImportVaultTest, ARowWithoutAUrlIsGroupedByItsName) {
    const ImportSummary summary = import("name,url,username,password\n"
                                         "Wi-Fi,,home,pw1\n"
                                         "wi-fi,,guest,pw2\n");
    EXPECT_EQ(summary, (ImportSummary{.services = 1, .accounts = 2, .fields = 4}));
    EXPECT_EQ(of_type("service").front().label, "Wi-Fi");
}

TEST_F(ImportVaultTest, ImportingTheSameFileAgainAddsNothing) {
    const std::string csv = "name,url,username,password\n"
                            "Example,https://example.com,me,pw\n"
                            "Example,https://example.com,other,pw\n";
    EXPECT_EQ(import(csv), (ImportSummary{.services = 1, .accounts = 2, .fields = 4}));
    EXPECT_EQ(import(csv), (ImportSummary{.skipped_existing = 2}));
    EXPECT_EQ(vault_->list_entries().value().size(), 3u);
}

TEST_F(ImportVaultTest, AddsToAServiceThatIsAlreadyThere) {
    Entry service;
    service.entry_type = "service";
    service.label = "My name for it";
    service.url = "https://example.com/";
    const Entry stored = vault_->add_entry(service).value();
    const ImportSummary summary = import("name,url,username,password\n"
                                         "Example,https://example.com/login,me,pw\n");
    EXPECT_EQ(summary, (ImportSummary{.accounts = 1, .fields = 2}));
    const std::vector<Entry> accounts = of_type("account");
    ASSERT_EQ(accounts.size(), 1u);
    EXPECT_EQ(accounts[0].parent_id, stored.id);
    EXPECT_EQ(of_type("service").front().label, "My name for it");
}

TEST_F(ImportVaultTest, ARowWithoutAUserNameGetsNoIdentifierField) {
    const ImportSummary summary = import("name,url,username,password\n"
                                         "Example,https://example.com,,pw\n");
    EXPECT_EQ(summary, (ImportSummary{.services = 1, .accounts = 1, .fields = 1}));
    const std::vector<Field> fields = vault_->list_fields(of_type("account").front().id).value();
    ASSERT_EQ(fields.size(), 1u);
    EXPECT_EQ(fields[0].label, "Password");
}

}
