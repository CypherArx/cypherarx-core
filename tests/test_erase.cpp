#include "cypherarx/erase.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

class EraseTest : public ::testing::Test {
protected:
    std::filesystem::path path_;

    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                (std::string("cypherarx_erase_") + info->name() + ".csv");
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    void write(const std::string& text) {
        std::ofstream out(path_, std::ios::binary);
        out << text;
    }

    std::string read() {
        std::ifstream in(path_, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
};

TEST_F(EraseTest, OverwritingKeepsTheSizeAndLeavesOnlyZeros) {
    const std::string text(200000, 'x');
    write(text);
    ASSERT_TRUE(overwrite_file(path_).has_value());
    const std::string now = read();
    EXPECT_EQ(now.size(), text.size());
    EXPECT_TRUE(std::ranges::all_of(now, [](char c) { return c == '\0'; }));
}

TEST_F(EraseTest, ErasingRemovesTheFile) {
    write("name,url,username,password\n");
    ASSERT_TRUE(erase_file(path_).has_value());
    EXPECT_FALSE(std::filesystem::exists(path_));
}

TEST_F(EraseTest, AnEmptyFileIsRemoved) {
    write("");
    ASSERT_TRUE(erase_file(path_).has_value());
    EXPECT_FALSE(std::filesystem::exists(path_));
}

TEST_F(EraseTest, AMissingFileIsRefused) {
    EXPECT_EQ(erase_file(path_).error(), EraseError::NotAFile);
}

TEST_F(EraseTest, ADirectoryIsRefusedAndKept) {
    std::filesystem::create_directory(path_);
    EXPECT_EQ(erase_file(path_).error(), EraseError::NotAFile);
    EXPECT_TRUE(std::filesystem::is_directory(path_));
}

}
