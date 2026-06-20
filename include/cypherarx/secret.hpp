#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <span>

namespace cypherarx {

/// Initialize libsodium. Must be called once before any cryptographic use.
/// Idempotent and safe to call multiple times. Throws std::runtime_error on failure.
void init_crypto();

/// Owns a buffer of sensitive bytes in libsodium-guarded memory (locked against
/// swap, protected by guard pages, and zeroed on free). Non-copyable and move-only;
/// the contents are wiped on destruction.
///
/// The streaming operator never prints the contents, so accidentally logging a
/// Secret yields "[REDACTED]" instead of leaking the plaintext.
class Secret {
public:
    Secret() noexcept = default;

    /// Allocate `size` bytes of guarded memory (uninitialized). size == 0 allocates nothing.
    explicit Secret(std::size_t size);

    /// Allocate and copy `bytes` into guarded memory.
    explicit Secret(std::span<const std::uint8_t> bytes);

    ~Secret();

    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&& other) noexcept;
    Secret& operator=(Secret&& other) noexcept;

    [[nodiscard]] std::uint8_t* data() noexcept { return data_; }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

    [[nodiscard]] std::span<std::uint8_t> bytes() noexcept { return {data_, size_}; }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return {data_, size_}; }

    friend std::ostream& operator<<(std::ostream& os, const Secret&) {
        return os << "[REDACTED]";
    }

private:
    void reset() noexcept;

    std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

} // namespace cypherarx
