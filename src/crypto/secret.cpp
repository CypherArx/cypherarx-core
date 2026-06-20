#include "cypherarx/secret.hpp"

#include <cstring>
#include <new>
#include <stdexcept>

#include <sodium.h>

namespace cypherarx {

void init_crypto() {
    // sodium_init() returns 0 on success, 1 if already initialized, -1 on failure.
    if (sodium_init() < 0) {
        throw std::runtime_error("cypherarx: libsodium initialization failed");
    }
}

Secret::Secret(std::size_t size) : size_(size) {
    if (size_ == 0) {
        return;
    }
    // sodium_malloc returns locked, guard-paged memory that is zeroed by sodium_free.
    data_ = static_cast<std::uint8_t*>(sodium_malloc(size_));
    if (data_ == nullptr) {
        size_ = 0;
        throw std::bad_alloc();
    }
}

Secret::Secret(std::span<const std::uint8_t> bytes) : Secret(bytes.size()) {
    if (!bytes.empty()) {
        std::memcpy(data_, bytes.data(), bytes.size());
    }
}

Secret::~Secret() { reset(); }

Secret::Secret(Secret&& other) noexcept : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

Secret& Secret::operator=(Secret&& other) noexcept {
    if (this != &other) {
        reset();
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void Secret::reset() noexcept {
    if (data_ != nullptr) {
        sodium_free(data_); // zeroes the memory before releasing it
        data_ = nullptr;
    }
    size_ = 0;
}

} // namespace cypherarx
