#include "cypherarx/totp.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

#include <sodium.h>

namespace cypherarx {

namespace {

// --- SHA-1 (libsodium has no SHA-1; TOTP defaults to HMAC-SHA-1) ---

class Sha1 {
public:
    Sha1() { reset(); }

    void reset() {
        h_[0] = 0x67452301;
        h_[1] = 0xEFCDAB89;
        h_[2] = 0x98BADCFE;
        h_[3] = 0x10325476;
        h_[4] = 0xC3D2E1F0;
        len_ = 0;
        buflen_ = 0;
    }

    void update(const std::uint8_t* p, std::size_t n) {
        len_ += n;
        while (n > 0) {
            const std::size_t take = std::min<std::size_t>(64 - buflen_, n);
            std::memcpy(buf_ + buflen_, p, take);
            buflen_ += take;
            p += take;
            n -= take;
            if (buflen_ == 64) {
                process(buf_);
                buflen_ = 0;
            }
        }
    }

    void finish(std::uint8_t out[20]) {
        const std::uint64_t bits = len_ * 8;
        const std::uint8_t one = 0x80;
        update(&one, 1);
        const std::uint8_t zero = 0;
        while (buflen_ != 56) {
            update(&zero, 1);
        }
        std::uint8_t lenb[8];
        for (int i = 0; i < 8; ++i) {
            lenb[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
        }
        update(lenb, 8);
        for (int i = 0; i < 5; ++i) {
            out[4 * i + 0] = static_cast<std::uint8_t>(h_[i] >> 24);
            out[4 * i + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
            out[4 * i + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
            out[4 * i + 3] = static_cast<std::uint8_t>(h_[i]);
        }
    }

private:
    static std::uint32_t rol(std::uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }

    void process(const std::uint8_t* p) {
        std::uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(p[4 * i]) << 24) |
                   (static_cast<std::uint32_t>(p[4 * i + 1]) << 16) |
                   (static_cast<std::uint32_t>(p[4 * i + 2]) << 8) |
                   static_cast<std::uint32_t>(p[4 * i + 3]);
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
        for (int i = 0; i < 80; ++i) {
            std::uint32_t f = 0, k = 0;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            const std::uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = t;
        }
        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
    }

    std::uint32_t h_[5];
    std::uint64_t len_;
    std::uint8_t buf_[64];
    std::size_t buflen_;
};

std::vector<std::uint8_t> hmac_sha1(std::span<const std::uint8_t> key,
                                    std::span<const std::uint8_t> msg) {
    std::uint8_t k0[64] = {0};
    if (key.size() > 64) {
        std::uint8_t kh[20];
        Sha1 s;
        s.update(key.data(), key.size());
        s.finish(kh);
        std::memcpy(k0, kh, 20);
    } else if (!key.empty()) {
        std::memcpy(k0, key.data(), key.size());
    }
    std::uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<std::uint8_t>(k0[i] ^ 0x36);
        opad[i] = static_cast<std::uint8_t>(k0[i] ^ 0x5C);
    }
    std::uint8_t inner[20];
    {
        Sha1 s;
        s.update(ipad, 64);
        s.update(msg.data(), msg.size());
        s.finish(inner);
    }
    std::uint8_t out[20];
    {
        Sha1 s;
        s.update(opad, 64);
        s.update(inner, 20);
        s.finish(out);
    }
    return std::vector<std::uint8_t>(out, out + 20);
}

std::vector<std::uint8_t> hmac_sha256(std::span<const std::uint8_t> key,
                                      std::span<const std::uint8_t> msg) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), key.size());
    crypto_auth_hmacsha256_update(&st, msg.data(), msg.size());
    std::vector<std::uint8_t> out(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_final(&st, out.data());
    return out;
}

std::vector<std::uint8_t> hmac_sha512(std::span<const std::uint8_t> key,
                                      std::span<const std::uint8_t> msg) {
    crypto_auth_hmacsha512_state st;
    crypto_auth_hmacsha512_init(&st, key.data(), key.size());
    crypto_auth_hmacsha512_update(&st, msg.data(), msg.size());
    std::vector<std::uint8_t> out(crypto_auth_hmacsha512_BYTES);
    crypto_auth_hmacsha512_final(&st, out.data());
    return out;
}

std::vector<std::uint8_t> hmac(TotpAlgorithm alg, std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t> msg) {
    switch (alg) {
        case TotpAlgorithm::Sha256: return hmac_sha256(key, msg);
        case TotpAlgorithm::Sha512: return hmac_sha512(key, msg);
        case TotpAlgorithm::Sha1:
        default:                    return hmac_sha1(key, msg);
    }
}

} // namespace

std::expected<std::vector<std::uint8_t>, TotpError> base32_decode(std::string_view text) {
    const auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a';
        if (c >= '2' && c <= '7') return c - '2' + 26;
        return -1;
    };

    std::vector<std::uint8_t> out;
    std::uint32_t buffer = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '=' || c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '-') {
            continue;
        }
        const int v = value(c);
        if (v < 0) {
            return std::unexpected(TotpError::InvalidSecret);
        }
        buffer = (buffer << 5) | static_cast<std::uint32_t>(v);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

std::expected<std::string, TotpError>
totp_at(std::span<const std::uint8_t> key, std::uint64_t unix_seconds, const TotpParams& params) {
    if (key.empty()) {
        return std::unexpected(TotpError::InvalidSecret);
    }
    if (params.digits < 1 || params.digits > 9 || params.period == 0) {
        return std::unexpected(TotpError::InvalidParams);
    }

    const std::uint64_t counter = unix_seconds / params.period;
    std::uint8_t msg[8];
    for (int i = 0; i < 8; ++i) {
        msg[i] = static_cast<std::uint8_t>(counter >> (56 - 8 * i));
    }

    const std::vector<std::uint8_t> mac = hmac(params.algorithm, key, {msg, 8});
    const std::size_t offset = mac.back() & 0x0F;
    const std::uint32_t binary =
        (static_cast<std::uint32_t>(mac[offset] & 0x7F) << 24) |
        (static_cast<std::uint32_t>(mac[offset + 1]) << 16) |
        (static_cast<std::uint32_t>(mac[offset + 2]) << 8) |
        static_cast<std::uint32_t>(mac[offset + 3]);

    std::uint32_t modulo = 1;
    for (std::uint32_t i = 0; i < params.digits; ++i) {
        modulo *= 10;
    }
    const std::uint32_t code = binary % modulo;

    std::string s = std::to_string(code);
    if (s.size() < params.digits) {
        s.insert(s.begin(), params.digits - s.size(), '0');
    }
    return s;
}

std::expected<std::string, TotpError>
totp_now(std::span<const std::uint8_t> key, const TotpParams& params) {
    using namespace std::chrono;
    const auto now = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    return totp_at(key, static_cast<std::uint64_t>(now), params);
}

std::uint32_t totp_seconds_remaining(std::uint64_t unix_seconds, std::uint32_t period) {
    if (period == 0) {
        return 0;
    }
    return period - static_cast<std::uint32_t>(unix_seconds % period);
}

} // namespace cypherarx
