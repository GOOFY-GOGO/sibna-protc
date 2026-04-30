#include "sibna/safety_number.hpp"
#include "sibna/crypto.hpp"
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

namespace sibna {

// ── SafetyNumber ─────────────────────────────────────────────────────────────

Result<SafetyNumber> SafetyNumber::calculate(
    const std::array<byte, 32>& our_identity,
    const std::array<byte, 32>& their_identity
) {
    // Sort keys lexicographically for deterministic ordering
    const std::array<byte, 32>* first = &our_identity;
    const std::array<byte, 32>* second = &their_identity;
    
    if (Utils::compare_bytes(our_identity, their_identity) > 0) {
        first = &their_identity;
        second = &our_identity;
    }
    
    // Concatenate: version byte + first key + second key
    bytes concat;
    concat.reserve(1 + 32 + 32);
    concat.push_back(1); // Version 1
    concat.insert(concat.end(), first->begin(), first->end());
    concat.insert(concat.end(), second->begin(), second->end());
    
    // SHA-512 hash
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return Result<SafetyNumber>(ResultCode::INTERNAL_ERROR, 
            "Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<SafetyNumber>(ResultCode::INTERNAL_ERROR, 
            "Failed to initialize SHA-512");
    }
    
    if (EVP_DigestUpdate(ctx, concat.data(), concat.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<SafetyNumber>(ResultCode::INTERNAL_ERROR, 
            "Failed to update hash");
    }
    
    std::array<byte, 64> hash;
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<SafetyNumber>(ResultCode::INTERNAL_ERROR, 
            "Failed to finalize hash");
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Use first 30 bytes (60 hex chars) formatted in groups of 5
    std::string hex_str;
    for (size_t i = 0; i < 30; ++i) {
        std::ostringstream oss;
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        hex_str += oss.str();
    }
    
    // Format in groups of 5
    std::string formatted;
    for (size_t i = 0; i < hex_str.length(); i += 5) {
        if (i > 0) formatted += ' ';
        formatted += hex_str.substr(i, std::min(size_t(5), hex_str.length() - i));
    }
    
    // Use first 32 bytes as fingerprint
    std::array<byte, 32> fingerprint;
    std::copy(hash.begin(), hash.begin() + 32, fingerprint.begin());
    
    return SafetyNumber(formatted, fingerprint, 1);
}

Result<SafetyNumber> SafetyNumber::parse(const std::string& safety_number) {
    // Remove spaces and validate
    std::string digits;
    digits.reserve(safety_number.size());
    
    for (char c : safety_number) {
        if (std::isxdigit(c)) {
            digits.push_back(c);
        } else if (c != ' ') {
            return Result<SafetyNumber>(ResultCode::INVALID_ARGUMENT, 
                "Invalid character in safety number");
        }
    }
    
    if (digits.length() != 60) {
        return Result<SafetyNumber>(ResultCode::INVALID_ARGUMENT, 
            "Safety number must be 60 hex digits");
    }
    
    // Convert to fingerprint
    std::array<byte, 32> fingerprint;
    for (size_t i = 0; i < 32; ++i) {
        std::string byte_str = digits.substr(i * 2, 2);
        fingerprint[i] = static_cast<byte>(std::stoi(byte_str, nullptr, 16));
    }
    
    std::string formatted = Utils::format_safety_number(digits);
    
    return SafetyNumber(formatted, fingerprint, 1);
}

bytes SafetyNumber::qr_data() const {
    // QR code data: version + fingerprint
    bytes result;
    result.reserve(1 + 32);
    result.push_back(static_cast<byte>(version_));
    result.insert(result.end(), fingerprint_.begin(), fingerprint_.end());
    return result;
}

bool SafetyNumber::verify(const SafetyNumber& other) const {
    return Utils::constant_time_equals(fingerprint_, other.fingerprint_);
}

double SafetyNumber::similarity(const SafetyNumber& other) const {
    // Calculate similarity based on matching digits
    std::string hex_a = Utils::bytes_to_hex(bytes(fingerprint_.begin(), fingerprint_.end()));
    std::string hex_b = Utils::bytes_to_hex(bytes(other.fingerprint_.begin(), other.fingerprint_.end()));
    
    // Take only the first 60 chars
    hex_a = hex_a.substr(0, 60);
    hex_b = hex_b.substr(0, 60);
    
    int matches = 0;
    for (size_t i = 0; i < std::min(hex_a.size(), hex_b.size()); ++i) {
        if (hex_a[i] == hex_b[i]) {
            matches++;
        }
    }
    
    return static_cast<double>(matches) / 60.0;
}

// ── VerificationQrCode ───────────────────────────────────────────────────────

VerificationQrCode::VerificationQrCode(
    std::array<byte, 32> identity_key,
    device_id device_id,
    std::array<byte, 32> safety_fingerprint,
    bool verified
) : identity_key_(std::move(identity_key))
  , device_id_(std::move(device_id))
  , safety_fingerprint_(std::move(safety_fingerprint))
  , verified_(verified)
{}

bytes VerificationQrCode::to_bytes() const {
    bytes result;
    result.reserve(1 + 32 + 16 + 32 + 1);
    
    result.push_back(static_cast<byte>(version_));
    result.insert(result.end(), identity_key_.begin(), identity_key_.end());
    result.insert(result.end(), device_id_.begin(), device_id_.end());
    result.insert(result.end(), safety_fingerprint_.begin(), safety_fingerprint_.end());
    result.push_back(verified_ ? 1 : 0);
    
    return result;
}

Result<VerificationQrCode> VerificationQrCode::from_bytes(const bytes& data) {
    if (data.size() < 1 + 32 + 16 + 32 + 1) {
        return Result<VerificationQrCode>(ResultCode::INVALID_ARGUMENT, 
            "QR code data too short");
    }
    
    size_t offset = 0;
    
    int version = data[offset++];
    if (version != 1) {
        return Result<VerificationQrCode>(ResultCode::INVALID_ARGUMENT, 
            "Unsupported QR code version");
    }
    
    std::array<byte, 32> identity_key;
    std::copy(data.begin() + offset, data.begin() + offset + 32, identity_key.begin());
    offset += 32;
    
    device_id dev_id;
    std::copy(data.begin() + offset, data.begin() + offset + 16, dev_id.begin());
    offset += 16;
    
    std::array<byte, 32> safety_fingerprint;
    std::copy(data.begin() + offset, data.begin() + offset + 32, safety_fingerprint.begin());
    offset += 32;
    
    bool verified = data[offset++] != 0;
    
    return VerificationQrCode(identity_key, dev_id, safety_fingerprint, verified);
}

// ── Safety Number Comparison ─────────────────────────────────────────────────

SafetyComparison compare_safety_numbers(
    const SafetyNumber& a,
    const SafetyNumber& b,
    double similarity_threshold
) {
    if (a.verify(b)) {
        return SafetyComparison::MATCH;
    }
    
    double sim = a.similarity(b);
    if (sim >= similarity_threshold) {
        return SafetyComparison::SIMILAR;
    }
    
    return SafetyComparison::MISMATCH;
}

} // namespace sibna
