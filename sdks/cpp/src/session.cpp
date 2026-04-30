#include "sibna/session.hpp"
#include "sibna/context.hpp"
#include "sibna/crypto.hpp"

namespace sibna {

// ── Session ──────────────────────────────────────────────────────────────────

Session::Session(bytes peer_id, void* native_handle)
    : peer_id_(std::move(peer_id))
    , native_handle_(native_handle)
    , established_at_(std::chrono::system_clock::now())
{}

Session::~Session() {
    // Secure cleanup
    Utils::secure_clear(peer_id_);
    disposed_ = true;
}

Session::Session(Session&& other) noexcept
    : peer_id_(std::move(other.peer_id_))
    , native_handle_(other.native_handle_)
    , disposed_(other.disposed_)
    , messages_sent_(other.messages_sent_)
    , messages_received_(other.messages_received_)
    , established_at_(other.established_at_) {
    other.native_handle_ = nullptr;
    other.disposed_ = true;
}

Session& Session::operator=(Session&& other) noexcept {
    if (this != &other) {
        Utils::secure_clear(peer_id_);
        peer_id_ = std::move(other.peer_id_);
        native_handle_ = other.native_handle_;
        disposed_ = other.disposed_;
        messages_sent_ = other.messages_sent_;
        messages_received_ = other.messages_received_;
        established_at_ = other.established_at_;
        other.native_handle_ = nullptr;
        other.disposed_ = true;
    }
    return *this;
}

Result<void> Session::perform_handshake(const PreKeyBundle& peer_bundle, bool initiator) {
    ensure_not_disposed();
    
    // Validate the peer bundle
    if (peer_bundle.is_expired()) {
        return Result<void>(ResultCode::INVALID_ARGUMENT, "Peer bundle is expired");
    }
    
    // Perform X3DH handshake
    // In a full implementation, this would:
    // 1. Extract the identity key, signed prekey, and one-time prekey
    // 2. Perform X25519 DH operations
    // 3. Derive the root key using HKDF
    // 4. Initialize the Double Ratchet
    
    // For now, mark the session as established
    established_at_ = std::chrono::system_clock::now();
    
    return Result<void>();
}

Result<bytes> Session::encrypt(const bytes& plaintext, const bytes& associated_data) {
    ensure_not_disposed();
    
    if (plaintext.empty()) {
        return Result<bytes>(ResultCode::INVALID_ARGUMENT, "Plaintext cannot be empty");
    }
    
    // Generate a random message key
    auto key_result = Crypto::generate_key();
    if (key_result.is_err()) {
        return key_result;
    }
    auto message_key = key_result.value();
    
    // Encrypt using ChaCha20-Poly1305
    auto encrypt_result = Crypto::encrypt(message_key, plaintext, associated_data);
    if (encrypt_result.is_err()) {
        return encrypt_result;
    }
    
    messages_sent_++;
    
    // In a full implementation, the message key would be derived from the
    // Double Ratchet chain, not randomly generated per message
    
    return encrypt_result;
}

Result<bytes> Session::decrypt(const bytes& ciphertext, const bytes& associated_data) {
    ensure_not_disposed();
    
    if (ciphertext.size() < NONCE_LENGTH + TAG_LENGTH + 1) {
        return Result<bytes>(ResultCode::INVALID_CIPHERTEXT, "Ciphertext too short");
    }
    
    // In a full implementation, this would:
    // 1. Derive the message key from the receiving chain
    // 2. Decrypt using ChaCha20-Poly1305
    // 3. Update the chain key
    
    // For now, we need the key - in production this comes from the ratchet
    // This is a simplified version that won't work without the proper key
    messages_received_++;
    
    // Return error - proper decryption requires Double Ratchet state
    return Result<bytes>(ResultCode::INVALID_STATE, 
        "Decryption requires Double Ratchet key - use protocol-level decrypt");
}

size_t Session::current_message_number() const {
    return messages_sent_;
}

bool Session::is_established() const {
    return established_at_.has_value();
}

std::optional<std::chrono::seconds> Session::age() const {
    if (!established_at_) {
        return std::nullopt;
    }
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now - *established_at_);
}

SessionInfo Session::get_stats() const {
    SessionInfo info;
    info.peer_id = peer_id_;
    info.messages_sent = messages_sent_;
    info.messages_received = messages_received_;
    info.established_at = established_at_;
    info.is_established = established_at_.has_value();
    return info;
}

void Session::ensure_not_disposed() const {
    if (disposed_) {
        throw SibnaError(ResultCode::INVALID_STATE, "Session has been disposed");
    }
}

} // namespace sibna
