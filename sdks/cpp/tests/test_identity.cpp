#include <catch2/catch_test_macros.hpp>
#include <sibna/identity.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("IdentityKeyPair::generate produces valid keys", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());

    auto identity = result.value();
    REQUIRE(identity.public_key().size() == KEY_LENGTH);
    REQUIRE(identity.private_key().size() == KEY_LENGTH);
}

TEST_CASE("IdentityKeyPair::generate produces unique keys", "[identity]") {
    auto r1 = IdentityKeyPair::generate();
    auto r2 = IdentityKeyPair::generate();
    REQUIRE(r1.is_ok());
    REQUIRE(r2.is_ok());

    REQUIRE(r1.value().public_key() != r2.value().public_key());
}

TEST_CASE("IdentityKeyPair sign and verify", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());
    auto identity = result.value();

    bytes data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto sig = identity.sign(data);
    REQUIRE(sig.size() == SIGNATURE_LENGTH);

    REQUIRE(IdentityKeyPair::verify(identity.public_key(), data, sig));
}

TEST_CASE("IdentityKeyPair verify rejects tampered signature", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());
    auto identity = result.value();

    bytes data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto sig = identity.sign(data);

    sig[0] ^= 0xFF;
    REQUIRE_FALSE(IdentityKeyPair::verify(identity.public_key(), data, sig));
}

TEST_CASE("IdentityKeyPair verify rejects wrong data", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());
    auto identity = result.value();

    bytes data = {0x01, 0x02, 0x03};
    bytes wrong_data = {0x04, 0x05, 0x06};
    auto sig = identity.sign(data);

    REQUIRE_FALSE(IdentityKeyPair::verify(identity.public_key(), wrong_data, sig));
}

TEST_CASE("IdentityKeyPair::from_seed roundtrip", "[identity]") {
    bytes seed(KEY_LENGTH, 0xAB);
    auto r1 = IdentityKeyPair::from_seed(seed);
    REQUIRE(r1.is_ok());

    auto identity = r1.value();
    bytes exported_seed = identity.seed();
    REQUIRE(exported_seed == seed);

    auto r2 = IdentityKeyPair::from_seed(exported_seed);
    REQUIRE(r2.is_ok());
    REQUIRE(r2.value().public_key() == identity.public_key());
}

TEST_CASE("IdentityKeyPair::from_seed rejects wrong length", "[identity]") {
    bytes short_seed(16, 0x00);
    auto result = IdentityKeyPair::from_seed(short_seed);
    REQUIRE(result.is_err());
    REQUIRE(result.code() == ResultCode::INVALID_ARGUMENT);
}

TEST_CASE("IdentityKeyPair public_key_hex", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());

    std::string hex = result.value().public_key_hex();
    REQUIRE(hex.size() == KEY_LENGTH * 2);

    for (char c : hex) {
        REQUIRE((std::isxdigit(c) != 0));
    }
}

TEST_CASE("IdentityKeyPair signature_hex", "[identity]") {
    auto result = IdentityKeyPair::generate();
    REQUIRE(result.is_ok());

    bytes data = {0x01, 0x02, 0x03};
    auto sig = result.value().sign(data);
    std::string hex = result.value().signature_hex(sig);

    REQUIRE(hex.size() == SIGNATURE_LENGTH * 2);
}
