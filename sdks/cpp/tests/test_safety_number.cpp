#include <catch2/catch_test_macros.hpp>
#include <sibna/safety_number.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("SafetyNumber generation", "[safety]") {
    bytes key1 = Utils::random_bytes(KEY_LENGTH);
    bytes key2 = Utils::random_bytes(KEY_LENGTH);

    auto sn = SafetyNumber::generate(key1, key2);
    REQUIRE(sn.is_ok());
    REQUIRE_FALSE(sn.value().empty());
}

TEST_CASE("SafetyNumber is symmetric", "[safety]") {
    bytes key1 = Utils::random_bytes(KEY_LENGTH);
    bytes key2 = Utils::random_bytes(KEY_LENGTH);

    auto sn1 = SafetyNumber::generate(key1, key2);
    auto sn2 = SafetyNumber::generate(key2, key1);
    REQUIRE(sn1.is_ok());
    REQUIRE(sn2.is_ok());
    REQUIRE(sn1.value() == sn2.value());
}

TEST_CASE("SafetyNumber differs for different keys", "[safety]") {
    bytes key1 = Utils::random_bytes(KEY_LENGTH);
    bytes key2 = Utils::random_bytes(KEY_LENGTH);
    bytes key3 = Utils::random_bytes(KEY_LENGTH);

    auto sn1 = SafetyNumber::generate(key1, key2);
    auto sn2 = SafetyNumber::generate(key1, key3);
    REQUIRE(sn1.is_ok());
    REQUIRE(sn2.is_ok());
    REQUIRE(sn1.value() != sn2.value());
}

TEST_CASE("SafetyNumber format", "[safety]") {
    bytes key1 = Utils::random_bytes(KEY_LENGTH);
    bytes key2 = Utils::random_bytes(KEY_LENGTH);

    auto sn = SafetyNumber::generate(key1, key2);
    REQUIRE(sn.is_ok());

    std::string formatted = SafetyNumber::format(sn.value());
    REQUIRE_FALSE(formatted.empty());
}
