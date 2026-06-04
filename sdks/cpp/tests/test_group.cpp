#include <catch2/catch_test_macros.hpp>
#include <sibna/group.hpp>
#include <sibna/types.hpp>

using namespace sibna;

TEST_CASE("GroupSession creation", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);
    REQUIRE(group.id() == gid);
}

TEST_CASE("GroupSession encrypt and decrypt", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);

    bytes plaintext = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    auto encrypted = group.encrypt(plaintext);
    REQUIRE(encrypted.is_ok());

    auto decrypted = group.decrypt(encrypted.value());
    REQUIRE(decrypted.is_ok());
    REQUIRE(decrypted.value() == plaintext);
}

TEST_CASE("GroupSession encrypt fails with empty plaintext", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);

    bytes empty;
    auto result = group.encrypt(empty);
    REQUIRE(result.is_err());
    REQUIRE(result.code() == ResultCode::INVALID_ARGUMENT);
}

TEST_CASE("GroupSession get_info", "[group]") {
    group_id gid;
    std::fill(gid.begin(), gid.end(), 0x01);

    GroupSession group(gid);
    auto info = group.get_info();
    REQUIRE(info.id == gid);
}
