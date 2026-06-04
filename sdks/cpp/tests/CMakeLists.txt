find_package(Catch2 3 QUIET)

if(NOT Catch2_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.5.2
    )
    FetchContent_MakeAvailable(Catch2)
endif()

add_executable(sibna_tests
    test_identity.cpp
    test_crypto.cpp
    test_session.cpp
    test_context.cpp
    test_group.cpp
    test_safety_number.cpp
    test_utils.cpp
)

target_link_libraries(sibna_tests PRIVATE
    sibna_protocol
    Catch2::Catch2WithMain
)

target_include_directories(sibna_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

include(Catch)
catch_discover_tests(sibna_tests)
