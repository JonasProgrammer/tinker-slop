option(JSTS_UBQT_REDACT_BOOST_USE_STATIC_LIBS
    "Prefer static Boost libraries for ubqt-redact" "${JSTS_BOOST_USE_STATIC_LIBS}")
mark_as_advanced(JSTS_UBQT_REDACT_BOOST_USE_STATIC_LIBS)
set(Boost_USE_STATIC_LIBS "${JSTS_UBQT_REDACT_BOOST_USE_STATIC_LIBS}")
find_package(Boost ${JSTS_BOOST_MIN} REQUIRED COMPONENTS json program_options)

add_library(ubqt-redact-core STATIC)
target_sources(ubqt-redact-core PUBLIC FILE_SET CXX_MODULES FILES core.cpp)
target_compile_features(ubqt-redact-core PUBLIC cxx_std_26)
target_link_libraries(ubqt-redact-core PRIVATE Boost::json)
add_executable(ubqt-redact main.cpp)
target_link_libraries(ubqt-redact PRIVATE ubqt-redact-core Boost::program_options)
if(BUILD_TESTING)
    add_executable(ubqt-redact-tests tests.cpp)
    target_link_libraries(ubqt-redact-tests PRIVATE ubqt-redact-core Boost::json)
    add_test(NAME ubqt-redact-tests COMMAND ubqt-redact-tests)
    add_test(NAME ubqt-redact-cli-tests
        COMMAND "${CMAKE_COMMAND}" "-DJSTS_TOOL=$<TARGET_FILE:ubqt-redact>"
            "-DJSTS_TEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-test"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cli_tests.cmake")
endif()
include(GNUInstallDirs)
install(TARGETS ubqt-redact RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
