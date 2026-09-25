option(
    JSTS_JGS245_PORTS_BOOST_USE_STATIC_LIBS
    "Prefer static Boost libraries for jgs245-ports"
    "${JSTS_BOOST_USE_STATIC_LIBS}"
)
mark_as_advanced(JSTS_JGS245_PORTS_BOOST_USE_STATIC_LIBS)

set(
    JSTS_JGS245_PORTS_SAMPLE_CONFIG
    ""
    CACHE FILEPATH
    "Optional private JGS524Ev2 backup for integration testing"
)
mark_as_advanced(JSTS_JGS245_PORTS_SAMPLE_CONFIG)

set(Boost_USE_STATIC_LIBS "${JSTS_JGS245_PORTS_BOOST_USE_STATIC_LIBS}")
find_package(Boost ${JSTS_BOOST_MIN} REQUIRED COMPONENTS json program_options)

add_library(jgs245-ports-core STATIC)
target_sources(
    jgs245-ports-core
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            domain.cpp
            parser.cpp
            render.cpp
)
target_compile_features(jgs245-ports-core PUBLIC cxx_std_26)
target_link_libraries(jgs245-ports-core PUBLIC Boost::headers Boost::json)

add_executable(jgs245-ports jgs245-ports.cpp)
target_compile_features(jgs245-ports PRIVATE cxx_std_26)
target_link_libraries(jgs245-ports PRIVATE jgs245-ports-core Boost::program_options)

if(BUILD_TESTING)
    add_executable(jgs245-ports-tests tests.cpp)
    target_compile_features(jgs245-ports-tests PRIVATE cxx_std_26)
    target_link_libraries(jgs245-ports-tests PRIVATE jgs245-ports-core Boost::headers)
    add_test(NAME jgs245-ports-tests COMMAND jgs245-ports-tests)

    if(JSTS_JGS245_PORTS_SAMPLE_CONFIG)
        if(NOT EXISTS "${JSTS_JGS245_PORTS_SAMPLE_CONFIG}")
            message(FATAL_ERROR "JSTS_JGS245_PORTS_SAMPLE_CONFIG does not exist")
        endif()
        add_test(
            NAME jgs245-ports-private-sample
            COMMAND jgs245-ports --strict --format json "${JSTS_JGS245_PORTS_SAMPLE_CONFIG}"
        )
    endif()
endif()

include(GNUInstallDirs)
install(TARGETS jgs245-ports RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
