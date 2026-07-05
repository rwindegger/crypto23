cmake_minimum_required(VERSION 3.31)

project(crypto23 LANGUAGES CXX VERSION 1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)


add_library(
        crypto23
        INTERFACE
        include/crypto23/rijndael.h
)
add_library(crypto23::crypto23 ALIAS crypto23)

# download CPM.cmake
file(
        DOWNLOAD
        https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.40.8/CPM.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake
        EXPECTED_HASH SHA256=78ba32abdf798bc616bab7c73aac32a17bbd7b06ad9e26a6add69de8f3ae4791
)
include(${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake)

target_compile_features(
        crypto23
        INTERFACE
        cxx_std_23
)

target_include_directories(
        crypto23
        INTERFACE
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

install(
        TARGETS crypto23
        EXPORT crypto23Targets
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
        DIRECTORY include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

set(crypto23_CMAKE_CONFIG_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/crypto23")

install(
        EXPORT crypto23Targets
        FILE crypto23Targets.cmake
        NAMESPACE crypto23::
        DESTINATION ${crypto23_CMAKE_CONFIG_DESTINATION}
)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/crypto23ConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
)
configure_package_config_file(
        "${CMAKE_CURRENT_LIST_DIR}/cmake/crypto23Config.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/crypto23Config.cmake"
        INSTALL_DESTINATION ${crypto23_CMAKE_CONFIG_DESTINATION}
)

install(
        FILES
        "${CMAKE_CURRENT_BINARY_DIR}/crypto23ConfigVersion.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/crypto23Config.cmake"
        DESTINATION ${crypto23_CMAKE_CONFIG_DESTINATION}
)

export(
        EXPORT crypto23Targets
        FILE "${CMAKE_CURRENT_BINARY_DIR}/crypto23Targets.cmake"
        NAMESPACE crypto23::
)

export(PACKAGE crypto23)

option(BUILD_TESTING "..." ON)
if (BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif ()
