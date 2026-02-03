cmake_minimum_required(VERSION 3.14)
project(minisign
        LANGUAGES C CXX
        VERSION 1.2)

set(COMMENT_PREFIX_DEFAULT "untrusted comment: ")
set(TRUSTED_COMMENT_PREFIX_DEFAULT "trusted comment: ")

configure_file("cmake/config-minisign.h.cmake" "${CMAKE_BINARY_DIR}/src/config-minisign.h")

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBSODIUM REQUIRED libsodium)

find_path(SODIUM_INCLUDE_DIR sodium.h HINTS ${LIBSODIUM_INCLUDE_DIRS} /usr/local/include /opt/local/include /opt/include)
find_library(SODIUM_LIBRARY NAMES sodium HINTS ${LIBSODIUM_LIBRARY_DIRS} /usr/local/lib /opt/local/lib /opt/lib)

add_library(minisign SHARED
        src/minisign.c
        src/base64.c
        src/core.c
        src/globals.c
        src/helpers.c
)

set_target_properties(minisign PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION 1
)

target_include_directories(minisign
    PUBLIC
        ${LIBSODIUM_INCLUDE_DIRS}
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/src>
        ${CMAKE_CURRENT_SOURCE_DIR}/minisign/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(minisign PUBLIC ${SODIUM_LIBRARY})
target_compile_options(minisign PUBLIC ${LIBSODIUM_CFLAGS} ${LIBSODIUM_CFLAGS_OTHER})
target_compile_features(minisign PUBLIC c_std_99)

if(NOT DEFINED COMMENT_PREFIX)
    set(COMMENT_PREFIX "${COMMENT_PREFIX_DEFAULT}")
endif()
if(NOT DEFINED TRUSTED_COMMENT_PREFIX)
    set(TRUSTED_COMMENT_PREFIX "${TRUSTED_COMMENT_PREFIX_DEFAULT}")
endif()

target_compile_definitions(minisign PRIVATE
        COMMENT_PREFIX="${COMMENT_PREFIX}"
        TRUSTED_COMMENT_PREFIX="${TRUSTED_COMMENT_PREFIX}"
)

add_executable(test example.cpp)
target_link_libraries(test PRIVATE minisign)
set_target_properties(test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        LINK_FLAGS_RELEASE -s
)

add_executable(sign-keygen tools/sign-keygen.c)
target_include_directories(sign-keygen PRIVATE $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/src>)
target_link_libraries(sign-keygen PRIVATE minisign)
set_target_properties(sign-keygen PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        LINK_FLAGS_RELEASE -s
)

# Install library
install(TARGETS minisign
        EXPORT minisignTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include/minisign
)

# Install public headers
install(FILES
        include/minisign/minisign.h
        include/minisign/globals.h
        DESTINATION include/minisign
)

# Export CMake targets
install(EXPORT minisignTargets
        FILE minisignTargets.cmake
        NAMESPACE minisign::
        DESTINATION lib/cmake/minisign
)

include(CMakePackageConfigHelpers)

# Write version file
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/minisignConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
)

# Configure the config file
configure_package_config_file(
        "${CMAKE_CURRENT_LIST_DIR}/cmake/minisignConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/minisignConfig.cmake"
        INSTALL_DESTINATION lib/cmake/minisign
)

# Install config files
install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/minisignConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/minisignConfigVersion.cmake"
        DESTINATION lib/cmake/minisign
)

# pkg-config
configure_file(minisign.pc.in minisign.pc @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/minisign.pc" DESTINATION lib/pkgconfig)

# sign-keygen
install(TARGETS sign-keygen
        RUNTIME DESTINATION bin
)