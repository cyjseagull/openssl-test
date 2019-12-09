include(ExternalProject)
include(GNUInstallDirs)

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set(OPENSSL_CONFIG_COMMAND sh ./Configure darwin64-x86_64-cc)
else()
    set(OPENSSL_CONFIG_COMMAND bash config -Wl,--rpath=./ shared)
endif ()

set(OPENSSL_BUILD_COMMAND make)

ExternalProject_Add(openssl
	PREFIX ${CMAKE_SOURCE_DIR}/deps
	DOWNLOAD_NO_PROGRESS 1
    GIT_REPOSITORY https://github.com/cyjseagull/openssl.git
	GIT_SHALLOW true
	BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ${OPENSSL_CONFIG_COMMAND}
	LOG_CONFIGURE 1
	LOG_BUILD 1
	LOG_INSTALL 1
    BUILD_COMMAND ${OPENSSL_BUILD_COMMAND}
	INSTALL_COMMAND ""
)

ExternalProject_Get_Property(openssl SOURCE_DIR)
add_library(OPENSSL STATIC IMPORTED)
set(OPENSSL_SUFFIX .a)
set(OPENSSL_INCLUDE_DIRS ${SOURCE_DIR}/include)
set(OPENSSL_LIBRARY ${SOURCE_DIR}/libssl${OPENSSL_SUFFIX})
set(OPENSSL_CRYPTO_LIBRARIE ${SOURCE_DIR}/libcrypto${OPENSSL_SUFFIX})
set(OPENSSL_LIBRARIES ${OPENSSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARIE} dl)
set_property(TARGET OPENSSL PROPERTY IMPORTED_LOCATION ${OPENSSL_LIBRARIES})
set_property(TARGET OPENSSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIRS})



