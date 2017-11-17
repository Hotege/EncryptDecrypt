cmake_minimum_required(VERSION 2.6)

file(
	GLOB SOURCE_FILES
	EncryptDecrypt.cpp
)

include_directories(
)

link_directories(
)

link_libraries(
)

add_library(encryptdecrypt_shared SHARED ${SOURCE_FILES})
set_target_properties(encryptdecrypt_shared PROPERTIES OUTPUT_NAME "encryptdecrypt")

add_library(encryptdecrypt_static STATIC ${SOURCE_FILES})
set_target_properties(encryptdecrypt_static PROPERTIES OUTPUT_NAME "encryptdecrypt")

install(
	TARGETS encryptdecrypt_shared encryptdecrypt_static
	LIBRARY DESTINATION "lib"
	ARCHIVE DESTINATION "lib"
)

set(HEADERS EncryptDecrypt.h)
install(
	FILES ${HEADERS}
	DESTINATION "include"
)