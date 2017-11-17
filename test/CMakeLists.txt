cmake_minimum_required (VERSION 2.6)

file(
	GLOB Test_Source 
    test.cpp
)

include_directories(
	${PROJECT_SOURCE_DIR}/src
)

link_libraries(
	encryptdecrypt_shared
)

add_executable(test ${Test_Source})

install(
	FILES build.sh run.sh
	DESTINATION "./"
)

install(
	FILES test.cpp
	DESTINATION "test"
)