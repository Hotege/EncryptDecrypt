project(EncryptDecrypt)

cmake_minimum_required(VERSION 2.6)

include_directories(
	${PROJECT_SOURCE_DIR}/libabstractalgorithm/include
	${PROJECT_SOURCE_DIR}/librandom/include
)

link_directories(
	${PROJECT_SOURCE_DIR}/libabstractalgorithm/lib
	${PROJECT_SOURCE_DIR}/librandom/lib
)

link_libraries(
	abstractalgorithm
	random
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,-Bsymbolic -O2 -fPIC -m64 -Wl,-Bsymbolic")

set(CMAKE_INSTALL_PREFIX "/")
set(CMAKE_INSTALL_DO_STRIP TRUE)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

add_subdirectory(src)
add_subdirectory(test)

install(
	FILES test11.jpg
	DESTINATION "./"
)