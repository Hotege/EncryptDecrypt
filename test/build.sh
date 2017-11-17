if [ ! -n "$CXX" ]; then
    CXX=g++
fi

$CXX test/test.cpp \
	-Iinclude \
	-Llib -Llibabstractalgorithm/lib -Llibrandom/lib \
	-lencryptdecrypt -labstractalgorithm -lrandom