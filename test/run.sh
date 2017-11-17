export LD_LIBRARY_PATH=`pwd`/lib:`pwd`/libabstractalgorithm/lib:`pwd`/librandom/lib:$LD_LIBRARY_PATH

# valgrind --leak-check=full --undef-value-errors=no 
./a.out $*