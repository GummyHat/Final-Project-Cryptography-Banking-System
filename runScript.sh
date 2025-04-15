export LD_LIBRARY_PATH=$(pwd)

g++ socketoutline.cpp -L. -lECC

./a.out