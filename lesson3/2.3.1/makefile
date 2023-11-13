#gcc -o cacu add/add_int.o sub/sub_int.o add/add_float.o sub/sub_float.o main.o
#wrong:gcc -o cacu add/add_int.c sub/sub_int.c add/add_float.c sub/sub_float.c main.c -I./add -I./sub
#right:gcc -o cacu add/add_int.c sub/sub_int.c add/add_float.c sub/sub_float.c main.c -I./add -I./sub
# -o cacu add/add_int.o sub/sub_int.o add/add_float.o sub/sub_float.o main.o -I./add -I./sub
gcc -c -o add/add_int.o add/add_int.c
#gcc -c add/add_float.c  -o add/add_float.o
#gcc -c sub/sub_int.c    -o sub/sub_int.o
#gcc -c sub/sub_float.c  -o sub/sub_float.o
#gcc -c main.c           -o main.o -I./add  -I./sub
#gcc -o cacu add/add_int.o sub/sub_int.o add/add_float.o sub/sub_float.o main.o -I./add -I./sub