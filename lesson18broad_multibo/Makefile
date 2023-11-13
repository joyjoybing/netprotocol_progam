all:mul_cli.o mul_cli mul_ser.o mul_ser bro_cli.o bro_cli bro_ser.o bro_ser clean
mul_cli.o:mul_cli.c 
	gcc -c mul_cli.c -o mul_cli.o
mul_cli:mul_cli.o
	gcc -o mul_cli mul_cli.o
mul_ser.o:mul_ser.c
	gcc -c mul_ser.c -o mul_ser.o
mul_ser:mul_ser.o
	gcc -o mul_ser mul_ser.o
bro_cli.o:bro_cli.c
	gcc -c bro_cli.c -o bro_cli.o
bro_cli:bro_cli.o
	gcc -o bro_cli bro_cli.o
bro_ser.o:bro_ser.c
	gcc -c bro_ser.c -o bro_ser.o
bro_ser:bro_ser.o
	gcc -o bro_ser bro_ser.o
clean:
	rm -f *.o
