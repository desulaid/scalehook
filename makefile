#	makefile for building and running scalehook test.
#
#	to build:
#		make
scalehook_flags = -c
clean_flags = -f

scalehook_out = test.out
scalehook_run = ./test.out

all: scalehook

clean:
	-rm $(clean_flags) ./*.o

scalehook: clean
	gcc $(scalehook_flags) ./scalehook.c
	gcc $(scalehook_flags) ./tests/test.c
	gcc ./*.o -o $(scalehook_out)
	$(scalehook_run)