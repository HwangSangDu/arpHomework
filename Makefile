
main : main.o

main.o : main.c
	gcc -c main.o main.c

clean:
	rm *.o