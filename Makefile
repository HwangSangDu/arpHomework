
main : main.o
	gcc -o main main.o -lpcap -g

main.o : main.c
	gcc -c main.c -lpcap -g

clean:
	rm *.o