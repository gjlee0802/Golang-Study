libcalc.so: sum.o
	gcc -shared -o libcalc.so sum.o

sum.o: sum.h sum.c
	gcc -fPIC -c sum.c

clean:
	rm -f *.o
