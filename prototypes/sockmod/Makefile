UNAME=2.4.21-99-smp

sockmod.o : sockmod.c
	gcc -c sockmod.c -I/lib/modules/${UNAME}/build/include

clean :
	rm *~ *.o

install :
	sudo insmod sockmod.o

uninstall :
	sudo rmmod sockmod
