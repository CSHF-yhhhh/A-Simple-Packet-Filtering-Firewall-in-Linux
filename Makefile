obj-m+=firewall.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) write.c -shared -o write.so
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm write.so
