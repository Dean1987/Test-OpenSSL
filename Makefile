OBJS = main.o \
	test.o

CC = gcc.exe
INCS = -I "C:\\bakup\\openssl-1.0.1s\\inc32\\"
CFLAGS = $(INCS) -Wall -O -g
LIBS = -Wall -g $ -L "C:\\bakup\\openssl-1.0.1s\\out32dll\\libeay32.lib"

Test-OpenSSL.exe : $(OBJS)
	$(CC) $(OBJS) -o Test-OpenSSL.exe $(LIBS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	del *.o Test-OpenSSL.exe
