main: PsiphonTunnel.dylib main.o
	gcc PsiphonTunnel.dylib -o main main.o

main.o: main.c
	gcc -I.. -c main.c

PsiphonTunnel.dylib: ../PsiphonTunnel.go
	go build -buildmode=c-shared -o PsiphonTunnel.dylib ../PsiphonTunnel.go

clean:
	rm PsiphonTunnel.dylib PsiphonTunnel.h main main.o

