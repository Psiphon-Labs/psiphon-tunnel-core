main: libpsiphontunnel.so main.o
	gcc -I. -o main main.o -L. -lpsiphontunnel

main.o: main.c
	gcc -I.. -c main.c

libpsiphontunnel.so: ../PsiphonTunnel.go
	# At this time, we don't support modules
	GO111MODULE=off go build -buildmode=c-shared -o libpsiphontunnel.so ../PsiphonTunnel.go

clean:
	rm libpsiphontunnel.so libpsiphontunnel.h main main.o

