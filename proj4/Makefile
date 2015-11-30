CXXFLAGS =  -g -MD -Wall -D_FILE_OFFSET_BITS=64
FUSEFLAGS= -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25 -I/usr/local/include/fuse -I/usr/include/fuse
LDFLAGS = -L. -L/usr/local/lib
LDLIBS = -lrpc -lfuse -lpthread
CC = g++

all: lab1

lab1: librpc.a rpctest lock_server lock_tester lock_demo

hfiles1=fifo.h chan.h host.h rpc.h marshall.h method_thread.h lock_protocol.h\
	 lock_server.h lock_client.h
hfiles2=yfs_client.h extent_client.h extent_protocol.h extent_server.h

rpclib=rpc.cc host.cc chan.cc

librpc.a: $(patsubst %.cc,%.o,$(rpclib))
	rm -f $@
	ar cq $@ $^
	ranlib librpc.a

rpctest: rpctest.o

lock_demo: lock_demo.o lock_client.o

lock_tester: lock_tester.o lock_client.o

lock_server: lock_server.o lock_smain.o

yfs_client: yfs_client.o extent_client.o fuse.o lock_client.o

extent_server: extent_server.o extent_smain.o

fuse.o: fuse.cc
	$(CXX) -c $(CXXFLAGS) $(FUSEFLAGS) $(MACFLAGS) $<

clean : 
	rm -rf *.o *.d librpc.a yfs_client extent_server lock_server lock_tester lock_demo rpctest 
