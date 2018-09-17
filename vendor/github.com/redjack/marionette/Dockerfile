FROM golang:1.9.4 as builder
ADD . /go/src/github.com/redjack/marionette/
WORKDIR /go/src/github.com/redjack/marionette/
RUN GOOS=linux GOARCH=amd64 go build -a -o marionette ./cmd/marionette

FROM ubuntu:16.04
WORKDIR /root/
RUN apt-get update && \
	apt-get install -y build-essential software-properties-common m4 wget python2.7 python-dev python-pip unzip libffi-dev && \
	pip2 install cffi cryptography

RUN wget https://gmplib.org/download/gmp/gmp-6.1.2.tar.bz2 && \
	tar -xvjf gmp-6.1.2.tar.bz2 && cd gmp-6.1.2 && \
	./configure --enable-cxx && make && make install && \
	cd /root && rm -rf gmp-*

RUN wget https://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.1.tar.gz && \
	tar zxvf pycrypto-2.6.1.tar.gz && cd pycrypto-2.6.1 && \
	python2.7 setup.py build && python2.7 setup.py install && \
	cd /root && rm -rf pycrypto-*

RUN wget -O regex2dfa.zip https://github.com/kpdyer/regex2dfa/archive/master.zip && \
	unzip regex2dfa.zip && cd regex2dfa-master && \
	./configure && make && python2.7 setup.py install && \
	cd /root && rm -rf regex2dfa*

RUN wget -O libfte.zip https://github.com/kpdyer/libfte/archive/master.zip && \
	unzip libfte.zip && cd libfte-master && \
	python2.7 setup.py install && \
	cd /root && rm -rf libfte*

COPY --from=builder /go/src/github.com/redjack/marionette/marionette .

ENTRYPOINT ["./marionette"]
