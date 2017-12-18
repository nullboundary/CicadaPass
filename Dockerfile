FROM golang:1.4.2-wheezy
MAINTAINER Noah Shibley <pass.ninja@mail.com>
#Build environment container for Pass Ninja Vendor app

#apt-get update
RUN apt-get update && \
apt-get install -y build-essential wget

#download and untar libressl
ENV LIBRESSL_VERSION libressl-2.1.4
RUN cd /usr/src/ && \
wget http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/${LIBRESSL_VERSION}.tar.gz && \
tar xvzf ${LIBRESSL_VERSION}.tar.gz && \
rm ${LIBRESSL_VERSION}.tar.gz

#compile libressl & link /usr/local/lib
RUN cd /usr/src/${LIBRESSL_VERSION}/ && \
./configure && \
make check && \
make install && \
ldconfig -v

#get go libraries
WORKDIR /go/src
RUN go get github.com/zenazn/goji && \
go get github.com/nullboundary/govalidator && \
go get github.com/nullboundary/gocertsigner && \
go get github.com/coreos/go-etcd/etcd && \
go get github.com/dancannon/gorethink && \
go get github.com/xordataexchange/crypt/config && \
go get github.com/hashicorp/logutils

#install crypt for setting up encrypted etcd key/value
RUN go install github.com/xordataexchange/crypt/bin/crypt

#private repos need ssh key. TODO
#RUN go get bitbucket.org/cicadaDev/storer
#RUN go get bitbucket.org/cicadaDev/utils

WORKDIR /go/src/bitbucket.org/passVendor
EXPOSE  8001

#build this container
#docker build -t passninja/build-vendor .

#access and run bash in build container
#docker run --rm -it -v "$PWD":/go/src/bitbucket.org/passVendor passninja/build-vendor /bin/bash -i

#to compile app in container
#docker run --rm -v "$PWD":/go/src/bitbucket.org/passVendor passninja/build-vendor go build -v

#run the app in the container
#docker run --rm --name ninjapassapp1 -v "$PWD":/go/src/bitbucket.org/passVendor -v "$PWD"/certs:/certs -p 443:10443 passninja/build-vendor ./passVendor
