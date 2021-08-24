FROM alpine:edge AS liblsquic-builder
WORKDIR /src

RUN apk add --no-cache build-base git apk-tools abuild cmake go perl linux-headers

RUN abuild-keygen -a -n && \
    cp /root/.abuild/-*.rsa.pub /etc/apk/keys/

COPY docker/APKBUILD-boringssl boringssl/APKBUILD
RUN cd boringssl && abuild -F -r && cd ..

RUN apk add --repository /root/packages/src boringssl boringssl-dev boringssl-static

RUN apk add --no-cache zlib-dev zlib-static libevent-dev libevent-static

COPY docker/APKBUILD-lsquic lsquic/APKBUILD
RUN cd lsquic && abuild -F -r && cd ..

RUN apk add --repository /root/packages/src lsquic-static

RUN mkdir tmp && cd tmp && \
    ar -x /usr/lib/libssl.a && \
    ar -x /usr/lib/libcrypto.a && \
    ar -x /usr/lib/liblsquic.a && \
    ar rc liblsquic.a *.o && \
    strip --strip-unneeded liblsquic.a && \
    ranlib liblsquic.a && \
    cp liblsquic.a /root/liblsquic.a && \
    cd .. && rm -rf tmp