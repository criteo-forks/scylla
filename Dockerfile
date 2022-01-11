# ./tools/toolchain/dbuild ./configure.py --mode=release
# ./tools/toolchain/dbuild ninja dist-rpm
# tar -czvf ./scylladb-4.4.5.15.tar.gz build/dist/*/redhat/RPMS/x86_64/ \
#          tools/python3/build/redhat/RPMS/x86_64/scylla-python3-*.rpm \
#          tools/jmx/build/redhat/RPMS/noarch/scylla-jmx-*.rpm \
#          tools/java/build/redhat/RPMS/noarch/scylla-tools-*.rpm \
#          tools/java/build/redhat/RPMS/noarch/scylla-tools-core-*.rpm
#
# docker build . -t ashangit/scylla:4.4.5.15
# docker push ashangit/scylla:4.4.5.15

ARG CENTOS_BASE_VERSION=0.1.0-864-g3f5aa7a

FROM filer-docker-registry-build.prod.crto.in/criteo-container-base:${CENTOS_BASE_VERSION}

ENV container docker

RUN yum -y install epel-release && \
    yum -y clean expire-cache && \
    yum -y update && \
    yum -y install hostname supervisor java-1.8.0-openjdk perf elfutils file  && \
    yum -y install gcc make texinfo gcc-c++ flex bison python-devel libiptcdata-devel libbabeltrace-devel mpfr-devel expat-devel xz-devel && \
    yum clean all

RUN curl -O https://ftp.gnu.org/gnu/gdb/gdb-11.1.tar.gz && \
    tar xvfz gdb-11.1.tar.gz && \
    cd gdb-11.1 && \
    ./configure --disable-werror && \
    make && \
    make install

ARG VERSION=4.4.5-criteo1
ARG DOCKER_DIST_DIR=/tmp/scylla-source/scylla-scylla-$VERSION/dist/docker/redhat

# Source dockerfile is https://github.com/scylladb/scylla/blob/master/dist/docker/redhat/Dockerfile
# CRITEO TIP: replace "ADD " to "RUN cp $DOCKER_DIST_DIR/"
# CRITEO TIP: Remove rsyslog, sshd and node-exporter from the supervisord config and yum
COPY scylla.tar.gz /tmp/scylla.tar.gz
RUN mkdir -p /tmp/scylla-source && \
    tar -xf /tmp/scylla.tar.gz -C /tmp/scylla-source && \
    rm /tmp/scylla.tar.gz && \
    cp $DOCKER_DIST_DIR/scylla_bashrc /scylla_bashrc && \
    cp $DOCKER_DIST_DIR/etc/sysconfig/scylla-server /etc/sysconfig/scylla-server && \
    cp $DOCKER_DIST_DIR/etc/supervisord.conf /etc/supervisord.conf && \
    mkdir -p /etc/supervisord.conf.d && \
    cp $DOCKER_DIST_DIR/etc/supervisord.conf.d/scylla-server.conf /etc/supervisord.conf.d/scylla-server.conf && \
    cp $DOCKER_DIST_DIR/etc/supervisord.conf.d/scylla-jmx.conf /etc/supervisord.conf.d/scylla-jmx.conf && \
    cp $DOCKER_DIST_DIR/scylla-service.sh /scylla-service.sh && \
    cp $DOCKER_DIST_DIR/scylla-jmx-service.sh /scylla-jmx-service.sh && \
    cp $DOCKER_DIST_DIR/scyllasetup.py /scyllasetup.py && \
    cp $DOCKER_DIST_DIR/commandlineparser.py /commandlineparser.py && \
    cp $DOCKER_DIST_DIR/docker-entrypoint.py /docker-entrypoint.py && \
    rm -R /tmp/scylla-source

# Install Scylla:
COPY scylladb.tar.gz /tmp/scylladb.tar.gz
RUN mkdir -p /tmp/scylla-rpms && \
    tar -xf /tmp/scylladb.tar.gz -C /tmp/scylla-rpms && \
    rm /tmp/scylladb.tar.gz && \
    find /tmp/scylla-rpms -name "*.rpm" | xargs yum install -y && \
    yum clean all && \
    rm -R /tmp/scylla-rpms;

COPY cassandra_exporter.conf /etc/supervisord.conf.d/cassandra_exporter.conf
COPY cassandra_exporter.jar /cassandra_exporter.jar
COPY scylla-server.conf /etc/supervisord.conf.d/scylla-server.conf

COPY .gdbinit /root/.gdbinit

RUN cd / && \
    curl -O https://raw.githubusercontent.com/scylladb/seastar/master/scripts/seastar-addr2line && \
    curl -O https://raw.githubusercontent.com/scylladb/seastar/master/scripts/addr2line.py && \
    chmod 755 /seastar-addr2line

# file /opt/scylladb/libexec/scylla to get ID which is the path
#RUN ID=$(file /opt/scylladb/libexec/scylla |cut -d= -f2|cut -d, -f1| cut -c -2) && \
#    FNAME=$(file /opt/scylladb/libexec/scylla |cut -d= -f2|cut -d, -f1| cut -c 3-) && \
#    eu-unstrip /opt/scylladb/libexec/scylla /usr/lib/debug/.build-id/$ID/$FNAME.debug && \
#    rm /opt/scylladb/libexec/scylla && \
#    ln -s /usr/lib/debug/opt/scylladb/libexec/scylla-4.4.5-0.20211005.4b9cfb9a4.x86_64.debug /opt/scylladb/libexec/scylla && \
#    chmod 755 /usr/lib/debug/opt/scylladb/libexec/scylla-4.4.5-0.20211005.4b9cfb9a4.x86_64.debug

ENV PATH /opt/scylladb/python3/bin:/usr/local/bin:$PATH
ENTRYPOINT ["/docker-entrypoint.py"]

EXPOSE 10000 9042 9160 9180 7000 7001 7192
VOLUME [ "/var/lib/scylla" ]