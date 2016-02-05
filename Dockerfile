FROM debian:jessie
MAINTAINER Wouter Verhelst <wouter.verhelst@fedict.be>
RUN apt-get update && apt-get install -y apache2 openssl
ADD camanage /usr/bin/camanage
ADD root/* /usr/share/eid-test/root/
ADD intermediate/* /usr/share/eid-test/intermediate/
EXPOSE 80
ENTRYPOINT ["/usr/bin/camanage"]
CMD ["run"]
