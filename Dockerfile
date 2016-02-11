FROM debian:jessie
MAINTAINER Wouter Verhelst <wouter.verhelst@fedict.be>
RUN apt-get update && apt-get install -y apache2 openssl
RUN a2enmod cgi
ADD camanage /usr/bin/camanage
ADD root/* /usr/share/eid-test/root/
ADD intermediate/* /usr/share/eid-test/intermediate/
ADD cgi/* /usr/lib/cgi-bin/
ADD eid-aliases.conf /etc/apache2/conf-available/
RUN a2enconf eid-aliases
EXPOSE 80
ENTRYPOINT ["/usr/bin/camanage"]
CMD ["run"]
