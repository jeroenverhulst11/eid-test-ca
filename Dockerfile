FROM debian:jessie
MAINTAINER Wouter Verhelst <wouter.verhelst@fedict.be>
RUN apt-get update && apt-get install -y apache2 openssl cron libcgi-perl libxml-sax-writer-perl
ADD bin/* /usr/local/bin/
ADD root/* /usr/share/eid-test/root/
ADD intermediate/* /usr/share/eid-test/intermediate/
ADD eid-aliases.conf /etc/apache2/conf-available/
RUN a2enconf eid-aliases
EXPOSE 80
EXPOSE 8888
ENTRYPOINT ["/usr/local/bin/camanage"]
CMD ["run"]
