FROM debian:jessie
MAINTAINER Wouter Verhelst <wouter.verhelst@fedict.be>
RUN apt-get update && apt-get install -y apache2 openssl cron libcgi-pm-perl libxml-sax-writer-perl && apt-get clean
ADD bin/* /usr/local/bin/
ADD root/* /usr/share/eid-test/root/
ADD intermediate/* /usr/share/eid-test/intermediate/
ADD cgi/* /usr/lib/cgi-bin/
ADD eid-aliases.conf /etc/apache2/conf-available/
ADD html/* /var/www/html/
RUN a2enconf eid-aliases
RUN a2enmod cgi
EXPOSE 80
EXPOSE 8888
ENTRYPOINT ["/usr/local/bin/camanage"]
CMD ["run"]
