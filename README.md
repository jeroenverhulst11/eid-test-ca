# How to use this test environment

The testing environment consists of several components:

- A test library and proxy, which intercepts and modifies requests to
  the card, to allow testing with different cards and/or features.
- A test PKI infrastructure, to create custom certificates
  for use within the test environment.
- A "fromcard" tool, used to generate a CSR (Certificate Signing
  Request) for a key on an eID card. This can then be used with the
  above test PKI infrastructure and test library to generate
  certificates valid for the given card, but containing different
  metadata or signing algorithms than the one on the card.

[This repository](https://github.com/fedict/eid-test-ca/) contains the
fromcard tool and the source for the PKI infrastructure. For the virtual
card generation tool, see the [eid-test-cards
repository](https://github.com/Fedict/eid-test-cards)

## Using fromcard

The fromcard tool is provided as a source file that must be modified and
compiled:

- Compile fromcard.c, derencode.c, base64encode.c, derdata.h, and base64.h
  against the eID middleware into a program. Alternatively, download the
  precompiled version.
- Run the fromcard program which was compiled in the previous step on a
  system with a single eID card in a reader, passing it the given
  name(s), last name, national registry number, and hashing algorithm (1
  or 256) to use.
- Fromcard will cause the eID middleware to ask for your PIN code, and
  will then generate a CSR for the Signature and the Authentication
  keys, in that order, with the metadata as specified at the top of
  fromcard.c. **Note**: fromcard assumes that the dialogs were not
  disabled when compiling the middleware (i.e., as in the official
  distribution). If that is wrong, you may need to modify fromcard.c to
  take a PIN code from somewhere.
- Copy and paste the two CSRs into the PKI infrastructure (see below)

## Using the PKI infrastructure

The PKI infrastructure is just a set of shell- and CGI scripts that run
openssl in the right ways so that it produces a CA infrastructure with
OCSP responder that is as similar as possible to the official PKI.

It is possible to run the infrastructure directly on a Debian system;
however, to keep matters easy, a Docker container is available at the
docker hub. To get started, first install docker for your operating
system. Then, do the following:

    docker pull fedict/eid-test-ca
    docker run --name eid_test_store -v /var/lib/eid -ti fedict/eid-test-ca build

You have now built an eID PKI infrastructure with SHA256 as the hashing
algorithm and 10 year validity of the certificates. To create a PKI
infrastructure with SHA1 instead, replace the second of the two above
commands with:

    docker run --name=eid_test_store -v /var/lib/eid -ti -e EID_TEST_CA_TYPE=sha1 fedict/eid-test-ca build

or for SHA1 with 5 year validity (for cards with 1024-bit keys):

    docker run --name=eid_test_store -v /var/lib/eid -ti -e EID_TEST_CA_TYPE=old fedict/eid-test-ca build

There are a few other options available as well; for more information,
run

    docker run fedict/eid-test-ca help

but note that many of the options listed there have not been implemented
yet (for the current state of affairs, look at the [github
repository](https://github.com/Fedict/eid-test-ca)

It is possible to build all three on the same system if necessary,
provided you pass a different argument to the `--name` option every
time.

Whenever you want to interact with the PKI, do:

    docker run --volumes-from=eid_test_store -ti -p 80 -p 8888 fedict/eid-test-ca run

This command will start an OCSP responder on port 8888, and a web server
(containing the management interface and the CRLs) on port 80. If you
already have something running on either of those two ports, you may
need to use a different port; see the Docker documentation for details.

When the above is running, open a browser to
[localhost](http://localhost/). This contains links 

## Retiring certificates

To revoke a certificate, run the `revoke` command:

    docker run --volumes-from=eid_test_store -ti fedict/eid-test-ca revoke <serial>

replacing &lt;serial&gt; by the serial number of the certificate (that
is, the certificate serial number as assigned by the CA, *not* the RRN
number)

To suspend a certificate, run the `suspend` command:

    docker run --volumes-from=eid_test_store -ti fedict/eid-test-ca suspend <serial>

To resume a suspended certificate, run the `resume` command:

    docker run --volumes-from=eid_test_store -ti fedict/eid-test-ca resume <serial>

where &lt;serial&gt; has the same meaning as in the `revoke` command,
above.

Alternatively, use the webinterface for this.

# Notes

- Suspend/reinstate is still TODO. Will be implemented ASAP, once some
  details have been clarified.
- Docker does not by default clean out containers. It may from time to
  time be necessary to run `docker ps -a` to get a list of older
  containers, and `docker rm <id>` to clean them up.

## About

Copyright(C) Fedict, 2016.
Written by Wouter Verhelst

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

A copy of the GNU General Public License can be found in the file
[COPYING](COPYING).
