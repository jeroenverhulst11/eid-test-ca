#!/usr/bin/perl -w

use warnings;
use strict;

use XML::SAX;
use XML::SAX::Writer;

# Yes, I should be using something more modern. No, not now -- I would need to
# learn first, and this is too urgent.
use CGI;

package xmlfilter;

use base qw(XML::SAX::Base);

sub new {
	my ($class, $hash, @args) = @_;

	my $self = $class->SUPER::new(@args);

	foreach my $key(keys %$hash) {
		$self->{"xmlfilter_$key"} = $hash->{$key};
	}

	$self->{xmlfilter_element} = "";
	$self->{xmlfilter_last_id} = "";

	return $self;
}

sub characters {
	my ($self, $data, @rest) = @_;

	if($self->{xmlfilter_element} eq "id") {
		$self->{xmlfilter_last_id} .= $data->{Data};
	}
	if(exists($self->{xmlfilter_file_name}) &&
				length($self->{xmlfilter_file_name}) > 0) {
		open OUT, ">", $self->{xmlfilter_file_name};
		my $s = pack 'H*', $data->{Data};
		print OUT $s;
		close OUT;
		$self->{xmlfilter_file_name} = "";
	}
	if(exists($self->{xmlfilter_override}) && 
				length($self->{xmlfilter_override}) > 0) {
		open IN, "< :raw :bytes", $self->{xmlfilter_override};
		my $s;
		read IN, $s, 9999999;
	       	$s = unpack 'H*', $s;
		$s =~ tr/a-z/A-Z/;
		$data->{Data} = $s;
		close IN;
		$self->{xmlfilter_override} = "";
	}
	return $self->SUPER::characters($data, @rest);
}

sub start_element {
	my ($self, $el, @rest) = @_;

	$self->{xmlfilter_element} = $el->{LocalName};
	if($el->{LocalName} eq "content") {
		chomp $self->{xmlfilter_last_id};
		if(exists($self->{xmlfilter_readfiles}{$self->{xmlfilter_last_id}})) {
			$self->{xmlfilter_override} = $self->{xmlfilter_readfiles}{$self->{xmlfilter_last_id}};
		}
		if(exists($self->{xmlfilter_writefiles}{$self->{xmlfilter_last_id}})) {
			$self->{xmlfilter_file_name} = $self->{xmlfilter_writefiles}{$self->{xmlfilter_last_id}};
		}
	}
	return $self->SUPER::start_element($el, @rest);
}

sub end_element {
	my ($self, $el, @rest) = @_;

	if($el->{LocalName} eq "file") {
		$self->{xmlfilter_last_id} = "";
		delete $self->{xmlfilter_override};
		delete $self->{xmlfilter_file_name};
	}
	return $self->SUPER::end_element($el, @rest);
}

package main;

my $q = CGI->new;
my @hidden;

sub show_hiddens {
	foreach my $hide(@hidden) {
		print $q->hidden($hide);
	}
	print "\n";
}

sub get_cur_certs {
	open INDEX, "index.txt";
	my $pems = ();
	my $friendlies = {};
	my $line;
	while($line = <INDEX>) {
		my (undef, $serial, undef, undef, $friendly) = split /\t/, $line;
		push @$pems, "$serial.pem";
		$friendlies->{"$serial.pem"} = $friendly;
	}

	return ($pems, $friendlies);
}

sub get_cert {
	my $crt = shift or die "need certificate type!";
	my $type = shift;

	print $q->start_html({-title=>'eID Test CA'});
	print $q->h1('eID Test CA');
	print $q->start_form({-method=>'post', -action=>'.'});
	show_hiddens;
	if(!defined($type)) {
		print $q->h2("Certificate selection");
		print $q->p("Please choose a method for selecting the $crt certificate:");
		print $q->radio_group(-name=>"${crt}type",
				-values=>['csr', 'previous', 'none'],
				-labels=>{ "csr" => "Upload a <abbr title='Certificate Signing Request'>CSR</abbr>",
					   "previous" => "Reuse a previously-signed certificate",
					   "none" => "Don't include a $crt certificate"});
	} else {
		print $q->hidden("${crt}type");
		if($type eq "csr") {
			print $q->h2("$crt certificate by CSR");
			print $q->p("Please paste the CSR (in PEM format) in the field below:");
			print $q->textarea(-name=>"${crt}csr", -rows=>25, -columns=>80);
			print $q->br();
			print $q->submit();
		} elsif($type eq "previous") {
			my ($certlist, $certlabels) = get_cur_certs();
			print $q->h2("Select an old $crt certificate");
			print $q->popup_menu(-name=>"${crt}serial",
					     -values=>$certlist,
					     -labels=>$certlabels);
		} else {
			die "unexpected certificate type: got $type, expected csr, none, or previous";
		}
	}
	print $q->end_form();
}

my $xml_input = $q->param('xmlin');
if(!defined($xml_input)) {
	print $q->start_html({-title=>'eID Test CA'});
	print <<EOF ;
    <h1>eID Test CA</h1>
    <h2>Note</h2>
    <p>Using this form (and the CA) is only necessary in the following
    cases:</p>
    <ol>
      <li>You want to test OCSP requests against a live server</li>
      <li>You want to test address and identity file signature
	verification using the SHA256 hashing algorithm, rather than the
	SHA1 one.</li>
      <li>You want to test cards with more or fewer certificates than
        are available on the card itself.</li>
    </ol>
    <p>In all other cases, the virtual card generator tool produces
      output that is sufficient.</p>
EOF
	print $q->start_form({-method=>"post", -action=>"."});
    	print <<EOF ;
      <h2>XML data</h2>
      <p>Run the tool to generate virtual cards. This generates an XML
        file containing all the data that should be on the virtual card.
	Paste it in this text area:</p>
      <textarea name="xmlin" rows="25" cols="80"></textarea>
      <br>
      <input type="submit">
EOF
	print $q->end_form();
	print $q->end_html();
	exit;
} else {
	push @hidden, "xmlin";
}

my $sigtype = $q->param('sigtype');
my $sigcsr = $q->param('sigcsr');
my $sigold = $q->param('sigold');

if(!defined($sigtype) || ($sigtype ne 'none' && !defined($sigcsr) &&
			!defined($sigold))) {
	get_cert("sig", $sigtype);
	exit;
} else {
	push @hidden, 'sigtype';
	push @hidden, 'sigcsr';
	push @hidden, 'sigold';
}

my $authtype = $q->param('authtype');
my $authcsr = $q->param('authcsr');
my $authold = $q->param('authold');

if(!defined($authtype) || ($authtype ne 'none' && !defined($authcsr) &&
		!defined ($authold))) {
	get_cert("auth", $authtype);
	exit;
} else {
	push @hidden, "authtype";
	push @hidden, "authcsr";
	push @hidden, "authold";
}

my %writefiles = (	"3F00DF014031" => "idfile.asn1",
			"3F00DF014033" => "addressfile.asn1");

my %readfiles = (	"3F00DF014031" => "idfile.asn1",
			"3F00DF014032" => "idsig",
			"3F00DF014033" => "addressfile.asn1",
			"3F00DF014034" => "addrsig",
			"3F00DF005038" => "auth.der",
			"3F00DF005039" => "sign.der",
			"3F00DF00503A" => "ca.der",
			"3F00DF00503B" => "root.der",
			"3F00DF00503C" => "rrn.der");

my $w = XML::SAX::Writer->new();
my $firstfilter = xmlfilter->new({writefiles => \%writefiles});
my $secondfilter = xmlfilter->new({readfiles => \%readfiles});
$secondfilter->set_handler($w);
my $firstparser = XML::SAX::ParserFactory->parser(Handler => $firstfilter);
my $secondparser = XML::SAX::ParserFactory->parser(Handler => $secondfilter);

# Parse the XML file, so we can 
$firstparser->parse_uri("test.foo");

system("~/code/eid-test-ca/resign idfile.asn1 idsig addressfile.asn1 addrsig ~/code/eid-test-ca/test/root.key 2");
print "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
$secondparser->parse_uri("test.foo");

