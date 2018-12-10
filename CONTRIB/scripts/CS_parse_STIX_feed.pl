#!/usr/bin/perl
use strict;
use warnings;

$|++;

if (not defined $ARGV[0]) {
	print "Usage: parse.pl [stix:Title|any] < INPUT_STIX_FILE\n";
	print "Questo script stampa in forma tabellare gli indicatori STIX ricevuti dalla rete Info Sharing di Cyber Saiyan\n\n";
	print "Nel caso in cui l'argomento sia:\n";
	print "- uno stix:Title (es. \"Gootkit\"), saranno stampati solo gli indicatori per la specifica minaccia\n";
	print "- la parola any, saranno stampati tutti gli indicatori trovati nel file STIX passato come input\n\n";
	print "Esempio\n";
	print '~$ taxii-poll --host infosharing.cybersaiyan.it --https --collection CS-COMMUNITY-TAXII --discovery /taxii-discovery-service > full.list';
	print "\n";
	print '~$ perl parse.pl any < full.list';
	print "\n\n";
	exit(1);
}
my $stix_title_search = $ARGV[0];

my %hash;

my $line;
my $stix_title;
my $stix_short_description;
my $indicator_title;

print "\n";
print "SEARCH FOR THREAT: ".$stix_title_search."\n";
print "----------------------------------------------------------------------------------------------------------------------\n";
if ( $stix_title_search eq "any" ) {
	my $out = sprintf "%-45s %-22s %-s\n", "THREAT NAME", "SENDING DATE", "INDICATOR";
	print $out;
} else {
	my $out = sprintf "%-22s %-s\n", "SENDING DATE", "INDICATOR";
	print $out;
}
print "----------------------------------------------------------------------------------------------------------------------\n";

foreach $line (<STDIN>) {  # parse linea per linea
	chomp($line); #rimuovo \n\r alla fine della riga
	if ( $line =~ /^<stix:STIX_Package/ ) {
		#reset delle var
		$stix_title = '';
		$stix_short_description = '';
		$indicator_title = '';
	}
	if ( $line =~ /<stix:Title>(.*)<\/stix:Title>/ ) {
		#print "DBG: $line\n";
		$stix_title = $1;
	}
	if ( $line =~ /<stix:Short_Description>(.*)<\/stix:Short_Description>/ ) {
		#print "DBG: $line\n";
		$stix_short_description = $1;
	}
	if ( $line =~ /<cybox:Title>(.*)<\/cybox:Title>/ ) {
		#print "DBG: $line\n";
		$indicator_title = $1;
	}
	if ( $line =~ /^<\/stix:STIX_Package/ ) {
		if ($stix_title eq $stix_title_search) {
			my $out = sprintf "%-22s %-s\n", $stix_short_description, $indicator_title;
			print $out;
		} elsif ( $stix_title_search eq "any" ) {
			my $stix_title_limited = $stix_title;
			if ( length($stix_title)>43) {
				$stix_title_limited = substr($stix_title, 0, 40)."...";
			}
			my $out = sprintf "%-45s %-22s %-s\n", $stix_title_limited, $stix_short_description, $indicator_title;
			print $out;
		}
	}
}

print "----------------------------------------------------------------------------------------------------------------------\n";
exit 0;
