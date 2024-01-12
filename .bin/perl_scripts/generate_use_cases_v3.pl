#!/usr/bin/perl

use strict;
use warnings;
use Text::CSV;
use Time::Piece;

# Input CSV file
my $csv_file = 'UseCases.csv';

# Output directory
my $output_dir = 'Use Cases';

# Create output directory if it doesn't exist
unless (-e $output_dir) {
    mkdir $output_dir or die "Unable to create output directory: $!";
}

# Create CSV parser
my $csv = Text::CSV->new({
    sep_char => ';',
    binary   => 1,
    auto_diag => 1,
});

# Open and read CSV file
open my $fh, '<', $csv_file or die "Could not open '$csv_file': $!";

# Skip header row
$csv->getline($fh);

while (my $row = $csv->getline($fh)) {
    my ($ID, $STIX_ID, $name, $description, $url, $created, $last_modified, $domain, $version, $tactics, $detection, $platforms, $data_sources, $is_sub_technique, $sub_technique_of, $defenses_bypassed, $contributors, $permissions_required, $supports_remote, $system_requirements, $impact_type, $effective_permissions, $relationship_citations, $Sigma, $Mitigation, $RedTeamTesting) = @$row;

    # Convert dates to YYYY-MM-DD format using Time::Piece
    $created = convert_date($created);
    $last_modified = convert_date($last_modified);

	# Replace colons with underscores in the name
	$name =~ s/:/-/g;
	$name =~ s/\//_/g;
    # Prepare output filename
    my $output_file = "$output_dir/$ID - $name.md";

    # Create and write to markdown file
    open my $md_fh, '>', $output_file or die "Could not open '$output_file' for writing: $!";
    print $md_fh "---\n";
    print $md_fh "created: $created\n";
    print $md_fh "last_modified: $last_modified\n";
    print $md_fh "version: $version\n";
    print $md_fh "tactics: $tactics\n";
    print $md_fh "url: $url\n";
    print $md_fh "platforms: $platforms\n";
	my $IDorg = $ID;
	$ID =~ s/\./_/g;
	$tactics =~ s/\ /_/g;	
    print $md_fh "tags: [$ID, techniques, $tactics]\n";
    print $md_fh "---\n\n";

    # Write body of markdown
    print $md_fh "## $name\n\n";
    print $md_fh "### Description\n\n$description\n\n";
    print $md_fh "### Detection\n\n$detection\n\n";
    print $md_fh "### Defenses Bypassed\n\n$defenses_bypassed\n\n";
	
	# Write Data Sources on separate lines
	print $md_fh "### Data Sources\n\n";
	my @data_sources_list = split /,/, $data_sources;
	foreach my $source (@data_sources_list) {
		print $md_fh "  - $source\n";
	}

	print $md_fh "### Detection Rule\n\n";

print $md_fh <<EOF1;
```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #$ID
```
EOF1

	
	# Write Testing
	print $md_fh "\n### Rule Testing\n\n";

print $md_fh <<EOF2;
```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #$ID
```
EOF2



    close $md_fh;
}

close $fh;

sub convert_date {
    my ($date_str) = @_;
    my $t = Time::Piece->strptime($date_str, '%d %B %Y');
    return $t->strftime('%Y-%m-%d');
}
