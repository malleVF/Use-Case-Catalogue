#!/usr/bin/perl
use strict;
use warnings;
use YAML::XS;
use File::Find;
use File::Basename;

# Set the path to the rules directory
my $rules_path = 'rules';

# Set the output path for Markdown files
my $output_path = 'Detection Rules';

# Ensure the output directory exists
unless (-e $output_path) {
    mkdir $output_path or die "Failed to create output directory: $!";
}

# Find all YAML files in the specified path
my @yaml_files;
find(
    sub {
        push @yaml_files, $File::Find::name if /\.yml$/i;
    },
    $rules_path
);

# Process each YAML file and convert it to Markdown
foreach my $yaml_file (@yaml_files) {
    process_yaml_file($yaml_file);
}

sub process_yaml_file {
    my ($yaml_file) = @_;

    # Read YAML content from file
    open my $yaml_fh, '<', $yaml_file or die "Failed to open $yaml_file: $!";
    my $yaml_content = do { local $/; <$yaml_fh> };
    close $yaml_fh;

    # Load YAML data
    my $data = Load($yaml_content);
	
	my $tags = $data->{tags};
    my $tags_str = ref($tags) eq 'ARRAY' ? join(", ", @$tags) : $tags // "";
	

    # Extract relevant data for frontmatter
    my $title         = $data->{title}         || '';
    my $status        = $data->{status}        || '';
    my $date          = $data->{date}          || '';
    my $modified      = $data->{modified}      || '';
    my $tags          = $tags_str;
	my $logsource     = $data->{logsource}     || {};
    my $product       = $logsource->{product}  || '';
    my $service       = $logsource->{service}  || '';
    my $level         = $data->{level}         || '';
	my $description   = $data->{description}   || '';
	
	$tags =~ s/attack.//g;
	$tags =~ s/\./_/g;
	
    # Create Markdown content
    my $markdown_content = <<"MARKDOWN";
---
title: "$title"
status: "$status"
created: "$date"
last_modified: "$modified"
tags: [$tags, detection_rule]
logsrc_product: "$product"
logsrc_service: "$service"
level: "$level"
---

## $title

### Description

$description

```yml
$yaml_content
```
MARKDOWN

    # Set the output filename
    my $output_file = "$output_path/" . basename($yaml_file, '.yml') . '.md';

    # Write Markdown content to file
    open my $markdown_fh, '>', $output_file or die "Failed to open $output_file for writing: $!";
    print $markdown_fh $markdown_content;
    close $markdown_fh;

    print "Converted $yaml_file to $output_file\n";
}
