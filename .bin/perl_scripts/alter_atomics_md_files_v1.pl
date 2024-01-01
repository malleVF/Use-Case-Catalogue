#!/usr/bin/perl

use strict;
use warnings;
use File::Find::Rule;

# Specify the root folder
my $root_folder = "atomics";

# Find all Markdown files in subfolders
my @files = File::Find::Rule->file()->name('*.md')->in($root_folder);

foreach my $file_path (@files) {
    # Read the content of the Markdown file
    open my $fh, '<', $file_path or do {
        warn "Cannot open file $file_path: $!";
        next;
    };
    my @lines = <$fh>;
    close $fh;

    # Extract the filename and the first line of text
    my ($filename) = $file_path =~ /([^\\\/]+)\.md$/;
    my ($first_line) = $lines[0] =~ /^\s*#\s*(.*)/;
	my $file = $filename;
	$filename =~ s/\./_/g;
    # Build the frontmatter
    my $frontmatter = "---\n";
    $frontmatter .= "tags: [$filename, atomic_test]\n";
    $frontmatter .= "filename: \"[[$file|$first_line]]\"\n";
    $frontmatter .= "---\n\n";

    # Add frontmatter to the beginning of the file
    unshift @lines, $frontmatter;

    # Write the modified content back to the file
    open $fh, '>', $file_path or do {
        warn "Cannot open file $file_path for writing: $!";
        next;
    };
    print $fh @lines;
    close $fh;

    print "Frontmatter added to $file_path\n";
}
