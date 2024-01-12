#!/usr/bin/perl

use strict;
use warnings;
use File::Find::Rule;
use File::Path qw(remove_tree make_path);
use File::Spec;

# Specify the root folder
my $root_folder = "atomics";
my $output_folder = "Testing Runbooks";

# Ensure the output folder exists or create it
make_path($output_folder);

# Find all Markdown files in subfolders
my @files = File::Find::Rule->file()->name('*.md')->in($root_folder);

foreach my $file_path (@files) {
    # Extract the filename and check the condition
    my ($filename) = $file_path =~ /([^\\\/]+)\.md$/;
    next unless $filename =~ /^T\d{3,}/;

    # Read the content of the Markdown file
    open my $fh, '<:raw', $file_path or do {
        warn "Cannot open file $file_path: $!";
        next;
    };
    my @lines = <$fh>;
    close $fh;

    # Extract the headline from the first line
    my ($headline) = $lines[0] =~ /^\s*#\s*(.*)/;
    $headline ||= "Untitled";  # Default value if no headline found
	my$fileheadline=$headline;
	$fileheadline =~ s/:/-/g;

    # Remove lines until '## Atomic Test #1' is found
    @lines = remove_lines_before_atomic_test(@lines);

    # Extract the filename and the first line of text
    $filename =~ s/\./_/g;

    # Build the frontmatter
    my $frontmatter = "---\n";
    $frontmatter .= "tags: [$filename, atomic_test]\n";
    $frontmatter .= "filename: \"[[$fileheadline]]\"\n";
    $frontmatter .= "---\n";
	$frontmatter .= "# $headline\n\n";

    # Add frontmatter to the beginning of the file
    unshift @lines, $frontmatter;

    # Create the output path in the new folder
    my $output_path = File::Spec->catfile($output_folder, $fileheadline . ".md");

    # Write the modified content to the new file
    open $fh, '>:raw', $output_path or do {
        warn "Cannot open file $output_path for writing: $!";
        next;
    };
    print $fh @lines;
    close $fh;

    print "Frontmatter added to $file_path, written to $output_path\n";
}

# Function to remove lines until '## Atomic Test #1' is found
sub remove_lines_before_atomic_test {
    my @lines = @_;

    # Find the index of the line that starts with '## Atomic Test #1'
    my $start_index = 0;
    while ($start_index < @lines && $lines[$start_index] !~ /^\s*## Atomic Test #1/) {
        $start_index++;
    }

    # Remove the lines before '## Atomic Test #1'
    splice @lines, 0, $start_index;

    return @lines;
}

# Function to remove folders with the name "src" and "run" and their contents
sub remove_folders {
    my ($root, @folders) = @_;

    foreach my $folder (@folders) {
        my @found_folders = File::Find::Rule->directory()->name($folder)->in($root);
        foreach my $found_folder (@found_folders) {
            remove_tree($found_folder);
            print "Removed folder: $found_folder\n";
        }
    }
}

# Remove "src" and "run" folders and their contents
remove_folders($root_folder, 'src', 'run');
