
# Welcome

This is the **prototype** of a SIEM (Security Information & Event Management) Use Case Catalogue in Obsidian vault. 

A quick and dirty developed solution. 

My motivation: A proof of value to demonstrate how easy it is to create SIEM use case documentation using only open source tools:
- MITRE ATT&CK: [http://attack.mitre.org/resources/working-with-attack/](http://attack.mitre.org/resources/working-with-attack/)
- SIGMA: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- Atomic Red Team: ([https://github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
- Obsidian.md: https://obsidian.md/

The Use Cases are an abstract of the MITRE ATT&CK Enterprise techniques.
The Detection Rules are from SIGMA.
The Testing Runbooks (Chapter "Rule Testing") are from Atomic Red Team.

Table of content of the Use Cases:

- **Description**
- **Detection**
- **Defenses Bypassed**
- **Data Sources**
- **Detection Rules** (from SIGMA)
- **Rule Testing**  (from Atomic Red Team)

>[! quote] Hint
>The Excel Sheet **UseCases.xlsx** (see `.bin/files`) includes all necessary data and in addition from  [VERIS](https://verisframework.org/) as well and can be used stand-alone, without any additional scripts. 
>>[! warning] The contents of the Excel table do not match the data in Obsidian, as some of the data records used here are not up-to-date.
>
>The following scripts are not required for the Obsidian vault and only for documentation purpose.

Perl scripts have been written with ChatGPT partially:

The `generate_use_cases_v3.pl` script requires the csv file **UseCases.csv** (see `.bin/files`). It is an export of the Excel-Sheet from Mitre Attack model, enriched with some data from other sources, like SIGMA and Atomic Red Team. 

The `generate_md_from_yml_v4.pl` makes Markdown files from the yaml files and requires the **rules** folder from the SIGMA repository. 

The `alter_atomics_md_files_v1.pl` adds frontmatter date on top of each markdown file of the Atomic Red Team repository and requires the **atomics** folder.

## How to ...

The installation is quite simple:
1. Download, install and open Obsidian. Start from here: https://obsidian.md/download
2. Download and extract the repository.
3. Add vault to Obsidian by choosing "Open folder as vault" and navigate to the extracted file.
4. Wait for indexing all the files and open the folder "Use Cases".








