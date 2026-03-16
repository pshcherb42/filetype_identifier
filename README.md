# Description

This project implements a file type identification tool based on magic numbers, instead of relying on file extensions. The operating system may display the file as a PDF, but the actual binary format is still an executable. Because of this, security tools such as antivirus software, forensic analyzers, and malware sandboxes rely on detecting file types through their binary signatures. The goal of this project is to implement a lightweight C program that identifies file types by analyzing the binary structure of the file.

# Instructions

Compile using make 
./filetype ~/Downloads/important_file.pdf

If the file is really a .pdf the program should output something like this

Bytes: 25 50 44 46
~/Downloads/important_file.pdf PDF              application/pdf

Otherwise:

Bytes: (here first 4 bytes)
~/Downloads/important_file.pdf PDF              UNKNOWN

# Possible improvements

Future improvements will include:
	•	scanning files inside ZIP archives
	•	recursive archive inspection
	•	support for additional formats (TAR, RAR)
	•	entropy analysis for malware detection
	•	polyglot file detection