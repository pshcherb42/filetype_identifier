# Description

This project implements a file type identification tool based on magic numbers instead of relying on file extensions. File extensions can be easily manipulated by users, so they are not a reliable indicator of the actual file type.

# Instructions

Compile using make 
then do:
./filetype ~/Downloads/important_file.pdf

If the file is really a .pdf the program should output something like this

Bytes: 25 50 44 46
~/Downloads/important_file.pdf PDF              application/pdf

Otherwise:

Bytes: (here first 4 bytes)
~/Downloads/important_file.pdf PDF              UNKNOWN

# Future Improvements

<table border="1" cellpadding="8" cellspacing="0">
  <thead>
    <tr>
      <th>Feature</th>
      <th>Description</th>
      <th>Status</th>
    </tr>
  </thead>

  <tbody>
    <tr>
      <td>Scan files inside ZIP</td>
      <td>Parse the Central Directory and analyze each file stored in the archive.</td>
      <td><input type="checkbox"></td>
    </tr>

<tr>
      <td>Recursive archive inspection</td>
      <td>Automatically analyze archives inside other archives (ZIP → ZIP → file).</td>
      <td><input type="checkbox"></td>
    </tr>

<tr>
      <td>Support additional formats</td>
      <td>Add support for more archive formats such as TAR and RAR.</td>
      <td><input type="checkbox"></td>
    </tr>

<tr>
      <td>Entropy analysis</td>
      <td>Detect suspicious files by measuring byte randomness (useful for packed malware).</td>
      <td><input type="checkbox"></td>
    </tr>

<tr>
      <td>Polyglot file detection</td>
      <td>Detect files that are valid in multiple formats (e.g. ZIP + PNG).</td>
      <td><input type="checkbox"></td>
    </tr>
  </tbody>
</table>

# Resources

List of file signatures
https://en.wikipedia.org/wiki/List_of_file_signatures

ZIP (file format)
https://en.wikipedia.org/wiki/ZIP_(file_format)

Executable and Linkable Format
https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

Acceso aleatorio a ficheros
https://www.it.uc3m.es/pbasanta/asng/course_notes/ch09s04.html

Standard Library Documentation
https://cppreference.com

Linux man pages

