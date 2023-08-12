Synopsis
--------

_zipclean_ is a utility to clean zip file directory traversal vulnerabilities.

Motivation
----------

zip files can be created with leading slashes and parent directory (..)
references. Extracting such files to the named locations is a security risk.
Older, still extant, versions of unzip (before 5.50) do not properly handle
such names. This utility can be used to fix such zip files by changing
any leading slashes to underscores, and parent references to two underscores.

Usage
------------

Compile to an executable. Run as:

    zipclean foo.zip
    zipclean -f foo.zip

where the first one will show what names would be changed in foo.zip without
modifying the file, and the second one will make the modifications in place.

License
-------

This code is under the zlib license, found in the source file and LICENSE.
