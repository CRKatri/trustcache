TRUSTCACHE(1)               General Commands Manual              TRUSTCACHE(1)

NAME
     trustcache – Create and interact with trustcaches

SYNOPSIS
     trustcache append [-f flags] [-u uuid | 0] infile file ...
     trustcache create [-u uuid] [-v version] outfile file ...
     trustcache info [-c] [-h] [-e entrynum] file
     trustcache remove [-k] file hash ...

DESCRIPTION
     The trustcache utility is used to get info about and modify Apple
     trustcaches.

     The following commands are supported by trustcache:

     append [-f flags] [-u uuid | 0] infile file ...
             Modify the trustcache at infile to include each signed Mach-O at
             the specified paths.  If file is both 40 characters and
             hexadecimal, that hash will be added to the cache.  uuid is used
             to specify a custom uuid to be used.  If it is 0, the uuid will
             be left the same, otherwise, it will be regenerated.  If -f is
             specified, any new entries with have the flags specified at
             flags.

     create [-u uuid] [-v version] outfile file ...
             Create a trustcache at outfile.  Each Mach-O found in the
             specified inputs will be scanned for a code signature and hashed.
             Any malformed or unsigned Mach-O will be ignored.  Each slice of
             a FAT binary will have its hash included.  Versions 0, 1, and 2
             are supported, if not specified, 1 is assumed.  If uuid is
             specified, that will be used instead of a randomly generated one.

     info [-c] [-h] [-e entrynum] file
             Print information about file.  The output for each hash will be
             in one of these formats:

                   <cdhash> <flags> [<hash_type>]
                   <cdhash> <flags> [<hash_type>] [<category>]

             If the -c is given, only the hashes will be printed.  If -h is
             given, only the header will be printed.  If entrynum is
             specified, only that entry will be printed.

     remove [-k] file hash ...
             Remove each specified hash from file.  If -k is specified, the
             uuid will not be regenerated.  The number of removed entries will
             be printed.

EXIT STATUS
     The trustcache utility exits 0 on success, and >0 if an error occurs.

SEE ALSO
     cryptex-dump-trust-cache(1), cryptex-generate-trust-cache(1)

HISTORY
     The trustcache utility was written by Cameron Katri
     <me@cameronkatri.com>.

FreeBSD 14.0-CURRENT             June 16, 2022            FreeBSD 14.0-CURRENT
