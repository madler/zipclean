/* zipclean.c -- clean .zip file directory traversal vulnerabilities
 * Copyright (C) 2023 Mark Adler
 * Version 1.1  12 Aug 2023  Mark Adler
 */

/*
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler
  madler@alumni.caltech.edu
 */

/* Version history:
   1.0  12 Aug 2023  First version
   1.1  12 Aug 2023  Bug fixes and error message clarifications
 */

// Modify the entry names in a zip file in place to remove directory traversal
// vulnerabilities. This operation is destructive, so you may want to make a
// copy of the zip file first. Any leading / is replaced by an _ . Any ..
// components are replaced with __ .

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdnoreturn.h>            // assumes C11
#include <sys/errno.h>

// Zip file structure signatures, lengths, and markers.
#define LOCAL 0x04034b50            // local entry header
#define CENTRAL 0x02014b50          // central directory entry header
#define ZIP64LOC 0x07064b50         // zip64 end record locator
#define ZIP64END 0x06064b50         // zip64 end record
#define END 0x06054b50              // end of central directory record
#define ZLOCLEN 20                  // length of zip64 end record locator
#define ENDLEN 22                   // length of end record
#define MAX16 0xffff                // zip64 indication for number of entries
#define MAX32 0xffffffff            // zip64 indication for length or offset

// Zip file processing and error handling information.
typedef struct {
    char *path;             // zip file path
    FILE *in;               // open zip file for reading and writing
    int fix;                // true to write fixed names
    int mod;                // true if modified
    unsigned char *name;    // allocated name
    unsigned char *repl;    // allocated replacement name
    unsigned char *extra;   // allocated central header extra field
    jmp_buf env;            // longjmp destination for errors
} zip_t;

// Report an error and give up on zip->path. Release resources.
static noreturn void throw(zip_t *zip, char *fmt, ...) {
    fputs("zipclean: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, " %s -- skipping%s\n",
            zip->path, zip->mod ? " (modified)" : "");
    free(zip->extra);
    free(zip->repl);
    free(zip->name);
    if (zip->in != NULL)
        fclose(zip->in);
    longjmp(zip->env, 1);
}

// Return one byte from zip->in. Throw an error if we can't get one.
static inline unsigned get1(zip_t *zip) {
    int ch = getc(zip->in);
    if (ch == EOF) {
        if (ferror(zip->in))
            throw(zip, "read error %s on", strerror(errno));
        else
            throw(zip, "premature EOF on");
    }
    return ch;
}

// Return a little-endian unsigned 16-bit integer from zip->in.
static unsigned get2(zip_t *zip) {
    unsigned val = get1(zip);
    return val + (get1(zip) << 8);
}

// Return a little-endian unsigned 32-bit integer from zip->in.
static uint32_t get4(zip_t *zip) {
    uint32_t val = get2(zip);
    return val + ((uint32_t)get2(zip) << 16);
}

// Return a little-endian unsigned 64-bit integer from zip->in.
static uint64_t get8(zip_t *zip) {
    uint64_t val = get4(zip);
    return val + ((uint64_t)get4(zip) << 32);
}

// Return the current absolute offset in the zip file.
static off_t tell(zip_t *zip) {
    off_t at = ftello(zip->in);
    if (at == -1)
        throw(zip, "could not tell (%s) on", strerror(errno));
    return at;
}

// Move the offset in the zip file by off with base whence. Return the
// resulting absolute offset in the zip file.
static off_t seek(zip_t *zip, off_t off, int whence) {
    int ret = fseeko(zip->in, off, whence);
    if (ret == -1)
        throw(zip, "could not seek (%s) on", strerror(errno));
    return tell(zip);
}

// Return an allocated buffer with len bytes read from the current position.
static unsigned char *load(zip_t *zip, size_t len) {
    if (len == 0)
        return NULL;
    unsigned char *buf = malloc(len);
    if (buf == NULL)
        throw(zip, "out of memory");
    size_t got = fread(buf, 1, len, zip->in);
    if (got != len) {
        free(buf);
        if (ferror(zip->in))
            throw(zip, "read error %s on", strerror(errno));
        else
            throw(zip, "premature EOF on");
    }
    return buf;
}

// Look for the end of central directory record. Leave the file pointer after
// its signature. This reads and scans the file backwards for the end record.
// It will almost always find it in a valid zip file on the first try, once the
// first four bytes have been processed from the buffer. It will only need to
// search if there is a zip file comment, which is rare. If the input is not a
// zip file, this will likely need to read the entire file to find that out.
// But it's pretty fast.
static void zip_end(zip_t *zip) {
    // Set beg and end to the position of the last partial sector. beg will be
    // a multiple of the sector size, end will be the size of the file, and beg
    // will be less than end. If the file is empty, then beg will be the
    // negation of the sector size. Start building the signature back bytes
    // back from the end in the buffer.
    unsigned char buf[512];                 // sector-size buffer
    off_t end = seek(zip, 0, SEEK_END);
    off_t beg = (end - 1) & (~(off_t)(sizeof(buf) - 1));
    off_t back = ENDLEN - 3;

    // Read sectors starting at the end of the file, working backwards,
    // updating the candidate record signature, sig, for each byte.
    uint32_t sig = 0;
    while (beg >= 0) {
        // Read the next sector. The first one may be a partial sector. All
        // reads start at a multiple of the sector size.
        seek(zip, beg, SEEK_SET);
        off_t got = fread(buf, 1, end - beg, zip->in);
        if (got != end - beg) {
            if (ferror(zip->in))
                throw(zip, "read error %s on", strerror(errno));
            else
                // Not really sure how this could happen, but just in case.
                throw(zip, "unexpected EOF on");
        }

        // Build signatures from buf[] starting back from the end, until an end
        // of central directory signature is found.
        for (off_t i = got - back; i >= 0; i--) {
            sig = (sig << 8) + buf[i];
            if (sig == END) {
                // Found it! Set the file pointer to the content of the end
                // record (after the signature) and return.
                seek(zip, beg + i + 4, SEEK_SET);
                return;
            }
        }

        // Not found in that sector. Get the next sector back.
        end = beg;
        beg -= sizeof(buf);
        if (got < back)
            back -= got;
        else
            back = 1;
    }

    // Scanned the entire file, but no joy. If we find one by accident in a
    // non-zip file, then its non-zipness will likely be discovered later.
    throw(zip, "end of central directory record not found in");
}

// Move the file pointer to the start of the central directory, and return the
// number of entries in the directory.
static uint64_t zip_dir(zip_t *zip) {
    // Find the end of central directory record.
    zip_end(zip);

    // Get the number of entries and the offset of the central directory.
    seek(zip, 6, SEEK_CUR);
    uint64_t num = get2(zip);
    seek(zip, 4, SEEK_CUR);
    off_t off = get4(zip);

    if (num == MAX16 || off == MAX32) {
        // Need to get the number and offset from the zip64 end record. Move
        // back to the zip64 end locator record and get the offset of the zip64
        // end record.
        seek(zip, 2 - ENDLEN - ZLOCLEN, SEEK_CUR);
        if (get4(zip) != ZIP64LOC)
            throw(zip, "missing zip64 locator record in");
        seek(zip, 4, SEEK_CUR);
        off = get8(zip);

        // Get the number of entries and central directory offset from the
        // zip64 end record.
        seek(zip, off, SEEK_SET);
        if (get4(zip) != ZIP64END)
            throw(zip, "missing zip64 end record in");
        seek(zip, 28, SEEK_CUR);
        num = get8(zip);
        seek(zip, 8, SEEK_CUR);
        off = get8(zip);
    }

    // Point the input to the start of the central directory and return the
    // number of entries.
    seek(zip, off, SEEK_SET);
    return num;
}

// Fix the name. Return an allocated new name, or NULL if it doesn't need to be
// fixed.
static unsigned char *zip_fix(zip_t *zip, size_t nlen) {
    if (nlen == 0)
        return NULL;
    unsigned char *fix = malloc(nlen);
    if (fix == NULL)
        throw(zip, "out of memory");
    int same = 1;

    // Replace a leading slash with an underscore.
    if (zip->name[0] == '/')
        fix[0] = '_', same = 0;
    else
        fix[0] = zip->name[0];

    // Look for .. down references, replace them with __ .
    int par = fix[0] == '.' ? 2 : 0;    // number of parent characters matched
    for (size_t i = 1; i < nlen; i++) {
        unsigned ch = zip->name[i];
        if (ch == '/')
            par = 1;
        else if (par && ch == '.') {
            par++;
            if (par == 3) {
                // Peek ahead to see if the ".." is at the end or followed by
                // a slash. If so, then this is a down reference. Fix it.
                if (i == nlen - 1 || zip->name[i + 1] == '/') {
                    same = 0;
                    fix[i - 1] = ch = '_';
                }
                else
                    par = 0;
            }
        }
        else
            par = 0;
        fix[i] = ch;
    }

    // Return the new name if fixed, NULL otherwise.
    if (same) {
        free(fix);
        fix = NULL;
    }
    return fix;
}

// Look for a zip64 extended information extra field in the provided extra
// data. Return the offset of the local header. skip is 0, 8, or 16, to skip 0,
// 1, or 2 64-bit lengths in the extra field, which are the compressed and/or
// uncompressed lengths.
static off_t zip64_local(zip_t *zip, size_t xlen, size_t skip) {
    size_t i = 0;
    while (i + 3 < xlen) {
        unsigned id = zip->extra[i] + ((unsigned)zip->extra[i + 1] << 8);
        unsigned len = zip->extra[i + 2] + ((unsigned)zip->extra[i + 3] << 8);
        if (id == 1) {
            if (i + 4 + len > xlen || skip + 8 > len)
                throw(zip, "invalid zip64 info field in");
            i += 4 + skip;
            return zip->extra[i] +
                   ((off_t)zip->extra[i + 1] << 8) +
                   ((off_t)zip->extra[i + 2] << 16) +
                   ((off_t)zip->extra[i + 3] << 24) +
                   ((off_t)zip->extra[i + 4] << 32) +
                   ((off_t)zip->extra[i + 5] << 40) +
                   ((off_t)zip->extra[i + 6] << 48) +
                   ((off_t)zip->extra[i + 7] << 56);
        }
        i += 4 + len;
    }
    throw(zip, "missing zip64 info field in");
}

// Process the entry for the central directory header at the file pointer. Fix
// the file name in the central directory header and in the associated local
// header, if needed. Leave the file pointer after the end of this header.
static void zip_entry(zip_t *zip) {
    // Check that we're at a central directory header.
    if (get4(zip) != CENTRAL)
        throw(zip, "missing central header in");

    // Get the name. Also prepare for finding the local header by getting the
    // tentative offset, and checking the compressed and uncompressed sizes to
    // see how much of zip64 extra data would be skipped to get to a long local
    // header offset.
    seek(zip, 16, SEEK_CUR);
    size_t skip = 8 * ((get4(zip) == MAX32) + (get4(zip) == MAX32));
    unsigned nlen = get2(zip);          // file name length
    unsigned xlen = get2(zip);          // extra field length
    unsigned clen = get2(zip);          // entry comment length
    seek(zip, 8, SEEK_CUR);
    off_t local = get4(zip);            // local entry offset (if not zip64)
    zip->name = load(zip, nlen);
    off_t next = tell(zip) + xlen + clen;

    // See if the name needs to be fixed.
    zip->repl = zip_fix(zip, nlen);
    if (zip->repl != NULL) {
        printf("%s: %.*s -> %.*s\n",
               zip->path, nlen, zip->name, nlen, zip->repl);
        // Replace the name in the central header.
        if (zip->fix) {
            zip->mod = 1;
            seek(zip, -(off_t)nlen, SEEK_CUR);
            size_t writ = fwrite(zip->repl, 1, nlen, zip->in);
            if (writ != nlen)
                throw(zip, "write error %s on", strerror(errno));
        }

        // Go to the local header and verify the signature and name.
        if (local == MAX32) {
            // Need to get the local header offset from the extra field.
            zip->extra = load(zip, xlen);
            local = zip64_local(zip, xlen, skip);
            free(zip->extra);
            zip->extra = NULL;
        }
        seek(zip, local, SEEK_SET);
        if (get4(zip) != LOCAL)
            throw(zip, "missing local header in");
        seek(zip, 22, SEEK_CUR);
        if (get2(zip) != nlen)
            throw(zip, "local/central name mismatch in");
        seek(zip, 2, SEEK_CUR);
        unsigned char *name = load(zip, nlen);
        int diff = memcmp(zip->name, name, nlen);
        free(name);
        if (diff)
            throw(zip, "local/central name mismatch in");

        // Replace the name in the local header.
        if (zip->fix) {
            seek(zip, -(off_t)nlen, SEEK_CUR);
            size_t writ = fwrite(zip->repl, 1, nlen, zip->in);
            if (writ != nlen)
                throw(zip, "write error %s on", strerror(errno));
        }
        free(zip->repl);
        zip->repl = NULL;
    }
    free(zip->name);
    zip->name = NULL;
    seek(zip, next, SEEK_SET);
}

// Clean the zip file path. If fix is zero, then report changes that would be
// made, but don't make them.
static void zip_clean(char *path, int fix) {
    // Open the zip file.
    zip_t zip_s = {0}, *zip = &zip_s;
    zip->path = path;
    zip->in = fopen(path, fix ? "r+b" : "rb");
    zip->fix = fix;
    zip->mod = 0;
    if (setjmp(zip->env))               // prepare for throw()
        return;
    if (zip->in == NULL)
        throw(zip, "failed to open%s", fix ? " (for writing)" : "");

    // Find the central directory and then fix the name of each entry as
    // needed and requested.
    uint64_t n = zip_dir(zip);
    while (n) {
        zip_entry(zip);
        n--;
    }
    fclose(zip->in);
}

// Process all of the zip files on the command line, fixing them if the -f
// option is given. By default, the files are untouched, and changes that would
// be made are only reported. If the -- option is given, subsequent file names
// can start with a dash, and won't be treated as invalid options.
int main(int argc, char **argv) {
    // Process options.
    int fix = 0, opt = INT_MAX;
    for (int i = 1; i < argc; i++)
        if (argv[i][0] == '-') {
            if (strcmp(argv[i] + 1, "f") == 0)
                fix = 1;
            else if (strcmp(argv[i] + 1, "-") == 0) {
                opt = i;
                break;
            }
            else {
                fprintf(stderr, "unknown option %s\n", argv[i]);
                return 1;
            }
        }

    // Process files.
    for (int i = 1; i < argc; i++)
        if (argv[i][0] != '-' || i > opt)
            zip_clean(argv[i], fix);
    return 0;
}
