/*
 *  compat_getopt.c - my re-implementation of getopt.
 *  Copyright 1997, 2000, 2001, 2002, 2006, 2008, Benjamin C. Wiley Sittler
 *
 *  Permission is hereby granted, free of charge, to any person
 *  obtaining a copy of this software and associated documentation
 *  files (the "Software"), to deal in the Software without
 *  restriction, including without limitation the rights to use, copy,
 *  modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be
 *  included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef HAVE_GETOPT_LONG

/* HAVE_SYS_TYPES_H: do we have <sys/types.h>? */

#ifndef HAVE_SYS_TYPES_H
#ifndef macintosh
#ifndef __PACIFIC__
#ifndef AZTEC
#ifndef __EFI__
#define HAVE_SYS_TYPES_H 1
#endif
#endif
#endif
#endif
#endif

#ifndef HAVE_SYS_TYPES_H
#define HAVE_SYS_TYPES_H 0
#endif

#ifdef macintosh
#include <Types.h>
#else
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "compat-getopt.h"

int compat_getopt_optind=1, compat_getopt_opterr=1, compat_getopt_optopt=0, compat_getopt_optreset=0;
char *compat_getopt_optarg=0;

/* reset argument parser to start-up values */
int compat_getoptreset(void)
{
    compat_getopt_optreset = 1;
    return 0;
}

/* this is the plain old UNIX getopt, with GNU-style extensions. */
/* if you're porting some piece of UNIX software, this is all you need. */
/* this supports GNU-style permution and optional arguments */

int compat_getopt(int argc, char * argv[], const char *opts)
{
    static int charind=0;
    const char *s;
    char mode, colon_mode;
    int off = 0, opt = -1;

    if (compat_getopt_optreset)
    {
        compat_getopt_optind = 1;
        compat_getopt_opterr = 1;
        compat_getopt_optopt = 0;
        compat_getopt_optarg = 0;
        compat_getopt_optreset = 0;
    }
    if(getenv("POSIXLY_CORRECT")) colon_mode = mode = '+';
    else {
        if((colon_mode = *opts) == ':') off ++;
        if(((mode = opts[off]) == '+') || (mode == '-')) {
            off++;
            if((colon_mode != ':') && ((colon_mode = opts[off]) == ':'))
                off ++;
        }
    }
    compat_getopt_optarg = 0;
    if(charind) {
        compat_getopt_optopt = argv[compat_getopt_optind][charind];
        for(s=opts+off; *s; s++) if(compat_getopt_optopt == *s) {
            charind++;
            if((*(++s) == ':') || ((compat_getopt_optopt == 'W') && (*s == ';'))) {
                if(argv[compat_getopt_optind][charind]) {
                    compat_getopt_optarg = &(argv[compat_getopt_optind++][charind]);
                    charind = 0;
                } else if(*(++s) != ':') {
                    charind = 0;
                    if(++compat_getopt_optind >= argc) {
                        if(compat_getopt_opterr) fprintf(stderr,
                                              "%s: option requires an argument -- %c\n",
                                              argv[0], compat_getopt_optopt);
                        opt = (colon_mode == ':') ? ':' : '?';
                        goto compat_getoptok;
                    }
                    compat_getopt_optarg = argv[compat_getopt_optind++];
                }
            }
            opt = compat_getopt_optopt;
            goto compat_getoptok;
        }
        if(compat_getopt_opterr) fprintf(stderr,
                              "%s: illegal option -- %c\n",
                              argv[0], compat_getopt_optopt);
        opt = '?';
        if(argv[compat_getopt_optind][++charind] == '\0') {
            compat_getopt_optind++;
            charind = 0;
        }
      compat_getoptok:
        if(charind && ! argv[compat_getopt_optind][charind]) {
            compat_getopt_optind++;
            charind = 0;
        }
    } else if((compat_getopt_optind >= argc) ||
              ((argv[compat_getopt_optind][0] == '-') &&
               (argv[compat_getopt_optind][1] == '-') &&
               (argv[compat_getopt_optind][2] == '\0'))) {
        compat_getopt_optind++;
        opt = -1;
    } else if((argv[compat_getopt_optind][0] != '-') ||
              (argv[compat_getopt_optind][1] == '\0')) {
        char *tmp;
        int i, j, k;

        if(mode == '+') opt = -1;
        else if(mode == '-') {
            compat_getopt_optarg = argv[compat_getopt_optind++];
            charind = 0;
            opt = 1;
        } else {
            for(i=j=compat_getopt_optind; i<argc; i++) if((argv[i][0] == '-') &&
                                               (argv[i][1] != '\0')) {
                compat_getopt_optind=i;
                opt=compat_getopt(argc, argv, opts);
                while(i > j) {
                    tmp=argv[--i];
                    for(k=i; k+1<compat_getopt_optind; k++) argv[k]=argv[k+1];
                    argv[--compat_getopt_optind]=tmp;
                }
                break;
            }
            if(i == argc) opt = -1;
        }
    } else {
        charind++;
        opt = compat_getopt(argc, argv, opts);
    }
    if (compat_getopt_optind > argc) compat_getopt_optind = argc;
    return opt;
}

/* this is the extended getopt_long{,_only}, with some GNU-like
 * extensions. Implements _getopt_internal in case any programs
 * expecting GNU libc getopt call it.
 */

int _compat_getoptinternal(int argc, char * argv[], const char *shortopts,
                       const struct compat_getopt_option *longopts, int *longind,
                       int long_only)
{
    char mode, colon_mode = *shortopts;
    int shortoff = 0, opt = -1;

    if (compat_getopt_optreset)
    {
        compat_getopt_optind = 1;
        compat_getopt_opterr = 1;
        compat_getopt_optopt = 0;
        compat_getopt_optarg = 0;
        compat_getopt_optreset = 0;
    }
    if(getenv("POSIXLY_CORRECT")) colon_mode = mode = '+';
    else {
        if((colon_mode = *shortopts) == ':') shortoff ++;
        if(((mode = shortopts[shortoff]) == '+') || (mode == '-')) {
            shortoff++;
            if((colon_mode != ':') && ((colon_mode = shortopts[shortoff]) == ':'))
                shortoff ++;
        }
    }
    compat_getopt_optarg = 0;
    if((compat_getopt_optind >= argc) ||
       ((argv[compat_getopt_optind][0] == '-') &&
        (argv[compat_getopt_optind][1] == '-') &&
        (argv[compat_getopt_optind][2] == '\0'))) {
        compat_getopt_optind++;
        opt = -1;
    } else if((argv[compat_getopt_optind][0] != '-') ||
              (argv[compat_getopt_optind][1] == '\0')) {
        char *tmp;
        int i, j, k;

        opt = -1;
        if(mode == '+') return -1;
        else if(mode == '-') {
            compat_getopt_optarg = argv[compat_getopt_optind++];
            return 1;
        }
        for(i=j=compat_getopt_optind; i<argc; i++) if((argv[i][0] == '-') &&
                                           (argv[i][1] != '\0')) {
            compat_getopt_optind=i;
            opt=_compat_getoptinternal(argc, argv, shortopts,
                                   longopts, longind,
                                   long_only);
            while(i > j) {
                tmp=argv[--i];
                for(k=i; k+1<compat_getopt_optind; k++)
                    argv[k]=argv[k+1];
                argv[--compat_getopt_optind]=tmp;
            }
            break;
        }
    } else if((!long_only) && (argv[compat_getopt_optind][1] != '-'))
        opt = compat_getopt(argc, argv, shortopts);
    else {
        int charind, offset;
        int found = 0, ind, hits = 0;

        if(((compat_getopt_optopt = argv[compat_getopt_optind][1]) != '-') && ! argv[compat_getopt_optind][2]) {
            int c;

            ind = shortoff;
            while (1)
            {
                c = shortopts[ind++];
                if (! c) break;
                if(((shortopts[ind] == ':') ||
                    ((c == 'W') && (shortopts[ind] == ';'))) &&
                   (shortopts[++ind] == ':'))
                    ind ++;
                if(compat_getopt_optopt == c) return compat_getopt(argc, argv, shortopts);
            }
        }
        offset = 2 - (argv[compat_getopt_optind][1] != '-');
        for(charind = offset;
            (argv[compat_getopt_optind][charind] != '\0') &&
                (argv[compat_getopt_optind][charind] != '=');
            charind++)
        {
        }
        for(ind = 0; longopts[ind].name && !hits; ind++)
            if((strlen(longopts[ind].name) == (size_t) (charind - offset)) &&
               (strncmp(longopts[ind].name,
                        argv[compat_getopt_optind] + offset, charind - offset) == 0))
                found = ind, hits++;
        if(!hits) for(ind = 0; longopts[ind].name; ind++)
            if(strncmp(longopts[ind].name,
                       argv[compat_getopt_optind] + offset, charind - offset) == 0)
                found = ind, hits++;
        if(hits == 1) {
            opt = 0;

            if(argv[compat_getopt_optind][charind] == '=') {
                if(longopts[found].has_arg == 0) {
                    opt = '?';
                    if(compat_getopt_opterr) fprintf(stderr,
                                          "%s: option `--%s' doesn't allow an argument\n",
                                          argv[0], longopts[found].name);
                } else {
                    compat_getopt_optarg = argv[compat_getopt_optind] + ++charind;
                    charind = 0;
                }
            } else if(longopts[found].has_arg == 1) {
                if(++compat_getopt_optind >= argc) {
                    opt = (colon_mode == ':') ? ':' : '?';
                    if(compat_getopt_opterr) fprintf(stderr,
                                          "%s: option `--%s' requires an argument\n",
                                          argv[0], longopts[found].name);
                } else compat_getopt_optarg = argv[compat_getopt_optind];
            }
            if(!opt) {
                if (longind) *longind = found;
                if(!longopts[found].flag) opt = longopts[found].val;
                else *(longopts[found].flag) = longopts[found].val;
            }
            compat_getopt_optind++;
        } else if(!hits) {
            if(offset == 1) opt = compat_getopt(argc, argv, shortopts);
            else {
                opt = '?';
                if(compat_getopt_opterr) fprintf(stderr,
                                      "%s: unrecognized option `%s'\n",
                                      argv[0], argv[compat_getopt_optind++]);
            }
        } else {
            opt = '?';
            if(compat_getopt_opterr) fprintf(stderr,
                                  "%s: option `%s' is ambiguous\n",
                                  argv[0], argv[compat_getopt_optind++]);
        }
    }
    if (compat_getopt_optind > argc) compat_getopt_optind = argc;
    return opt;
}

int compat_getopt_getopt_long(int argc, char * argv[], const char *shortopts,
                  const struct compat_getopt_option *longopts, int *longind)
{
    return _compat_getoptinternal(argc, argv, shortopts, longopts, longind, 0);
}

int compat_getopt_getopt_long_only(int argc, char * argv[], const char *shortopts,
                       const struct compat_getopt_option *longopts, int *longind)
{
    return _compat_getoptinternal(argc, argv, shortopts, longopts, longind, 1);
}
#else
typedef int make_iso_compilers_happy;
#endif
