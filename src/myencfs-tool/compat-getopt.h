/*
 *  mygetopt.h - interface to my re-implementation of getopt.
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

#ifndef COMPAT_GETOPT_H_INCLUDED
#define COMPAT_GETOPT_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#ifdef COMPAT_GETOPT_APPLY
#define getopt_long compat_getopt_getopt_long
#define long_options compat_getopt_long_options
#define optarg compat_getopt_optarg
#define opterr compat_getopt_opterr
#define optind compat_getopt_optind
#define option compat_getopt_option
#define optopt compat_getopt_optopt
#define optreset compat_getopt_optreset
#endif

/* reset argument parser to start-up values */
extern int compat_getoptreset(void);

/* UNIX-style short-argument parser */
extern int compat_getopt(int argc, char * argv[], const char *opts);

extern int compat_getopt_optind, compat_getopt_opterr, compat_getopt_optopt, compat_getopt_optreset;
extern char *compat_getopt_optarg;

struct compat_getopt_option {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

/* human-readable values for has_arg */
#undef no_argument
#define no_argument 0
#undef required_argument
#define required_argument 1
#undef optional_argument
#define optional_argument 2

/* GNU-style long-argument parsers */
extern int compat_getopt_getopt_long(int argc, char * argv[], const char *shortopts,
                       const struct compat_getopt_option *longopts, int *longind);

extern int compat_getopt_getopt_long_only(int argc, char * argv[], const char *shortopts,
                            const struct compat_getopt_option *longopts, int *longind);

extern int _compat_getopt_getopt_long_internal(int argc, char * argv[], const char *shortopts,
                            const struct compat_getopt_option *longopts, int *longind,
                            int long_only);

#ifdef __cplusplus
}
#endif

#endif /* COMPAT_GETOPT_H_INCLUDED */
