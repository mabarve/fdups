#!/usr/bin/env python3

import  getopt, sys

# Settings local to the script

# Debug Levels:
CLDBG_SNGL =  0 # Only print number of failed test cases otherwise 0 on success
CLDBG_SUM  =  1 # Print summary of test cases (total, success, failed)
CLDBG_BFL  =  2 # Print brief info on failures
CLDBG_DFL  =  3 # Print detailed info on failures
CLDBG_DSU  =  4 # Print details on successful cases
CLDBG_EXE  =  5 # Details on test execution
CLDBG_VER1  = 6 # Details' verbosity level-1

__def_debug      = CLDBG_SNGL # Default debug level
__def_verbose    = CLDBG_DSU  # Default debug level

def usage(progname) :
    print(progname + " [options]\n\n")

    print("[(-d | --debug) <debuglevel>]\t(default=%d). " % __def_debug)
    print("\t\t\t\tdebug level: higher value prints more info.\n")
    print("[(-D | --dir) <directory>]\tBase directory for file search. (default=\'./\')")
    print("-h\t\t\t\tThis help message.")
    print("--help\t\t\t\tMore extensive help message.")
    print("\n\n")
    print("[-v | --verbose]\t\t(default=%d)" % __def_verbose)

    # usage() ends

def process_input():

    '''Entry level function for unit testing this script file.
    '''

    try:
        opts, args = getopt.getopt(
                        sys.argv[1:], "d:D:hv",
                        ["debug=", "dir=", "help", "verbose"])

    except getopt.GetoptError as input_err:
        print(input_err)
        usage(sys.argv[0])
        sys.exit(2)

    debug = __def_debug
    basedir = "./"

    for arg, argval in opts:
        if arg in ("-d", "--debug") :
            debug = int(argval)
        elif arg in ("-D", "--dir") :
            basedir = str(argval)
        elif arg in ("-h", "--help") :
            usage(sys.argv[0])
            sys.exit()
        elif arg in ("-v", "--verbose") :
            debug = __def_verbose
        else:
            assert False, "unknown option %s" % arg
    # end-for

    inargs = {}
    inargs['debug'] = debug
    inargs['basedir'] = basedir
    inargs['errno'] = 0
    return inargs


#############################################################################################
#############################################################################################
#############################################################################################


def main():

    inargs = process_input()
    debug = inargs['debug']

    return 0

if __name__ == "__main__" :
    failed = main()
    if (failed) : print(failed)
