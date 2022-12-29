#!/usr/bin/env python3

import getopt, hashlib, os, re, sys

# Settings local to the script

# Debug Levels:
CLDBG_SNGL =  0 # Only print number of failed test cases otherwise 0 on success
CLDBG_SUM  =  1 # Print summary of test cases (total, success, failed)
CLDBG_BFL  =  2 # Print brief info on failures
CLDBG_DFL  =  3 # Print detailed info on failures
CLDBG_DSU  =  4 # Print details on successful cases
CLDBG_EXE  =  5 # Details on test execution
CLDBG_VER1  = 6 # Details' verbosity level-1

__def_debug      = CLDBG_BFL # Default debug level
__def_verbose    = CLDBG_DSU  # Default debug level
__def_hash_algo  = "sha1" # Default file hashing algorithm

def usage(progname, basedir) :
    print(progname + " [options]\n\n")

    print("[(-d | --debug) <debuglevel>]\t(default=%d). " % __def_debug)
    print("\t\t\t\tdebug level: higher value prints more info.\n")
    print("[(-D | --dir) <directory>]\tBase directory for file search."
          "\n\t\t\t\t(default is $PWD i.e., \'%s')\n" %
          basedir)

    print("[(-R | --refdir) <directory>]\tReference directory for file search. "
          "Search for duplicates is restricted to\n\t\t\t\tfiles within this tree or"
          " the files from the base directory that are also\n\t\t\t\tpresent in the"
          " reference directory. Files within the base directory that are " 
          "\n\t\t\t\tduplicates of each other but are missing from the reference are NOT "
          " reported.\n\t\t\t\tThis feature is deemed useful before merging a new reference "
          " directory content\n\t\t\t\twith the existing, large base directory.\n")
          
    print("[(-H | --hash) <algorith>]\tHash algorithm (md5/ sha1/ sha256)"
          "\n\t\t\t\t(default is '%s')\n" % (__def_hash_algo))

    print("-h\t\t\t\tThis help message.\n")
    print("--help\t\t\t\tMore extensive help message.\n")
    print("[-v | --verbose]\t\t(default=%d)" % __def_verbose)
    print("\n")

    # usage() ends

def process_input():
    '''Entry level function for unit testing this script file.
    '''

    basedir = os.getcwd()

    try:
        opts, args = getopt.getopt(
                        sys.argv[1:], "d:D:hH:R:v",
                        ["debug=", "dir=", "help", "hash",
                         "refdir", "verbose"])

    except getopt.GetoptError as input_err:
        print(input_err)
        usage(sys.argv[0], basedir)
        sys.exit(2)


    inargs = {}
    inargs['debug'] = __def_debug
    inargs['basedir'] = basedir
    inargs['filename'] = ''
    inargs['singlefile'] = False
    inargs['errno'] = 0
    inargs['hash_algo'] = __def_hash_algo

    for arg, argval in opts:
        if arg in ("-d", "--debug") :
          inargs['debug'] = int(argval)
        elif arg in ("-D", "--dir") :
          inargs['basedir'] = str(argval)
        elif arg in ("-H", "--hash") :
          hasher = get_hasher(str(argval))
          if not hasher :
              print("Invalid hash algorithm: %s.\nCorrect Syntax:\n" %
                    (str(argval)))
              usage(sys.argv[0], basedir)
              sys.exit()
          inargs['hash_algo'] = str(argval)
        elif arg in ("-h", "--help") :
            usage(sys.argv[0], basedir)
            sys.exit()
        elif arg in ("-R", "--refdir") :
          inargs['refdir'] = str(argval)
        elif arg in ("-v", "--verbose") :
          inargs['debug'] = __def_verbose
        else :
            assert False, "unknown option %s" % arg
    # end-for

    return inargs


def get_hasher(algo) :

    if 'md5' == algo.lower() :
        return hashlib.md5()
    elif 'sha1' == algo.lower() :
        return hashlib.sha1()
    elif 'sha256' == algo.lower() :
        return hashlib.sha256()
    elif 'sha384' == algo.lower() :
        return hashlib.sha384()
    elif 'sha512' == algo.lower() :
        return hashlib.sha512()

    return None

def get_file_hash(inargs, filename) :
    status = False
    hashval = ''
    fn = 'get_file_hash'

    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    # hasher = inargs['hasher']
    # hasher = hashlib.md5()
    print("hash_algo: {}".format(inargs['hash_algo']))
 
    hasher = get_hasher(inargs['hash_algo'])

    if not hasher :
        print("{} Invalid hasher handle".format(fn))
        return (status, hashval)

    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            status = True # Should work for empty files too

            if not data : break

            hasher.update(data)

    hashval = hasher.hexdigest()

    # get_file_hash()
    return (status, hashval)

def build_frec(inargs, basedir, frec, fdup) :
    count = 0
    fn = 'build_frec'

    first_pass = (0 == len(fdup.keys()))

    for prfx, dirs, hits in os.walk(basedir, followlinks = False) :

        for fx in hits :
            full_name  = prfx + "/" + fx

            # clean any multiple '/' in the full path
            full_name = re.sub("//", "/", full_name)

            if full_name in frec.keys() :
                # Error condition
                if first_pass and (CLDBG_BFL <= inargs['debug']) :
                    print("duplicate_file=[%s] skipping.." % (full_name))
                    print(frec[full_name])
                continue # :TODO: should we abort??

            file_size = os.path.getsize(full_name)

            if (not first_pass) and (file_size not in fdup.keys()) :
                # We want to skip this entry because we will only consider
                # files in subsequent passes that can possibly be duplicate
                # with the files found in the first pass. If the file_size
                # is new, it means there were no files in the first pass
                # with the same file_size. While checking for duplicates,
                # there is no need to compute the expensive file hash if
                # the file sizes are not matching in order
                if (CLDBG_EXE <= inargs['debug']) :
                    print("skipping file {} from second (or higher) pass".format(
                        full_name))
                continue

            # Arrange based on file-size & file-hash
            # This helps fast searching for duplicates
            (hash_done, file_hash) = get_file_hash(inargs, full_name)

            if not hash_done :
                # Error condition
                if (CLDBG_BFL <= inargs['debug']) :
                    print("Failure hashing=[%s] skipping" % (full_name))
                continue # :TODO: should we abort??

            if file_size not in fdup.keys() :
                fdup[file_size] = dict()
                fdup[file_size][file_hash] = list()
                fdup[file_size][file_hash].append(full_name)
            else :
                if file_hash not in fdup[file_size].keys() :
                    fdup[file_size][file_hash] = list()
                else :
                    if not (full_name in fdup[file_size][file_hash]) :
                        # We have found a duplicate !
                        count += 1

                        if (CLDBG_VER1 <= inargs['debug']) :
                            print("%s is_duplicate in=>" % (full_name))
                            print(fdup[file_size])
                        elif (CLDBG_DFL <= inargs['debug']) :
                            print("%s is_duplicate" % (full_name))

                    # Finally add the duplicate entry
                    fdup[file_size][file_hash].append(full_name)
                
            frec[full_name] = dict()
            frec[full_name]['size'] = file_size
            frec[full_name]['hash'] = file_hash

            if (CLDBG_VER1 <= inargs['debug']) :
                print("%s prefix[%s]\t[%s] size=%ld" %
                      (fn, prfx, fx, file_size))

    # build_frec()
    return (count, frec, fdup)

#############################################################################################


def main():

    fn = 'main'
    inargs = process_input()
    debug = inargs['debug']
    frec = dict()
    fdup = dict()
    dup_count = 0
    count = 0

    if 'refdir' in inargs.keys() :
        (count, frec, fdup) = build_frec(inargs, inargs['refdir'], frec, fdup)

    (dup_count, frec, fdup) = build_frec(inargs, inargs['basedir'], frec, fdup)

    if (0 < count) : dup_count += count

    if (CLDBG_VER1 <= inargs['debug']) :
        print("\n{} dup_count={}".format(fn, dup_count))
        print("\n{} frec=>".format(fn))
        print(frec)
        print("\n{} fdup=>".format(fn))
        print(fdup)
    elif (CLDBG_BFL <= inargs['debug']) :
        print("\nTotal duplicate file groups: {}\n".format(dup_count))
        groups = 0
        for dx in fdup.keys() :
            for hx in fdup[dx].keys() :
                group_size = len(fdup[dx][hx])
                if (1 < group_size) :
                    print("Group# {}\tgroup-size: {}\tHash({}): {}".
                          format(groups, group_size, inargs['hash_algo'], hx))
                    groups += 1
                    for fx in fdup[dx][hx] : print(fx)
                    print("")

    return 0

if __name__ == "__main__" :
    failed = main()
    if (failed) : print(failed)
