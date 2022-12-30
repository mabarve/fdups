#!/usr/bin/env python3

import datetime, getopt, hashlib, os, re, sys

# Settings local to the script

# Debug Levels:
CLDBG_SNGL =  0 # Only print number of failed test cases otherwise 0 on success
CLDBG_SUM  =  1 # Print summary of test cases (total, success, failed)
CLDBG_BFL  =  2 # Print brief info on failures
CLDBG_DFL  =  3 # Print detailed info on failures
CLDBG_DSU  =  4 # Print details on successful cases
CLDBG_EXE  =  5 # Details on test execution
CLDBG_VER1  = 6 # Details' verbosity level-1
CLDBG_VER2  = 7 # Details' verbosity level-1

__tmp_rec = '0' # Temporary Record Identifier

__def_debug             = CLDBG_BFL # Default debug level
__def_verbose           = CLDBG_DSU  # Default debug level
__def_hash_algo         = "sha1" # Default file hashing algorithm
__def_follow_links      = False # Default file hashing algorithm
__def_buf_size          = 1048576  # lets read stuff in 64kb chunks!


def usage(progname, basedir) :
    print(progname + " [options]\n\n")

    print("[(-b | --buffer-size) <in-bytes>] (default=%d). "
          "Temporary buffer size for reading file contents\n\t\t\t\tduring "
          "the hash computation process. Generally larger buffer"
          " space\n\t\t\t\timproves the read IO performance at the cost of"
          " higher run time memory consumption.\n" % (__def_buf_size))

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

    print("[(-H | --hash) <algorith>]\tFile hashing algorithm "
          "(md5/ sha1/ sha256/ sha384/ sha512)"
          "\n\t\t\t\t(default is '%s')\n" % (__def_hash_algo))

    print("-h\t\t\t\tThis help message.\n")
    print("--help\t\t\t\tMore extensive help message.\n")

    print("[-l | --links]\t\t\t(default={}) Also check symbolic links.\n".format(
        __def_follow_links))

    print("[-v | --verbose]\t\t(default=%d)" % __def_verbose)
    print("[-z | --zero-compare]\t\tCompare zero-byte size files, which usually "
          "isn't very meaningful. ")
    print("\n")

    # usage() ends

def process_input():
    '''Entry level function for unit testing this script file.
    '''

    basedir = os.getcwd()

    try:
        opts, args = getopt.getopt(
                        sys.argv[1:], "b:d:D:hH:lR:vz",
                        ["buffer-size=", "debug=", "dir=",
                         "help", "hash=", "links", "refdir=",
                         "verbose", "zero-compare"])

    except getopt.GetoptError as input_err:
        print(input_err)
        usage(sys.argv[0], basedir)
        sys.exit(2)


    inargs = {}
    inargs['buf_size'] = __def_buf_size
    inargs['debug'] = __def_debug
    inargs['basedir'] = basedir
    inargs['filename'] = ''
    inargs['singlefile'] = False
    inargs['errno'] = 0
    inargs['hash_algo'] = __def_hash_algo
    inargs['follow_links'] = __def_follow_links
    inargs['zero_cmp'] = False

    for arg, argval in opts:
        if arg in ("-b", "--buffer-size") :
          inargs['buf_size'] = int(argval)
        elif arg in ("-d", "--debug") :
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
        elif arg in ("-l", "--links") :
          inargs['follow_links'] = True
        elif arg in ("-R", "--refdir") :
          inargs['refdir'] = str(argval)
        elif arg in ("-v", "--verbose") :
          inargs['debug'] = __def_verbose
        elif arg in ("-z", "--zero-compare") :
          inargs['zero_cmp'] =  True
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

    # get_hasher()
    return None

def get_file_hash(inargs, filename) :
    status = False
    hashval = ''
    fn = 'get_file_hash'

    hasher = get_hasher(inargs['hash_algo'])

    if not hasher :
        print("{} Invalid hasher handle".format(fn))
        return (status, hashval)

    bsize = inargs['buf_size']

    with open(filename, 'rb') as f:
        while True:
            data = f.read(bsize)
            status = True # Should work for empty files too

            if not data : break

            hasher.update(data)

    hashval = hasher.hexdigest()

    # get_file_hash()
    return (status, hashval)

def build_frec(inargs, basedir, frec, fdup) :
    count = 0
    fn = 'build_frec'
    zero_cmp = inargs['zero_cmp'] # Avoiding reading inargs multiple times

    first_pass = (0 == len(fdup.keys()))

    for prfx, dirs, hits in os.walk(basedir,
                                    followlinks =
                                    inargs['follow_links']) :

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

            if (0 == file_size) :
                if zero_cmp :
                    if (CLDBG_VER1 <= inargs['debug']) :
                        print("processing zero-byte size file {}".format(full_name))
                else :
                    if (CLDBG_VER1 <= inargs['debug']) :
                        print("skipping zero-byte size file {}".format(full_name))
                    continue

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

            file_hash = '00'
            hash_done = False


            if file_size not in fdup.keys() :
                # We have found the first file with 'file_size'. We won't compute
                # it's hash for now. Hash computation is an expensive function and
                # we will only compute it if there are multiple files with the same
                # size. So we defer the hash computation of the first file by stashing
                # it in a special location called '__tmp_rec'. However this is done
                # only once for a given file size. When we encounter the second file
                # with the same size, we compute hash on the first (__tmp_rec) and the
                # second file. Any additional files (third/ fourth etc.) are immediately
                # hashed.
                fdup[file_size] = dict()
                fdup[file_size][__tmp_rec] = full_name
            else :
                # Check for backlog and update if needed
                if __tmp_rec in fdup[file_size].keys() :
                    tmp_file = fdup[file_size][__tmp_rec]
                    if (0 < len(tmp_file)) :
                        # Delayed hash computation!!!
                        # Previous entry remains to be processed. We only compute
                        # it's hash now because there are more than 1 files with the
                        # same size, potentially leading to duplicate files. Unless
                        # that's the case, we don't compute hash for a file if it's
                        # the only file of that size.
                        (hash_done, file_hash) = get_file_hash(inargs, tmp_file)

                        if not hash_done :
                            # Error condition
                            if (CLDBG_BFL <= inargs['debug']) :
                                print("Failure hashing tmp=[%s] skipping" % (tmp_file))
                                continue # :TODO: should we abort??

                        if file_hash in fdup[file_size].keys() :
                            # :TODO: Error Condition, we expected the 'file_size'
                            # bin to be empty except for the special record __tmp_rec
                            if (CLDBG_BFL <= inargs['debug']) :
                                print("Unexpected hash-entry for =[%s] skipping." %
                                      (tmp_file))
                                continue # :TODO: should we abort??

                        fdup[file_size][file_hash] = [tmp_file]
                        frec[tmp_file]['hash'] = file_hash

                        # Permanently disable this record by writing empty filename
                        fdup[file_size][__tmp_rec] = ''

                # '__tmp_rec' processed. Now compute hash for the current file
                (hash_done, file_hash) = get_file_hash(inargs, full_name)

                if not hash_done :
                    # Error condition
                    if (CLDBG_BFL <= inargs['debug']) :
                        print("Failure hashing current=[%s] skipping" % (full_name))
                        continue # :TODO: should we abort??

                if file_hash not in fdup[file_size].keys() :
                    fdup[file_size][file_hash] = list()
                else :
                    if not (full_name in fdup[file_size][file_hash]) :
                        # We have found a duplicate !
                        count += 1

                        if (CLDBG_VER2 <= inargs['debug']) :
                            print("%s is_duplicate in=>" % (full_name))
                            print(fdup[file_size])
                        elif (CLDBG_VER1 <= inargs['debug']) :
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


def search_and_report():

    fn = 'main'
    inargs = process_input()
    debug = inargs['debug']
    frec = dict()
    fdup = dict()

    time_stamp_1 = datetime.datetime.now()

    if 'refdir' in inargs.keys() :
        # Check duplicate files within the reference tree
        # Subsequently the base-directory will be searched
        # only for files that can potentially be identical
        # to some from the reference directory. In other words
        # if there duplicates present in the base-directory without
        # any matching files in the reference directory, those will
        # will be silently ignored.
        (count, frec, fdup) = build_frec(inargs, inargs['refdir'], frec, fdup)

    # Final computation of duplicates
    (count, frec, fdup) = build_frec(inargs, inargs['basedir'], frec, fdup)

    time_stamp_2 = datetime.datetime.now()

    if (CLDBG_EXE <= inargs['debug']) :
        time_delta = time_stamp_2 - time_stamp_1
        print("\n{} total search time {} seconds\n".format(
            fn, time_delta.total_seconds()))
        
    # Analyze the results
    count = 0
    groups = 0
    for dx in fdup.keys() :
        for hx in fdup[dx].keys() :
            if __tmp_rec == hx :
                # Special entry to be skipped
                continue

            group_size = len(fdup[dx][hx])
            if (1 < group_size) :

                if (CLDBG_SUM <= inargs['debug']) :
                    print("Group# {}\tgroup-size: {}\tHash({}): {}".
                          format(groups, group_size, inargs['hash_algo'], hx))
                    for fx in fdup[dx][hx] : print(fx)
                    print("")

                count += group_size
                groups += 1

    # Report the results
    if (0 < groups) :
        if (CLDBG_SUM <= inargs['debug']) :
            print("\nTotal duplicate-file-groups: {}, duplicate-files:{}\n".
                  format(groups, count))
        elif (CLDBG_SNGL <= inargs['debug']) :
            print(count)

    return (count, frec, fdup)

if __name__ == "__main__" :
    search_and_report()
