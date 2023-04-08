#!/usr/bin/env python3

import datetime, getopt, hashlib, os, re, sys

####
# Settings local to the script
####

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


__design_doc = """
 **** Design Documentation ****

 This script works in one of the two modes:

 Mode-1: It scans all the files in a given directory tree and identifies
 duplicate files and reports those.

 Mode-2: It scans a directory (usually smaller) tree and finds any duplicates
 within that tree. Then it scans a larger directory tree and finds ONLY those
 files that have any duplicates in the smaller tree. this mode is useful
 before amalgamating a smaller tree with a larger one.


 For any two files to be identical, their sizes AND hash must match. Comparing
 file sizes is relatively inexpensive compared to computing file hash. This is
 leveraged in the design. Files are first sorted according to their size. Then
 only those size groups containing multiple files are subjected to hashing.


 Hash computation involves reading all the bytes of a given file and passing
 those through a hash-computation block (i.e. 'hasher' in our design). Reading
 the file in it's entirety is done iteratively by using a temporary buffer. This
 way files of arbitrarily large size (e.g. hundreds of gigabytes) can be safely
 hashed without risking memory exhaustion. However size of the temporary buffer
 does impact the run time performance. We use a descent value for buffer size
 as default but also let users override this with their choice.


 By default, symbolic links to directories and files are ignored by the search
 logic, but users can include symbolic links by adding a command line option.


 Comparing files of zero size is meaningless. Any two files, created for very
 different purposes will appear as identical if both are empty. This is because
 their sizes (0 bytes) and hash values match. Hasher produces a fixed value
 for zero-byte files for a given hashing algorithm. Users can enable the
 'zero comparison' by adding a command line option.


 Run time complexity varies with the choice of hashing algorithms. This tool
 offers user selectable hashing algorithm (with a default value).


 This module can be used as a library if the callers invoke "search_and_report()"
 Alternatively the modules can be directly invoked as a command-line utility.

"""

def show_doc() :
    print(__design_doc)


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

    print("[(-H | --hash) <algorithm>]\tFile hashing algorithm "
          "(md5/ sha1/ sha256/ sha384/ sha512)"
          "\n\t\t\t\t(default is '%s')\n" % (__def_hash_algo))

    print("-h\t\t\t\tThis help message.\n")
    print("--help\t\t\t\tMore extensive help message.\n")

    print("[-l | --links]\t\t\t(default={}) Also check symbolic links.\n".format(
        __def_follow_links))

    print("[--rm-auto]\t\t\tAutomatically remove duplicates while retaining the first one found.")
    print("\t\t\t\tThis option doesn't require user confirmation. So be careful.\n")

    print("[--rm-cnf]\t\t\tRemove duplicates while retaining the first one found.")
    print("\t\t\t\tThis option requires user confirmation for each file deletion.\n")

    print("[--rm-test]\t\t\tProcess removal request but don't actually remove files in the final step.")

    print("[-s | --stats]\t\t\tPrint additional statistics.\n")
    print("[-v | --verbose]\t\t(default=%d)\n" % __def_verbose)
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
                        sys.argv[1:], "b:d:D:hH:lR:svz",
                        ["buffer-size=", "debug=", "dir=",
                         "help", "hash=", "links", "refdir=",
                         "rm-auto", "rm-cnf", "rm-test",
                         "stats", "verbose", "zero-compare"])

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
    inargs['stats'] = False
    inargs['rm_auto'] = False
    inargs['rm_cnf'] = False
    inargs['rm_test'] = False

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
        elif arg in ("-h") :
            usage(sys.argv[0], basedir)
            sys.exit()
        elif arg in ("--help") :
            usage(sys.argv[0], basedir)
            show_doc()
            sys.exit()
        elif arg in ("-l", "--links") :
          inargs['follow_links'] = True
        elif arg in ("-R", "--refdir") :
          inargs['refdir'] = str(argval)
        elif arg in ("--rm-auto") :
          inargs['rm_auto'] = True
        elif arg in ("--rm-cnf") :
          inargs['rm_cnf'] = True
        elif arg in ("--rm-test") :
          inargs['rm_test'] = True
        elif arg in ("-s", "--stats") :
          inargs['stats'] = True
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
            full_name = re.sub("/+", "/", full_name)

            if full_name in frec.keys() :
                # Error condition
                if first_pass and (CLDBG_BFL <= inargs['debug']) :
                    print("duplicate_file=[%s] skipping.." % (full_name))
                    print(frec[full_name])
                continue

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
                                continue

                        if file_hash in fdup[file_size].keys() :
                            # Error Condition, we expected the 'file_size'
                            # bin to be empty except for the special record __tmp_rec
                            if (CLDBG_BFL <= inargs['debug']) :
                                print("Unexpected hash-entry for =[%s] skipping." %
                                      (tmp_file))
                                continue

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
                        continue

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


def search_and_report(inargs):

    fn = 'search_and_report'
    debug = inargs['debug']
    frec = dict()
    fdup = dict()
    fstats = dict()

    time_stamp_1 = datetime.datetime.now()

    if 'refdir' in inargs.keys() :
        # Check duplicate files within the reference tree. Subsequently the
        # base-directory will be searched only for files that can potentially
        # be identical to some from the reference directory. In other words if
        # there are duplicates in the base-directory without any matching files
        # in the reference directory, those will be silently ignored.
        (count, frec, fdup) = build_frec(inargs, inargs['refdir'], frec, fdup)

    # Final computation of duplicates
    (count, frec, fdup) = build_frec(inargs, inargs['basedir'], frec, fdup)

    time_stamp_2 = datetime.datetime.now()
    time_delta = time_stamp_2 - time_stamp_1

    if (CLDBG_EXE <= inargs['debug']) :
        print("\n{} total search time {} seconds\n".format(
            fn, time_delta.total_seconds()))

    consent = ['y', 'yes', 'ye']

    # Analyze the results
    count = 0
    groups = 0
    fstats['unq_files'] = 0
    fstats['dup_files'] = 0
    fstats['dup_groups'] = 0
    fstats['sz_tot'] = 0
    fstats['sz_unq'] = 0
    fstats['sz_dup'] = 0
    fstats['hashed_files'] = 0
    fstats['removed'] = 0

    for dx in fdup.keys() :
        for hx in fdup[dx].keys() :
            if __tmp_rec == hx :
                # Special entry to be skipped
                if 1 == len(fdup[dx]) :
                    # This is the only record for a given file-size dx.
                    # It means it's a file without duplicates. Update the stats
                    fstats['unq_files'] += 1
                    fname = fdup[dx][hx]
                    fsize = frec[fname]['size']
                    fstats['sz_tot'] += fsize
                    fstats['sz_unq'] += fsize
                continue # skip entry

            group_size = len(fdup[dx][hx])
            printed_filenames = False
            if (1 < group_size) :

                count += group_size
                groups += 1
                fstats['dup_files'] += group_size
                fstats['dup_groups'] += 1

                fname = fdup[dx][hx][0]
                fsize = frec[fname]['size']
                sz_grp = group_size * fsize
                fstats['sz_tot'] += sz_grp
                fstats['sz_dup'] += sz_grp
                fstats['hashed_files'] += group_size

                if (CLDBG_SUM <= inargs['debug']) :
                    print("Group# {}\tgroup-size: {}\tfile-size: {}\tHash({}): {}".
                          format(groups, group_size, fsize, inargs['hash_algo'], hx))
                    for fx in fdup[dx][hx] : print(fx)
                    print("")
                    printed_filenames = True

                # Optionally remove duplicates
                if inargs['rm_cnf'] :
                    # Interactive removal takes precedence
                    if not printed_filenames :
                        # You definitely want to show all the group members to the
                        # user in an interactive removal scenario. So if you haven't
                        # shown the filenames earlier, show those regardless of the
                        # debug level of this script.
                        print("Group# {}\tgroup-size: {}\tfile-size: {}\tHash({}): {}".
                              format(groups, group_size, fsize, inargs['hash_algo'], hx))
                        for fx in fdup[dx][hx] : print(fx)
                        print("")
                    for fx in fdup[dx][hx] :
                        question = "Remove: '" + fx + "' ? (Y/ N)  "
                        inpt = input(question)
                        if inpt.lower() in consent :
                            print("\nRemoval confirmed for: {}\n".format(fx))
                            if not inargs['rm_test'] :
                                fstats['removed'] += 1
                                os.remove(fx)
                        else :
                            print("keeping file: {}\n".format(fx))
                    print("\n\n")
                elif inargs['rm_auto'] :
                    id = 0
                    for fx in fdup[dx][hx] :
                        if (0 == id) :
                            print("keeping: {}\n".format(fx))
                        else :
                            print("removing: {}\n".format(fx))
                            if not inargs['rm_test'] :
                                fstats['removed'] += 1
                                os.remove(fx)
                        id += 1
                    print("\n\n")
                    
            elif (1 == group_size) :
                # Only file with a given hash value hx
                fstats['unq_files'] += 1

                fname = fdup[dx][hx][0]
                fsize = frec[fname]['size']
                fstats['sz_tot'] += fsize
                fstats['sz_unq'] += fsize
                fstats['hashed_files'] += 1

    # Report the results
    if (0 < groups) :
        if (CLDBG_SUM <= inargs['debug']) :
            print("\nTotal duplicate-file-groups: {}, duplicate-files:{}\n".
                  format(groups, count))
        elif (CLDBG_SNGL <= inargs['debug']) :
            print(count)


    # Compute additional statistics
    fstats['processed_files'] = len(frec.keys())
    fstats['prcnt_dup'] = 100.0 * fstats['dup_files'] / fstats['processed_files']
    fstats['prcnt_unq'] = 100.0 * fstats['unq_files'] / fstats['processed_files']
    fstats['prcnt_sz_unq'] = 100.0 * fstats['sz_unq'] / fstats['sz_tot']
    fstats['prcnt_sz_dup'] = 100.0 * fstats['sz_dup'] / fstats['sz_tot']

    # Print statistics
    if inargs['stats'] :
        print("\nExtended statistics:\n")
        print("Processed Files:\t\t{}".format(fstats['processed_files']))
        print("Unique Files:\t\t\t{}".format(fstats['unq_files']))
        print("Duplicate Files:\t\t{}".format(fstats['dup_files']))
        print("% Unique Files:\t\t\t{} %".format(fstats['prcnt_unq']))
        print("% Duplicate Files:\t\t{} %".format(fstats['prcnt_dup']))
        print("Total space consumed:\t\t{} bytes".format(fstats['sz_tot']))
        print("Unique space consumed:\t\t{} bytes".format(fstats['sz_unq']))
        print("Duplicate space consumed:\t{} bytes".format(fstats['sz_dup']))
        print("% Unique/ Total space:\t\t{} %".format(fstats['prcnt_sz_unq']))
        print("% Duplicate/ Total space:\t{} %".format(fstats['prcnt_sz_dup']))
        print("File search time:\t\t{} seconds".format(time_delta.total_seconds()))
        print("Hashing algorithm:\t\t{}".format(inargs['hash_algo'].upper()))
        print("Total files hashed:\t\t{}".format(fstats['hashed_files']))
        print("Total files removed:\t\t{}".format(fstats['removed']))
        print("")


    # Return the results to the caller. If some other module called this method,
    # they will get various data-structures as the result from this module.
    return (count, frec, fdup, fstats)

def main():
    inargs = process_input() # Process User Inputs
    search_and_report(inargs) # Invoke the processor

if __name__ == "__main__" :
    main()
