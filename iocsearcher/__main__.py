#!/usr/bin/env python3
#
# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import os
import sys
import argparse
import logging
from iocsearcher.ioc import create_ioc
from iocsearcher.document import open_document
from iocsearcher.doc_base import Document
from iocsearcher.searcher import Searcher

# Set logging
log = logging.getLogger(__name__)

# Avoid log messages from specific modules below given log level
logging.getLogger("pdfminer.pdfdocument").setLevel(logging.CRITICAL)
logging.getLogger("pdfminer.pdfpage").setLevel(logging.CRITICAL)
logging.getLogger("pdfminer.pdfinterp").setLevel(logging.CRITICAL)
logging.getLogger("pdfminer.converter").setLevel(logging.CRITICAL)
logging.getLogger("pdfminer.cmapdb").setLevel(logging.CRITICAL)

# Log warn and above to stderr
#formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
formatter = logging.Formatter(u'%(message)s')
handler_stderr = logging.StreamHandler(sys.stderr)
handler_stderr.setLevel(logging.INFO)
handler_stderr.setFormatter(formatter)
root = logging.getLogger()
root.setLevel(logging.INFO)
root.addHandler(handler_stderr)


def main():

    argparser = argparse.ArgumentParser(prog='iocparser')

    argparser.add_argument('-f', action='append',
       help = 'Input file to search IOCs.')

    argparser.add_argument('-d', '--dir',
       help = 'Input directory. Search IOCs in all its files.')

    argparser.add_argument('-r', '--raw', action='store_true',
       help = 'Use raw search on HTML.')

    argparser.add_argument('-t', '--target', action='append',
       help = 'Search this target IOC name.')

    argparser.add_argument('-o', '--output',
       help = 'Output IOCs to this file.')

    argparser.add_argument('-p', '--phone',
       help = 'Search for phone numbers.')

    argparser.add_argument('-F', '--forcetext', action='store_true',
       help = 'Treat the input file as text, no filetype detection.')

    argparser.add_argument('-R', '--readability', action='store_true',
        help='use Readability.js for text extraction')

    argparser.add_argument('-T', '--text', action='store_true',
        help='store file text into separate file with .text extension')

    argparser.add_argument('-v', '--verbose', action='store_true',
        help='verbose. Prints match location and defanged value')

    argparser.add_argument('-P', '--patterns',
       help = 'Use patterns in this file instead of the default patterns.')

    # Parse arguments
    args = argparser.parse_args()

    if (not args.f) and (not args.dir):
        log.warning("No input file. Use -f or -d options")
        argparser.print_usage()
        sys.exit(1)

    if not args.target:
        args.target = None

    # Create Searcher object
    searcher = Searcher(patterns_ini=args.patterns,
                        create_ioc_fun=create_ioc)

    # List of files to scan
    files = args.f if args.f is not None else []
    if args.dir:
        dir_files = [ os.path.join(args.dir, f) for f in os.listdir(args.dir) \
                                if os.path.isfile(os.path.join(args.dir, f))]
        files.extend(dir_files)

    # Set for all found IOCs
    # all_iocs = set()

    # Set output file
    if args.output:
        out_fd = open(args.output, 'w', encoding='utf-8')
    else:
        out_fd = None

    # Iterate on files
    for filepath in sorted(files):
        log.info("Searching into %s" % filepath)
        iocs = set()

        # Open document
        if (not args.forcetext):
            doc = open_document(filepath)
        else:
            doc = Document(filepath, mime_type='text/plain')
        if doc is None:
            log.warning("Skipping unsupported file: %s" % filepath)
            continue

        # Extract text
        options = {
                    'html_raw' : args.raw,
                    'html_use_readability' : args.readability,
                  }
        text = doc.get_text(options=options)[0]
        if not text:
            log.error("Could not obtain text from %s" % filepath)
            continue

        # Open output file
        if not args.output:
            ioc_filepath = filepath + '.iocs'
            out_fd = open(ioc_filepath, "w")

        # If verbose, get matched tuples and continue
        if args.verbose:
            match_l = searcher.search_raw(text, targets=args.target)
            for m in sorted(match_l, key=lambda p : (p[2],-len(p[1]))):
                log.info("%s\t%s @ %d Raw: %s" % (m[0], m[1],
                                                  m[2], m[3]))
                out_fd.write("%s\t%s @ %d Raw: %s\n" % (m[0], m[1],
                                                        m[2], m[3]))
            continue

        # Search file
        iocs.update(searcher.search_data(text, targets=args.target))

        # Search for phone numbers
        if args.phone:
            phone_iocs = searcher.search_phone_numbers(text, args.phone)
            iocs.update(phone_iocs)

        # Output IOCs
        for ioc in sorted(iocs):
            log.info("%s" % ioc)
            out_fd.write("%s\n" % ioc)

        # Flush output file or close it
        if args.output:
            out_fd.flush()
        else:
            out_fd.close()

        # Output text to file
        if args.text:
            text_filepath = filepath + '.text'
            fd = open(text_filepath, "w")
            fd.write(text)
            fd.close()

        # Store IOCs
        # all_iocs.update(iocs)

    #if args.output:
    #    fd = open(args.output, "w")
    #    for ioc in sorted(all_iocs):
    #        fd.write("%s\n" % ioc)
    #    fd.close()

    # Close output file
    if args.output:
        out_fd.close()

if __name__ == '__main__':
    main()
