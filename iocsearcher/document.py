# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import os
import logging
from iocsearcher.doc_base import Document
from iocsearcher.doc_epdf import ExtendedPdf
from iocsearcher.doc_ehtml import ExtendedHtml
from iocsearcher.doc_common import get_file_mime_type

# Set logging
log = logging.getLogger(__name__)

def open_document(filepath, create_ioc_fun=None):
    """Return a Document object, None if unsupported document type"""
    # Check we have a file
    if not os.path.isfile(filepath):
        log.warning("Not a file: %s" % filepath)
        return None
    # Get MIME type
    mime_type = get_file_mime_type(filepath)
    log.debug("  File MIME type: %s" % mime_type)
    # Create right object according to MIME type
    tokens = mime_type.split('/')
    if tokens[1] == "pdf":
        doc = ExtendedPdf(filepath, mime_type=mime_type,
                          create_ioc_fun=create_ioc_fun)
    elif ((mime_type == "text/html") or
          (mime_type == "text/xml")):
          doc = ExtendedHtml(filepath, mime_type=mime_type,
                              create_ioc_fun=create_ioc_fun)
    elif ((tokens[0] == "text") or
          (mime_type == "application/csv")):
        doc = Document(filepath, mime_type=mime_type)
    else:
        log.warning("Unsupported MIME type %s for %s" % (mime_type, filepath))
        doc = None
    return doc

