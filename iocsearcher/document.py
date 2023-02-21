# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import os
import logging
from iocsearcher.doc_base import Document
from iocsearcher.doc_pdf import Pdf
from iocsearcher.doc_html import Html
from iocsearcher.doc_common import get_file_mime_type

# Set logging
log = logging.getLogger(__name__)

def open_document(filepath):
    ''' Return a Document object, None if unsupported document type '''
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
        doc = Pdf(filepath, mime_type=mime_type)
    elif ((mime_type == "text/html") or
          (mime_type == "text/xml")):
          doc = Html(filepath, mime_type=mime_type)
    elif ((tokens[0] == "text") or
          (mime_type == "application/csv")):
        doc = Document(filepath, mime_type=mime_type)
    else:
        log.warning("Unsupported MIME type %s for %s" % (mime_type, filepath))
        doc = None
    return doc

