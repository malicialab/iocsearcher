# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import logging
from io import StringIO
from iocsearcher.doc_base import Document
from docx2python import docx2python

# Set logging
log = logging.getLogger(__name__)

class Word(Document):
    """Class for Word OOXML (.docx) documents"""
    def __init__(self, filepath, mime_type=None):
        Document.__init__(self, filepath, mime_type=mime_type)
        self.filepath = filepath
        self.doc = docx2python(filepath, html=False)

    def __del__(self):
        """Close document on destruction"""
        self.doc.close()

    def get_metadata(self, enc='utf-8'):
        """Get document metadata"""
        return self.doc.core_properties

    def get_title(self):
        """Return title"""
        metadata = self.get_metadata()
        if metadata:
            return metadata.get("title", None)
        else:
            return None

    def get_text_elements(self, options=None):
        """Return list of text elements and extraction method
            A single element with all text is currently returned.
        """
        return ([self.doc.text],'docs2python')

