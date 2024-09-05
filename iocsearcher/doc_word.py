# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import logging
from io import StringIO
from iocsearcher.doc_base import Document
from docx2python import docx2python
from docx2python.docx_text import flatten_text

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
        #return ([self.doc.text],'docs2python')
        document_runs = []
        # Add header
        if options.get('add_header', False):
            document_runs += self.doc.header_runs
        # Add body
        document_runs += self.doc.body_runs
        # Add footer
        if options.get('add_footer', False):
            document_runs += self.doc.footer_runs
        # Add footnotes
        if options.get('add_footnotes', True):
            document_runs += self.doc.footnotes_runs
        # Add endnotes
        if options.get('add_endnotes', True):
            document_runs += self.doc.endnotes_runs
        # Get text
        text = flatten_text(document_runs)
        return ([text],'docs2python')

