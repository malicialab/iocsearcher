# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import logging
import re
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
        return {k: v for k, v in self.doc.core_properties.items() 
                if v is not None}

    def get_title(self):
        """Return title"""
        metadata = self.get_metadata()
        if metadata:
            return metadata.get("title", None)
        else:
            return None

    def get_text_elements(self, options=None):
        """Return list of text elements and extraction method"""
        runs = []
        elements = []
        # Add header
        if options.get('add_header', False):
            runs.append(self.doc.header_runs)
        # Add body
        document_runs = self.doc.body_runs
        for run in document_runs:
            runs.append([run])
        # Add footer
        if options.get('add_footer', False):
            runs.append(self.doc.footer_runs)
        # Add footnotes
        if options.get('add_footnotes', True):
            runs.append(self.doc.footnotes_runs)
        # Add endnotes
        if options.get('add_endnotes', True):
            runs.append(self.doc.endnotes_runs)
        # Iterate on runs to produce elements
        for r in runs:
            # Get run's text
            text = flatten_text(r).strip()
            # Remove figure references
            if options.get('remove_figure_refs', True):
                text = re.sub('----media\/[a-zA-Z0-9]+\.[a-z]{3,}----',
                              '', text)
            # Remove consecutive tabs
            if options.get('remove_consecutive_tabs', True):
                text = re.sub('\n\t+', '\n', text)
            # Remove consecutive blank lines
            if options.get('remove_consecutive_blank_lines', True):
                text = re.sub('(\r?\n){3,}', '\n\n', text)
            if text:
                elements.append(text)
        return (elements,'docs2python')

