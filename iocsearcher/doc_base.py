# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import logging
import langdetect
from iocsearcher.doc_common import get_file_mime_type,read_file_as_text

# Set logging
log = logging.getLogger(__name__)

class Document:
    """Base class for documents. Used for text files.
        PDF and HTML are children of this class and override its methods
    """
    def __init__(self, filepath, mime_type=None):
        self.filepath = filepath
        self._lang = None
        if mime_type:
            self.mime_type = mime_type
        else:
            self.mime_type = get_file_mime_type(filepath)

    @property
    def is_html(self):
        """Return if this is an HTML page"""
        return 'html' in self.mime_type

    @property
    def is_pdf(self):
        """Return if this is a PDF document"""
        return 'pdf' in self.mime_type

    def get_metadata(self):
        """Return metadata dictionary, empty dict if no metadata"""
        return {}

    def get_title(self):
        """Return document title, None if no title"""
        return None

    def get_text_elements(self, options=None):
        """Return list of text elements in file and extraction method
            A text element is the whole content by default
        """
        method = 'raw'
        text = read_file_as_text(self.filepath)
        if text:
            return ([text], method)
        else:
            return ([], method)

    def get_text(self, sep='\n', options=None):
        """Return readable file text as a string and extraction method"""
        try:
            (text_l, method) = self.get_text_elements(options)
            if text_l:
                return (sep.join(text_l), method)
            else:
                log.warning("Failed to extract text from %s" %  self.filepath)
                return (None, method)
        except Exception as e:
            log.warning("Failed to extract text from %s with exception: %s" %
                          (self.filepath, e))
            return (None, None)

    def get_language(self, text=None):
        """Return document language"""
        if self._lang is None:
            if text is None:
                text = self.get_text()[0]
            try:
                self._lang = langdetect.detect(text)
            except langdetect.lang_detect_exception.LangDetectException as e:
                log.warning("Could not get language for %s. Exception: %s" %
                              (self.filepath, e))
                self._lang = None
        return self._lang

    def metadata_iocs(self, searcher, metadata):
        """Return metadata IOCs, empty set if no metadata"""
        return set()


