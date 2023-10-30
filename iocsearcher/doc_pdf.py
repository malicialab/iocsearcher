# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import logging
from io import StringIO
from iocsearcher.doc_base import Document
# Import pdfminer.six APIs
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfinterp import PDFResourceManager
from pdfminer.converter import TextConverter
from pdfminer.pdfinterp import PDFPageInterpreter
from pdfminer.layout import LAParams
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument

# Set logging
log = logging.getLogger(__name__)

class Pdf(Document):
    """Class for PDF documents"""
    def __init__(self, filepath, mime_type=None):
        Document.__init__(self, filepath, mime_type=mime_type)
        self.filepath = filepath
        self.fd = open(filepath, "rb")

    def __del__(self):
        """Close file descriptor on destruction"""
        self.fd.close()

    def get_metadata(self, enc='utf-8'):
        """Get PDF metadata using pdfminer"""
        metadata = {}
        parser = PDFParser(self.fd)
        try:
            pdf = PDFDocument(parser)
        except Exception as e:
            log.warning("Failed to get PDF metadata from %s" % filepath)
            log.warning(e)
            pdf = None
        if (pdf is not None) and pdf.info:
            for key, data in pdf.info[0].items():
                if isinstance(data, bytes):
                    try:
                        value = data.decode(enc).strip()
                        if value:
                            metadata[key] = value
                    except UnicodeDecodeError:
                        try:
                            value = data.decode('utf-16').strip()
                            if value:
                                metadata[key] = value
                        except UnicodeDecodeError:
                            continue
        return metadata

    def get_title(self):
        """Return PDF title"""
        metadata = self.get_metadata()
        if metadata:
            return metadata.get("Title", None)
        else:
            return None

    def get_text_elements(self, options=None):
        """Return list of text elements and extraction method
            Each element is the text of a page
        """
        pages = []
        laparams = LAParams()
        laparams.all_texts = True
        rsrcmgr = PDFResourceManager()
        pagenos = set()
        page_num = 0
        for page in PDFPage.get_pages(self.fd, pagenos,
                                      check_extractable=False):
            page_num += 1
            retstr = StringIO()
            device = TextConverter(rsrcmgr, retstr, codec='utf-8',
                                   laparams=laparams)
            interpreter = PDFPageInterpreter(rsrcmgr, device)
            interpreter.process_page(page)
            page_text = retstr.getvalue()
            retstr.close()
            pages.append(page_text)
        return (pages,'pdfminer.six')

