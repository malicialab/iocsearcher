# Copyright (c) MaliciaLab, 2023.
# Do not copy, disclose, or distribute without explicit written permission
# Author: Juan Caballero
#
import logging
import iocsearcher.ioc
from iocsearcher.doc_pdf import Pdf

# Set logging
log = logging.getLogger(__name__)

class ExtendedPdf(Pdf):
    """Class for PDF documents"""
    def __init__(self, filepath, mime_type=None, create_ioc_fun=None):
        Pdf.__init__(self, filepath, mime_type=mime_type)
        # IOC creation function
        if create_ioc_fun is not None:
            self.create_ioc = create_ioc_fun
        else:
            self.create_ioc = iocsearcher.ioc.create_ioc

    def metadata_iocs(self, searcher, metadata):
        """Return metadata IOCs, empty set if no metadata 
            For now, only the author's identity is output
        """
        iocs = set()
        author = metadata.get('Author', None)
        if author:
            iocs.add(self.create_ioc("identity", author))
        return iocs

