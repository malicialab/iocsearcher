# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import re
import logging
import magic

# Set logging
log = logging.getLogger(__name__)

def read_raw_file(filepath):
    """Read file contents as binary string"""
    fd = open(filepath, 'rb')
    data = fd.read()
    fd.close()
    return data

def read_file_as_text(filepath):
    """Try to read file as text using a fixed list of popular encodings"""
    data = read_raw_file(filepath)
    text = None
    for enc in [ 'utf-8', 'cp1252' ]:
        try:
            text = data.decode(enc)
            if text:
                break
        except (UnicodeDecodeError, TypeError) as e:
            log.debug("File %s does not use %s encoding" % (filepath, enc))
            continue
    return text

def get_file_mime_type(filepath, n=1024):
    """Get file MIME type"""
    mime_type = magic.from_file(filepath, mime=True)
    if (mime_type == "application/octet-stream"):
        with open(filepath, 'rb') as fd:
            buf = fd.read(n)
        mime_type = magic.from_buffer(buf, mime=True)
    # If text file contains HTML tags, then it is HTML
    elif mime_type == "text/plain":
        with open(filepath, 'rb') as fd:
            buf = fd.read(n)
        html_regex = (b"<h1>|<h2>|<h3>|<p>|<em>|<i>|<br>|<br \/>"
                      b"<b>|<strong[^>]*>")
        if re.search(html_regex, buf):
            mime_type = "text/html"
    return mime_type

