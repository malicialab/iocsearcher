# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import re
import logging
from bs4 import BeautifulSoup
from bs4.element import Comment
from readabilipy import simple_json_from_html_string
from iocsearcher.doc_base import Document
from iocsearcher.doc_common import read_raw_file,read_file_as_text


# Set logging
log = logging.getLogger(__name__)

class Html(Document):
    def __init__(self, filepath, mime_type=None):
        Document.__init__(self, filepath, mime_type=mime_type)
        self.filepath = filepath
        data = read_raw_file(filepath)
        # self.soup = BeautifulSoup(data, "html.parser")
        self.soup = BeautifulSoup(data, "lxml")

    @staticmethod
    def is_visible_element(element, include_metadata=False, include_links=True):
        # Skip comments
        if isinstance(element, Comment):
            return False
        # Skip invisible content
        if element.parent.name in ['style', 'script', '[document]', 'head']: 
            return False
        # Skip metadata, unless requested
        if ((not include_metadata) and
            (element.parent.name in ['title', 'meta'])):
            return False
        # Skip links, unless requested
        if (not include_links) and (element.parent.name == "a"):
            link = element.parent.get('href')
            val = element.strip()
            if (not link) or (not val):
                return False
            idx = link.find('://')
            if (idx != -1) and (idx < 10):
                link = link[idx+3:]
            idx = val.find('://')
            if (idx != -1) and (idx < 10):
                val = val[idx+3:]
            return not link.startswith(val)
            #return False
        # Keep rest
        return True

    def get_metadata(self):
        """Return metadata dictionary, None if no metadata"""
        metadata = {}
        # Add title
        if self.soup.title is not None:
            title = self.soup.title.string
            if title:
                metadata["Title"] =  title.strip()
        # Add meta tags
        for tag in self.soup.find_all("meta"):
            name = None
            value = None
            for aname, avalue in tag.attrs.items():
                if aname in "charset":
                    name = aname
                    value = avalue
                elif aname == "http-equiv":
                    name = avalue
                elif aname == "content":
                    value = avalue
                elif aname == "class":
                    continue
                else:
                    name = avalue
            if name and value:
                v = value.strip()
                if v:
                    metadata[name] = v
        return metadata

    def get_title(self):
        """Return HTML title"""
        metadata = self.get_metadata()
        title = metadata.get('Title', None)
        if title is None:
            title = metadata.get('og:title', None)
        if title is None:
            title = metadata.get('twitter:title', None)
        if title is None:
            title = metadata.get('title', None)
        return title

    def get_text_html(self, sep=' ', include_all=False,
                    include_metadata=False, include_links=False):
        """Extract visible text in HTML using our own approach"""
        # Read raw contents
        data = read_raw_file(self.filepath)
        # Replace beautifiers
        replace_regex = (b"<span[^>]*>|<\/span>|<pre[^>]*>|<\/pre>|"
                         b"<em>|<\/em>|<i>|<\/i>|"
                         b"<b>|<\/b>|<strong[^>]*>|<\/strong>|<wbr \/>")
        data = re.sub(replace_regex, b'', data)
        # Parse HTML
        soup = BeautifulSoup(data, features="lxml")
        # Replace breaks
        for br in soup.find_all("br"):
            br.replace_with("\n")
        # Get text
        #htext = soup.get_text(separator=' ')
        htext = ""
        matches = soup.find_all(text=True)
        for elem in matches:
            if include_all or self.is_visible_element(elem,
                                          include_metadata=include_metadata,
                                          include_links=include_links):
                #log.warning(elem.parent.name)
                #log.warning(elem)
                htext = htext + elem + sep
        #log.warning(htext)
        # TODO: FIX
        return [htext]

    def get_text_elements(self, options=None):
        """Return list of text elements and extraction method"""
        if options is None:
            options = {}
        html_raw = options.get('html_raw', False)
        if (not html_raw):
            html_readable = options.get('html_readable', True)
            if html_readable:
                try:
                    use_readability = options.get('html_use_readability',
                                                        False)
                    html = read_file_as_text(self.filepath)
                    d = simple_json_from_html_string(html,
                                        use_readability=use_readability)
                    text_l = map(lambda x : x['text'], d['plain_text'])
                    method = 'readability' if use_readability else 'readabilipy'
                except:
                    text_l = self.get_text_html(include_all=False,
                                                include_metadata=False,
                                                include_links=False)
                    method = 'html_custom_readable'
            else:
                html_sep = options.get('html_sep', ' ')
                html_include_all = options.get('html_include_all', False)
                html_include_metadata = options.get('html_include_metadata',
                                                      False)
                html_include_links = options.get('html_include_links', False)
                text_l = self.get_text_html(sep=html_sep,
                                      include_all=html_include_all,
                                      include_metadata=html_include_metadata,
                                      include_links=html_include_links)
                method = 'html_custom'
        else:
            text = read_file_as_text(self.filepath)
            text_l = [text]
            method = 'raw'
        return (text_l, method)

