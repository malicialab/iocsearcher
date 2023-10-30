# Copyright (c) MaliciaLab, 2023.
# Do not copy, disclose, or distribute without explicit written permission
# Author: Juan Caballero
#
import re
import logging
import json
from urllib.parse import urlparse, urljoin
import iocsearcher.ioc
from iocsearcher.doc_html import Html

# Set logging
log = logging.getLogger(__name__)

class ExtendedHtml(Html):
    tmap = {
        'alternateName' : 'organization',
        'legalName' : 'organization',
        'name' : 'organization',
        'url' : 'url',
    }
    amap = {
        #'addressCountry' : 'country',
        'addressLocality' : 'city',
        'addressRegion' : 'state',
        #'postalCode' : 'postal_code',
        'streetAddress' : 'street',
    }
    def __init__(self, filepath, mime_type=None, create_ioc_fun=None):
        Html.__init__(self, filepath, mime_type=mime_type)
        # IOC creation function
        if create_ioc_fun is not None:
            self.create_ioc = create_ioc_fun
        else:
            self.create_ioc = iocsearcher.ioc.create_ioc

    def get_identity(self, searcher, s):
        """Extract url, fqdn, or identify from input string"""
        iocs = set()
        url_iocs = searcher.search_data(s, targets={'url'})
        if url_iocs:
            iocs.update(url_iocs)
        else:
            url_iocs = searcher.search_data(s, targets={'fqdn'})
            if url_iocs:
                iocs.update(url_iocs)
            elif (s[0] != '/') and (len(s) > 2):
                iocs.add(self.create_ioc("identity", s))
        return iocs

    def metadata_iocs(self, searcher, metadata):
        """Extract IOCs from given metadata dictionary"""
        iocs = set()
        for key, value in metadata.items():
          if not value:
              continue
          if key in ["author", "Author", "changedby", 
                      "shareaholic:article_author_name"]:
              iocs.add(self.create_ioc("identity", value))
          elif key in ["twitter:site", "twitter:creator"]:
              url_iocs = searcher.search_data(value, targets={'twitterHandle'})
              if url_iocs:
                  iocs.update(url_iocs)
              elif re.search("^@?[a-zA-Z0-9_]{3,15}$", value):
                  iocs.add(self.create_ioc("twitterHandle", value))
              else:
                  iocs.update(self.get_identity(searcher, value))
          elif key in ["og:url", "twitter:url", "twitter:domain",
                        "msapplication-starturl"]:
              iocs.update(self.get_identity(searcher, value))
          elif key in ["article:publisher", "article:author"]:
              url_iocs = searcher.search_data(value, 
                                          targets={'facebookHandle'})
              if url_iocs:
                  iocs.update(url_iocs)
              else:
                  iocs.update(self.get_identity(searcher, value))
          elif key in ["copyright", "copyrightHolder", "Copyright"]:
              copyright_iocs = searcher.search_data(value, 
                                                    targets={'copyright'})
              if copyright_iocs:
                  iocs.update(copyright_iocs)
              else:
                  iocs.update(self.get_identity(searcher, value))
          elif key in ["apple-itunes-app", "twitter:app:id:iphone", 
                        "al:ios:app_store_id"]:
              match = re.search("(?:app-id=|id)?(\d+)", value)
              if match:
                  iocs.add(self.create_ioc("appId", match.group(1),
                                      market="AppleStore"))
          elif key in ["google-play-app", "al:android:package"]:
              match = re.search("(?:app-id=)?([A-Za-z][A-Za-z0-9_\.]+)", value)
              if match:
                  iocs.add(self.create_ioc("packageName", match.group(1),
                                      market="GooglePlay"))

        return iocs

    def get_html_schema_entries(self):
        """Search HTML for schema.org data
            Returns dictionary type -> entry list
        """
        # Iterate on scripts to get list of entries
        entry_l = []
        for script in self.soup.find_all("script", 
                                          {"type":"application/ld+json"}):
            # Get JSON
            try:
                data = json.loads("".join(script.contents), strict=False)
            except json.decoder.JSONDecodeError:
                log.warning("Error decoding ld+json")
                continue
            # Outer entry could be dictionary or list
            if isinstance(data, dict):
                l = data.get("@graph", [data])
                entry_l.extend(l)
            elif isinstance(data, list):
                for e in data:
                    if e:
                        l = e.get("@graph", [e])
                        entry_l.extend(l)
            else:
                log.warning("Unknown entry in ld+json")
                continue

        # Process entries
        entries = {}
        for entry in entry_l:
            try:
                otype = entry.get('@type', None)
            except AttributeError:
                log.warning("Error decoding ld+json")
                continue
            log.debug("Entry: %s" % otype)
            if otype is None:
                continue
            if isinstance(otype, list):
                if "Person" in otype:
                    entries.setdefault("Person", []).append(entry)
                elif "Organization" in otype:
                    entries.setdefault("Organization", []).append(entry)
                else:
                    for o in otype:
                        entries.setdefault(o, []).append(entry)
            else:
                entries.setdefault(otype, []).append(entry)
        # Return dictionary
        return entries

    def postalAddress_iocs(self, entry):
        """Schema.org PostaAddress IOC extraction"""
        iocs = set()
        data = {}
        for field, fvalue in entry.items():
            if not fvalue:
                continue
            if type(fvalue) is list:
                fvalue = ', '.join(fvalue)
            attr = self.amap.get(field, None)
            if attr:
                data[attr] = fvalue
            elif field == "postalCode":
                data['postal_code'] = str(fvalue)
            elif field == "addressCountry":
                if type(fvalue) is dict:
                    country = fvalue.get("name", None)
                    if country:
                        data["country"] = country
                else:
                    data["country"] = fvalue
        if len(data) > 0:
            iocs.add(self.create_ioc("physicalAddress", None,
                              attributes=data))
        return iocs

    def address_iocs(self, entry):
        """Schema.org Address IOC extraction"""
        iocs = set()
        tvalue = type(entry)
        if (tvalue is str):
            iocs.add(self.create_ioc("physicalAddress", entry))
        elif (tvalue is list):
            for a in entry:
                iocs.update(self.address_iocs(a))
        else:
            iocs.update(self.postalAddress_iocs(entry))
        return iocs

    def place_iocs(self, entry):
        """Schema.org Place IOC extraction"""
        iocs = set()
        for field, value in entry.items():
            log.debug("PlaceField: %s" % field)
            if not value:
                continue
            # telephone
            if field == "telephone":
                phone_str = re.sub('[^+0-9]','', value)
                if phone_str:
                    iocs.add(self.create_ioc("phoneNumber", phone_str))
            # address
            elif field == "address":
                iocs.update(self.address_iocs(value))
        # Return IOCs
        return iocs

    def person_iocs(self, searcher, entry):
        """Schema.org Person IOC extraction"""
        iocs = set()
        for field, value in entry.items():
            log.debug("PersonField: %s" % field)
            if not value:
                continue
            # name
            if field == "name":
                iocs.add(self.create_ioc("personName", value))
            # sameAs
            elif field == "sameAs":
                for url in value:
                    url_iocs = searcher.search_url(
                                  url, additional_targets=['email', 'url'])
                    if url_iocs:
                        iocs.update(url_iocs)

        return iocs

    def organization_iocs(self, searcher, entry):
        """Schema.org Address IOC extraction"""
        iocs = set()
        tvalue = type(entry)
        if (tvalue is str):
            iocs.add(self.create_ioc("organization", entry))
        elif (tvalue is list):
            for a in entry:
                iocs.update(self.organization_iocs(searcher, a))
        else:
            iocs.update(self.org_iocs(searcher, entry))
        return iocs

    def org_iocs(self, searcher, entry):
        """Schema.org Organization IOC extraction"""
        iocs = set()
        for field, value in entry.items():
            log.debug("OrgField: %s" % field)
            if not value:
                continue
            # Get list of values to process
            vtype = type(value)
            if vtype is dict:
                l = value.values()
            elif vtype is list:
                if type(value[0]) is list:
                    l = value[0]
                else:
                    l = value
            else:
                l = [value]
            # Process values according to field type
            ioc_type = self.tmap.get(field, None)
            if ioc_type:
                for v in l:
                    if v:
                        iocs.add(self.create_ioc(ioc_type, v))
            # email
            elif field == "email":
                for v in l:
                    if v:
                        email_iocs = searcher.search_data(v, targets=['email'])
                        if email_iocs:
                            iocs.update(email_iocs)
            # telephone
            elif field in ["telephone", "telePhone"]:
                for v in l:
                    if v:
                        phone_str = re.sub('[^+0-9]','', v)
                        if phone_str:
                            iocs.add(self.create_ioc("phoneNumber", phone_str))
            # sameAs
            elif field == "sameAs":
                for v in l:
                    if v:
                        url_iocs = searcher.search_url(v,
                                          additional_targets=['email', 'url'])
                        if url_iocs:
                            iocs.update(url_iocs)
            # address
            elif field == "address":
                iocs.update(self.address_iocs(value))
            # parentOrganization, subOrganization
            elif field in ["parentOrganization", "subOrganization"]:
                iocs.update(self.organization_iocs(searcher, value))
        # TODO: contactPoint, location
        # Return IOCs
        return iocs

    def html_schema_entry_iocs(self, searcher, entry, etype):
        """Extract IOCs from schema.org entry"""
        if etype in ["Organization", "organization", "Corporation",
                     "LocalBusiness", "NewsMediaOrganization",
                     "TouristInformationCenter", "NGO", "RadioStation"]:
            return self.organization_iocs(searcher, entry)
        elif etype == "Place":
            return self.place_iocs(entry)
        elif etype == "Person":
            return self.person_iocs(searcher, entry)
        else:
            return set()

    def get_html_schema_iocs(self, searcher):
        """Return IOCs in schema.org entries"""
        iocs = set()
        try:
            entry_dict = self.get_html_schema_entries()
            for etype, entry_l in entry_dict.items():
                for entry in entry_l:
                    iocs.update(self.html_schema_entry_iocs(searcher, entry,
                                                              etype))
        except Exception as e:
            log.warning("Failed processing Schema.org data with exception %s"
                          % e)
        return iocs

    def get_html_script_iocs(self, searcher):
        """Search scripts in HTML for IOCs"""
        iocs = set()
        # Iterate on scripts
        for node in self.soup.find_all(["script", "noscript"]):
            script_iocs = searcher.search_data(str(node), [
                                                      'googleAdsense',
                                                      'googleAnalytics',
                                                      'googleTagManager'])
            if script_iocs:
                iocs.update(script_iocs)
        return iocs

    def get_html_headings(self):
        """Return list of (heading,text) in HTML"""
        acc = []
        heading_tags = ["h1","h2","h3","h4","h5","h6"]
        for node in self.soup.find_all(heading_tags):
            acc.append((node.name, node.text))
        return acc

    def get_base_url(self):
        """Return the base URL for the HTML document or None"""
        # Check base tag
        base_tag = self.soup.find('base')
        base_url = base_tag.get('href', None) if base_tag else None
        if base_url:
            return base_url
        # Check og:url
        ogurl_tag = self.soup.find("meta", property="og:url", content=True)
        base_url = ogurl_tag.get('content', None) if ogurl_tag else None
        return base_url

    def get_contacturl_ioc(self, link, base_url=None):
        """Return contactUrl IOC from link node.
            Returns None if not a contact link"""
        ioc = None
        ioc_url = None
        url = link.get('href')
        # Ignore anchors
        if url[0] == '#':
            return None
        try:
            parsed_url = urlparse(url)
        except ValueError:
            log.info(f"ValueError while parsing URL: {url}")
            return None
        # Ignore non HTTP(S) schemes
        if (parsed_url.scheme and (parsed_url.scheme not in ['http', 'https'])):
            return None
        # Check for ZenDesk URLs
        match = re.match("/hc/[^/]+/requests/new", parsed_url.path)
        if match:
            ioc_url = url
        # Check if link text contains keywords
        contact_re = r"contact|support"
        match = re.match(contact_re, link.text, re.IGNORECASE)
        if match:
            ioc_url = url
        # Check if URL contains keywords
        match = re.search(contact_re, url, re.IGNORECASE)
        if match:
            ioc_url = url
        # Create IOC (add base URL if needed)
        if ioc_url:
            if (not parsed_url.scheme) and base_url:
                ioc_url = urljoin(base_url, ioc_url)
            ioc = self.create_ioc("contactUrl", ioc_url)
        return ioc

    def get_abouturl_ioc(self, link, base_url=None):
        """Return aboutUrl IOC from link node.
            Returns None if not a contact link
        """
        ioc = None
        ioc_url = None
        url = link.get('href')
        # Ignore anchors
        if url[0] == '#':
            return None
        try:
            parsed_url = urlparse(url)
        except ValueError:
            log.info(f"ValueError while parsing URL: {url}")
            return None
        # Ignore non HTTP(S) schemes
        if (parsed_url.scheme and (parsed_url.scheme not in ['http', 'https'])):
            return None
        # Check if link text contains keywords
        match = re.match("about", link.text, re.IGNORECASE)
        if match:
            ioc_url = url
        # Check if URL contains keywords
        match = re.search("about", url, re.IGNORECASE)
        if match:
            ioc_url = url
        # Create IOC (add base URL if needed)
        if ioc_url:
            if (not parsed_url.scheme) and base_url:
                ioc_url = urljoin(base_url, ioc_url)
            ioc = self.create_ioc("aboutUrl", ioc_url)
        return ioc

    def get_tosurl_ioc(self, link, base_url=None):
        """Return tosUrl IOC from link node.
            Returns None if not a contact link
        """
        ioc = None
        ioc_url = None
        url = link.get('href')
        # Ignore anchors
        if url[0] == '#':
            return None
        try:
            parsed_url = urlparse(url)
        except ValueError:
            log.info(f"ValueError while parsing URL: {url}")
            return None
        # Ignore non HTTP(S) schemes
        if (parsed_url.scheme and (parsed_url.scheme not in ['http', 'https'])):
            return None
        # Check if link text contains keywords
        match = re.match("terms", link.text, re.IGNORECASE)
        if match:
            ioc_url = url
        # Check if URL contains keywords
        match = re.search("terms", url, re.IGNORECASE)
        if match:
            ioc_url = url
        # Create IOC (add base URL if needed)
        if ioc_url:
            if (not parsed_url.scheme) and base_url:
                ioc_url = urljoin(base_url, ioc_url)
            ioc = self.create_ioc("tosUrl", ioc_url)
        return ioc

    def get_privacyurl_ioc(self, link, base_url=None):
        """Return aboutUrl IOC from link node.
            Returns None if not a contact link
        """
        ioc = None
        ioc_url = None
        url = link.get('href')
        # Ignore anchors
        if url[0] == '#':
            return None
        try:
            parsed_url = urlparse(url)
        except ValueError:
            log.info(f"ValueError while parsing URL: {url}")
            return None
        # Ignore non HTTP(S) schemes
        if (parsed_url.scheme and (parsed_url.scheme not in ['http', 'https'])):
            return None
        # Check if link text contains keywords
        match = re.match("privacy", link.text, re.IGNORECASE)
        if match:
            ioc_url = url
        # Check if URL contains keywords
        match = re.search("privacy", url, re.IGNORECASE)
        if match:
            ioc_url = url
        # Create IOC (add base URL if needed)
        if ioc_url:
            if (not parsed_url.scheme) and base_url:
                ioc_url = urljoin(base_url, ioc_url)
            ioc = self.create_ioc("privacyUrl", ioc_url)
        return ioc

    def get_html_link_iocs(self, searcher, base_url=None, all_links=True):
        """Search links in HTML for non-URL IOCs"""
        iocs = set()
        # Get base URL
        if base_url is None:
            base_url = self.get_base_url()
        # Iterate on links
        for link in self.soup.find_all("a"):
            url = link.get('href')
            if not url:
                continue
            # Check for CloudFlare encoded emails
            if url == "/cdn-cgi/l/email-protection":
                encoded_email = link.get('data-cfemail', None)
                if encoded_email:
                    email = cfDecodeEmail(encoded_email)
                    email_iocs = searcher.search_data(email, targets=['email'])
                    iocs.update(email_iocs)
            # Check for contactUrl
            contact_ioc = self.get_contacturl_ioc(link, base_url=base_url)
            if contact_ioc:
                iocs.add(contact_ioc)
                continue
            # Check for aboutUrl
            about_ioc = self.get_abouturl_ioc(link, base_url=base_url)
            if about_ioc:
                iocs.add(about_ioc)
                continue
            # Check for tosUrl
            tos_ioc = self.get_tosurl_ioc(link, base_url=base_url)
            if tos_ioc:
                iocs.add(tos_ioc)
                continue
            # Check for privacyUrl
            privacy_ioc = self.get_privacyurl_ioc(link, base_url=base_url)
            if privacy_ioc:
                iocs.add(privacy_ioc)
                continue
            # Process URL based on scheme
            idx = url.find(':')
            if idx == -1:
                continue
            scheme = url[0:idx].lower()
            if scheme in [ "http", "https" ]:
                value = url[idx+1:]
                handle_iocs = searcher.search_url(value)
                if handle_iocs:
                    iocs.update(handle_iocs)
                elif all_links:
                    url_ioc = self.create_ioc('url', url)
                    iocs.add(url_ioc)
            elif scheme == "tel":
                value = url[idx+1:]
                phone_str = re.sub('[^+0-9]','', value)
                if phone_str:
                    found_ioc = self.create_ioc('phoneNumber', phone_str)
                    iocs.add(found_ioc)
            elif scheme == "mailto":
                value = url[idx+1:]
                email_iocs = searcher.search_data(value, targets=['email'])
                if email_iocs:
                    iocs.update(email_iocs)
            elif scheme == "sms":
                end_idx = url.rfind('?')
                if end_idx != -1:
                    value = url[idx+1:end_idx]
                else:
                    value = url[idx+1:]
                phone_str = re.sub('[^+0-9]','', value)
                if phone_str:
                    found_ioc = self.create_ioc('phoneNumber', phone_str)
                    iocs.add(found_ioc)
            elif scheme == "skype":
                end_idx = url.rfind('?')
                if end_idx != -1:
                    value = url[idx+1:end_idx]
                else:
                    value = url[idx+1:]
                found_ioc = self.create_ioc('skypeHandle', value)
                iocs.add(found_ioc)
            # other schemes: bitcoin, bitcoincash, ethereum, geo
        # Return IOCs
        return iocs

    def get_html_address_iocs(self, searcher):
        """Get physicalAddress IOCs from HTML <address> tags"""
        iocs = set()
        for node in self.soup.find_all("address"):
            # Remove internal <script>, <noscript>, links
            if node.script:
                node.script.replace_with('')
            if node.noscript:
                node.noscript.replace_with('')
            if node.a:
                node.a.replace_with('')
            # Get remaining text
            s = ''.join(node.get_text(separator=' ')).strip()
            if not s:
                continue
            # It is not uncommon to have a copyright
            copyright_iocs = searcher.search_data(s, ['copyright'])
            if copyright_iocs:
                iocs.update(copyright_iocs)
                continue
            # If contains no digits, not an interesting address, ignore
            has_digit = any(char.isnumeric() for char in s)
            if (not has_digit):
                continue
            # Replace EOF with comma
            s = re.sub('\s*\n\s*', ', ', s)
            # Some cleaning
            s = re.sub('\s+,', ',', s)
            s = re.sub('\s+', ' ', s)
            s = re.sub(',[,]+', ',', s)
            # Create IOC
            found_ioc = self.create_ioc('physicalAddress', s)
            iocs.add(found_ioc)
        return iocs

