# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import os
import re
import logging
import ipaddress
import phonenumbers
from base64 import b32decode
from hashlib import sha3_256
from urllib.parse import urlparse
import configparser as ConfigParser

# Import optional third-party libraries
try:
    import coinaddrvalidator
    can_validate_blockchain_addr = True
except ImportError:
    can_validate_blockchain_addr = False

# Set logging
log = logging.getLogger(__name__)

# Default data files
script_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(script_dir, 'data/')
default_patterns_file = os.path.join(data_dir, 'patterns.ini')
default_tlds_file = os.path.join(data_dir, 'tlds-alpha-by-domain.txt')

# Map language to countries
lang_countries = {
    'en' : ['US', 'GB', 'CA', 'AU', 'IN'],
    'de' : ['DE'],
    'es' : ['ES', 'MX'],
    'fr' : ['FR'],
    'it' : ['IT'],
}

# Default IOC creation function
def default_create_ioc(name, value):
    ''' Create IOC from its name and value '''
    return (name, value)

class Searcher:
    # Static regular expressions for rearming IOCs
    re_dots = re.compile(r'\[\.\]|\[\]|\(dot\)|\[dot\]|\(\.\)', re.I)
    re_at = re.compile(r' at |\(at\)| \(at\) |\[at\]| \[at\] ', re.I)
    re_http = re.compile(r'^(hxxp|h___p|httx|hpp)', re.I)
    re_private_ip = re.compile(r'^(192.168.|10.|172.(1[6-9]|2[0-9]|3[0-1]))')

    def __init__(self, patterns_ini=None, tld_filepath=None,
                        create_ioc_fun=None):
        # Patterns file
        self.patterns_ini = patterns_ini or default_patterns_file
        # TLDs file
        self.tld_filepath = tld_filepath or default_tlds_file
        # IOC names to be validated
        self.validate = set()
        # IOC creation function
        if create_ioc_fun is not None:
            self.create_ioc = create_ioc_fun
        else:
            self.create_ioc = default_create_ioc
        # Read TLDs
        self.tlds = self.read_tlds(self.tld_filepath)
        self.tlds.add("onion")
        log.debug("Read %d TLDs" % len(self.tlds))
        # Read patterns
        self.patterns = self.read_patterns(self.patterns_ini)
        log.debug("Read regexps for %d IOCs" % len(self.patterns))

    @classmethod
    def rearm_dots(cls, s):
        return re.sub(cls.re_dots, '.', s)

    @classmethod
    def rearm_email(cls, s):
        s = re.sub(cls.re_at, '@', s)
        return cls.rearm_dots(s)

    @classmethod
    def rearm_fqdn(cls, s):
        return cls.rearm_dots(s)

    @classmethod
    def rearm_ip(cls, s):
        return cls.rearm_dots(s)

    @classmethod
    def rearm_ipNet(cls, s):
        return cls.rearm_dots(s)

    @classmethod
    def rearm_url(cls, s):
        s = re.sub(cls.re_http, 'http', s)
        return cls.rearm_dots(s)

    def is_valid_tld(self, s):
        ''' Check if given string is a valid TLD according to IANA list '''
        # To help address common issues such a period not followed by a space
        # we allow 'COM' and 'com', but not 'Com' and 'CoM'
        if re.match('[A-Z][a-z]', s):
            return False
        # Check that TLD in lowercase appears in IANA list
        s = s.lower()
        return (self.tlds is None) or (s in self.tlds) or s.startswith('xn--')

    def is_valid_fqdn(self, s):
        ''' Check if given string ends with valid TLD according to IANA '''
        idx = s.rfind('.')
        return (idx != -1) and self.is_valid_tld(s[idx+1:])

    def is_valid_email(self, s):
        ''' Check if given string ends with valid TLD according to IANA '''
        idx = s.rfind('.')
        return (idx != -1) and self.is_valid_tld(s[idx+1:])

    def is_valid_packageName(self, s):
        ''' Check if given string starts with valid TLD according to IANA '''
        tokens = s.split('.')
        return (len(tokens) > 1) and self.is_valid_tld(tokens[0])

    @classmethod
    def is_valid_ip(cls, s, ignore_private=True):
        ''' Check if given string is a valid IPv4 or IPv6 address '''
        try:
            ipaddress.ip_address(s)
            if ignore_private:
                return (cls.re_private_ip.match(s) is None)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_ipNet(s):
        ''' Check if given string is a valid IPv4 or IPv6 network '''
        try:
            ipaddress.ip_network(s)
            return True
        except ValueError:
            return False

    def is_valid_url(self, s):
        ''' Check if given string is a valid URL by extracting host
            and checking if IP or valid TLD '''
        try:
            if ("://" in s[0:15]):
                parsed = urlparse(s)
            else:
                parsed = urlparse("http://" + s)
        except ValueError:
            return False
        if not parsed.hostname:
            return False
        # Validate URLs with IP address
        tokens = parsed.hostname.split('.')
        if tokens[-1].isdigit():
            # Avoid ipNet
            if re.match('/[0-9]{1,2}$', parsed.path):
                return False
            return __class__.is_valid_ip(parsed.hostname)
        # Validate Onion URLs
        #elif tokens[-1] == 'onion':
        #    return self.is_valid_onionAddress(tokens[-2])
        # Validate URLs with FQDN
        else:
            return self.is_valid_tld(tokens[-1])

    @staticmethod
    def is_valid_nif(s):
        ''' Check if given string is a valid Spanish NIF or NIE  '''
        tabla = "TRWAGMYFPDXBNJZSQVHLCKE"
        dig_ext_map = {'X':'0','Y':'1','Z':'2'}
        # Remove hyphens
        s = s.replace('-', '')
        # Check valid length
        if len(s) != 9:
            return False
        # Everything except first and last characters have to be digits
        middle = s[1:-1]
        if not middle.isdigit():
            return False
        # Convert to uppercase
        s = s.upper()
        # The first character determines the type
        initial = s[0]
        # The last character is the checksum
        control = s[-1]
        # NIE
        if initial in dig_ext_map:
            number = s[:8].replace(initial, dig_ext_map[initial])
            return tabla[int(number)%23] == control
        # NIF (person)
        elif initial.isdigit():
            number = s[:8]
            return tabla[int(number)%23] == control
        # K: Spanish younger than 14 year old
        # L: Spanish living outside Spain without DNI
        # M: Foreigners without NIE
        elif initial in 'KLM':
            return tabla[int(middle)%23] == control
        # NIF (legal) (old CIF)
        elif initial in 'ABCDEFGHJNPQRSUVW':
            alphabet = '0123456789'
            number = middle + alphabet[0]
            n = len(alphabet)
            number = tuple(alphabet.index(i)
                           for i in reversed(str(number)))
            ck = (sum(number[::2]) +
                    sum(sum(divmod(i * 2, n))
                        for i in number[1::2])) % n
            check = alphabet[-ck]
            check2 = check + 'JABCDEFGHI'[int(check)]
            return control in check2
        else:
          return False

    @staticmethod
    def is_valid_uuid(s):
        ''' Check if given string has valid UUID version and variant '''
        tokens = s.split('-')
        num_tokens = len(tokens)
        try:
            version = int(tokens[2][0])
            variant = tokens[3][0]
            return ((num_tokens==5) and
                    (version >= 1) and (version <= 5) and
                    (variant in '89abAB'))
        except Exception:
            return False

    @staticmethod
    def copyright_entity(s):
        ''' Extract entity from copyright string '''
        # Remove variations of: "All Rights Reserved", "copyright", "(c)", years
        regexp = re.compile(
              "((?:[.\-,–;]+)?(?:[ ]+)?All Right[s]? Reserved( to|\.)?)|"
              "((?:©|\(C\)|&copy;|\xA9)(?:\s+)?[.,\-]?)|"
              "(@)|"
              "([12][0-9]{3}\s?[--–—]\s?(?:[12][0-9]{3}|present)"
                    "(?:\s+by)?(?:[\s.,\-\/]+)?)|"
              "([12][0-9]{3}(?:\s+by)?(?:[\s.,\-\/]+)?)|"
              "(CopyRight)",
              re.UNICODE | re.I)
        cleaned = regexp.sub('',  s).strip()
        return cleaned

    @staticmethod
    def is_valid_copyright(s):
        ''' Check if given copyright string has a non-empty entity '''
        entity = __class__.copyright_entity(s)
        return entity != ""

    @staticmethod
    def is_valid_coinaddr(s, addr_type, network_type="main"):
        ''' Use coinaddr library to validate virtual currency address '''
        if not can_validate_blockchain_addr:
            return True
        # Validate checksum
        try:
            result = coinaddrvalidator.validate(addr_type, s)
            return result.valid and (result.network == network_type)
        except (ValueError,TypeError):
            return False

    @staticmethod
    def is_valid_bitcoin(s, network_type="main"):
        ''' Check if given string is a valid Bitcoin address
            by validating its checksum '''
        # cryptoaddr does not seem to support BECH addresses
        #if s.startswith("bc1"):
        #    return True
        return __class__.is_valid_coinaddr(s, 'btc', network_type)

    @staticmethod
    def is_valid_bitcoincash(s, network_type="main"):
        ''' Check if given string is a valid BitcoinCash address
            by validating its checksum '''
        # coinaddrvalidator does not seem to support Bitcoin Cash correctly
        # It returns valid=False for valid addresses like
        # qz7xc0vl85nck65ffrsx5wvewjznp9lflgktxc5878
        return True
        # return __class__.is_valid_coinaddr(s, 'bitcoin-cash', network_type)

    @staticmethod
    def is_valid_dashcoin(s, network_type="main"):
        ''' Check if given string is a valid Dashcoin address
            by validating its checksum '''
        return __class__.is_valid_coinaddr(s, 'dashcoin', network_type)

    @staticmethod
    def is_valid_dogecoin(s, network_type="main"):
        ''' Check if given string is a valid Dogecoin address
            by validating its checksum '''
        return __class__.is_valid_coinaddr(s, 'dogecoin', network_type)

    @staticmethod
    def is_valid_ethereum(s, network_type="both"):
        ''' Check if given string is a valid Ethererum address
            by validating its checksum '''
        return __class__.is_valid_coinaddr(s, 'ethereum', network_type)

    @staticmethod
    def is_valid_litecoin(s, network_type="main"):
        ''' Check if given string is a valid Litecoin address
            by validating its checksum '''
        return __class__.is_valid_coinaddr(s, 'litecoin', network_type)

    @staticmethod
    def is_valid_tezos(s):
        ''' Check if given string is a valid Tezos address
            by validating its checksum '''
        # We cannot use is_valid_coinaddr since coinaddrvalidator.validate
        # returns valid=False for valid Tezos addresses
        # Also coinaddrvalidator.validate seems to validate incorrect addresses
        # For example, tz1L9r8mWmRpndRhuvMCWESLGSVeFzQ9NAWx validates
        # but should not according to https://tezostaquito.io/docs/validators/
        if not can_validate_blockchain_addr:
            return True
        try:
            result = coinaddrvalidator.validate('tezos', s)
            return result.address_type != ''
        except:
            return False

    @staticmethod
    def is_valid_zcash(s, network_type="main"):
        ''' Check if given string is a valid ZCash address
            by validating its checksum '''
        # coinaddrvalidator does not seem to support ZCash correctly
        # It returns valid=False for valid addresses like
        # t1fSVQStheqdugmoN2LKy6WZzdSc29m7Wze
        return True
        # return __class__.is_valid_coinaddr(s, 'zcash', network_type)

    @staticmethod
    def is_valid_telegramHandle(s):
        ''' Check if given string is a valid Telegram handle '''
        return s not in {'joinchat', 'share', 'username'}

    @staticmethod
    def is_valid_twitterHandle(s):
        ''' Check if given string is a valid Twitter handle '''
        return s not in {'author_handle', 'home', 'https', 'intent',
                          'personalization', 'privacy',
                          'rules', 'search', 'settings', 'share',
                          'terms', 'tos', 'web', 'widgets', 'your_twitter_da'}

    @staticmethod
    def is_valid_facebookHandle(s):
        ''' Check if given string is a valid Facebook handle '''
        return s not in {'about', 'ads', 'business', 'dialog', 'docs',
                            'events', 'help',
                            'full', 'groups', 'legal', 'pages',
                            'plugins', 'policy', 'policy.php', 'policies',
                            'privacy', 'settings', 'share', 'share.php',
                            'sharer', 'sharer.php'}

    @staticmethod
    def is_valid_instagramHandle(s):
        ''' Check if given string is a valid Instagram handle '''
        return s not in {'about', 'legal'}

    @staticmethod
    def is_valid_pinterestHandle(s):
        ''' Check if given string is a valid Pinterest handle '''
        return s not in {'https', 'pin', 'static'}

    @staticmethod
    def is_valid_githubHandle(s):
        ''' Check if given string is a valid GitHub handle '''
        return s not in {'about', 'auth', 'buttons', 'contact', 'events',
                          'fluidicon', 'github', 'notifications', 'pricing',
                          'readme', 'security', 'site', '_private'}

    @staticmethod
    def is_valid_linkedinHandle(s):
        ''' Check if given string is a valid LinkedIn handle '''
        return True

    @staticmethod
    def is_valid_youtubeHandle(s):
        ''' Check if given string is a valid YouTube handle '''
        return s not in {'channel', 'embed', 'feed', 'iframe',
                          'player', 'playlist', 'privacynotice',
                          'static', 'watch', 'yt'}

    @staticmethod
    def is_valid_youtubeChannel(s):
        ''' Check if given string is a valid YouTube channel '''
        return True

    def is_valid_phone(self, s, country=None, language=None):
        ''' Check if given string is a valid phone '''
        # If country provided, validate it using the country
        if country:
            try:
                number = phonenumbers.parse(s, country)
                return phonenumbers.is_valid_number(number)
            except phonenumbers.phonenumberutil.NumberParseException:
                return False
        # If language provided, validate each candidate country
        if language:
            cc_l = lang_countries.get(language, [])
            for cc in cc_l:
                try:
                    number = phonenumbers.parse(s, cc)
                except phonenumbers.phonenumberutil.NumberParseException:
                    continue
                if phonenumbers.is_valid_number(number):
                    return True
            # Not valid for any countries for this language
            return False
        # If it can be validated without country, then valid E164 format
        try:
            number = phonenumbers.parse(s)
            return phonenumbers.is_valid_number(number)
        except phonenumbers.phonenumberutil.NumberParseException:
            pass
        # Otherwise, take a guess based on length
        digit_str = re.sub('[^0-9]','', s)
        l = len(digit_str)
        return (l >= 3) and (l <= 15)

    @staticmethod
    def is_valid_onionAddress(s):
        ''' Return true if the input string is a valid Tor onion v3 address '''
        if not s.endswith('d'):
            return False
        # Validate the embedded checksum
        decoded = b32decode(s.upper())
        v3_pubkey = decoded[:32]
        v3_checksum = decoded[32:34]
        v3_version = int(3).to_bytes(1, 'little')
        expected_checksum = sha3_256(".onion checksum".encode('utf-8') +
                                      v3_pubkey + v3_version).digest()[:2]
        return expected_checksum == v3_checksum

    @staticmethod
    def is_valid_iban(s):
        ''' Return true if the input string is a valid IBAN
            An IBAN comprises of 15-32 alphanumeric characters with format:
              2 characters for country code
              2 control characters (checksum)
              up to 28 account characters depending on country
            Validator checks length for country and IBAN checksum
        '''
        iban_length = {
            "AD":24, "AE":23, "AT":20, "AZ":28, "BA":20, "BE":16,
            "BG":22, "BH":22, "BR":29, "CH":21, "CR":21, "CY":28,
            "CZ":24, "DE":22, "DK":18, "DO":28, "EE":20, "ES":24,
            "FI":18, "FO":18, "FR":27, "GB":22, "GI":23, "GL":18,
            "GR":27, "GT":28, "HR":21, "HU":28, "IE":22, "IL":23,
            "IS":26, "IT":27, "JO":30, "KW":30, "KZ":20, "LB":28,
            "LI":21, "LT":20, "LU":20, "LV":21, "MC":27, "MD":24,
            "ME":22, "MK":19, "MR":27, "MT":31, "MU":30, "NL":18,
            "NO":15, "PK":24, "PL":28, "PS":29, "PT":25, "QA":29,
            "RO":24, "RS":22, "SA":24, "SE":24, "SI":19, "SK":24,
            "SM":27, "TN":24, "TR":26, "AL":28, "BY":28, "CR":22, 
            "EG":29, "GE":22, "IQ":23, "LC":32, "SC":31, "ST":25,
            "SV":28, "TL":23, "UA":29, "VA":22, "VG":24, "XK":20
        };
        conversion={"A":10, "B":11, "C":12, "D":13, "E":14, "F":15, "G":16,
                    "H":17, "I":18, "J":19, "K":20, "L":21, "M":22, "N":23,
                    "O":24, "P":25, "Q":26, "R":27, "S":28, "T":29, "U":30,
                    "V":31, "W":32, "X":33, "Y":34, "Z":35}

        # These could be done before invocation
        iban=s.strip().upper()
        iban=iban.replace(" ", "").replace("-", "");

        # Check length
        cc = iban[0:2]
        l = len(iban)
        expected_length = iban_length.get(cc, None)
        if (expected_length is None) or (expected_length != l):
            return False

        # Check IBAN checksum
        check_str = ""
        for c in iban[4:]:
          if c.isdigit():
              check_str += c
          else:
              check_str = ("%s%s" % (check_str,conversion[c]))
        check_str = "%s%s%s%s" % (
                              check_str,
                              conversion[iban[0:1]],
                              conversion[iban[1:2]],
                              iban[2:4])
        return (int(check_str)%97) == 1

    def read_patterns(self, filepath):
        ''' Reads regexp in INI file and returns them as a map '''
        patterns = {}
        # Read configuration file
        config = ConfigParser.SafeConfigParser()
        config.readfp(open(filepath, "r", encoding="utf8"))

        # Iterate on sections
        for sec in config.sections():
            # IOC name is section without trailing digits separated by hyphen
            ioc_name = re.sub('\-[0-9]+$','', sec)
            # Read pattern
            try:
                ioc_pattern = config.get(sec, 'pattern')
            except ConfigParser.Error:
                log.warning("Missing pattern in %s" % sec)
                continue

            # Read flags
            try:
                flag_str = config.get(sec, 'flags')
                tokens = flag_str.split('|')
                flags = 0
                for t in tokens:
                    t = t.strip()
                    if t == "IGNORECASE":
                        flags |= re.I
                    elif t == "UNICODE":
                        flags |= re.UNICODE
                    else:
                        log.warning("Unknown flag %s" % flags_str)
            except ConfigParser.Error:
                flags = 0

            # Check whether IOC needs to be validated
            try:
                if config.getboolean(sec, 'validate'):
                    self.validate.add(ioc_name)
            except ConfigParser.Error:
                pass

            # Compile regexp and store it
            if ioc_pattern:
                ioc_regex = re.compile(ioc_pattern, flags)
                patterns.setdefault(ioc_name, []).append(ioc_regex)

        return patterns

    @staticmethod
    def read_tlds(filepath):
        ''' Reads TLDs in IANA file and returns them as a set '''
        fd = open(filepath, 'r')
        tlds = set()
        for line in fd:
            if line == '\n' or line.startswith('#'):
                continue
            tld = line.strip().lower()
            tlds.add(tld)
        fd.close()
        return tlds

    @staticmethod
    def build_alternate_regex(elements, match_word=True):
        ''' Return alternate regex for input strings '''
        if not elements:
            return None
        sorted_l = sorted(list(elements), key=len, reverse=True)
        boundary = "\\b" if match_word else ""
        return "%s(%s)%s" % (boundary, "|".join(sorted_l), boundary)

    def add_iocs_regex(self, iocs, ignore_case=True, match_word=True):
        ''' Add alternate pattern for each ioc type in input list '''
        ioc_map = {}
        num_patterns = 0
        for ioc in iocs:
            ioc_map.setdefault(ioc.name, set()).add(ioc.value)
        for name, values in ioc_map.items():
            # Build alternate regex
            ioc_pattern = self.build_alternate_regex(values, 
                                                      match_word=match_word)
            if ioc_pattern is None:
                return num_patterns
            # Compilation flags
            flags = 0
            if ignore_case:
                flags |= re.I
            # Compile regexp and store it
            if ioc_pattern:
                ioc_regex = re.compile(ioc_pattern, flags)
                self.patterns.setdefault(name, []).append(ioc_regex)
                num_patterns += 1
        # Return number of patterns added
        return num_patterns

    def search_raw(self, data, targets=None):
        ''' Apply targets regexps to input data,
            Returns list of (type, rearmed_value, start_offset, raw_value) '''
        results = []
        for ioc_name, regexes in self.patterns.items():
            # If not a target, skip this IOC name
            if (targets is not None) and (ioc_name not in targets):
                continue
            # Iterate on regexp for IOC name
            for ioc_regex in regexes:
                # Apply regex to data
                matches = ioc_regex.finditer(data)

                # Check matches
                for m in matches:
                    # If groups are defined in the regexp, get the first one
                    # otherwise, get the whole match
                    idx = 1 if m.groups() else 0
                    start_offset = m.start(idx)
                    end_offset = m.end(idx)
                    raw_value = m.group(idx)

                    log.debug("Processing %s %s at [%d,%d)" % (
                              ioc_name, raw_value, start_offset, end_offset))

                    # Rearm
                    if ioc_name in ["email", "fqdn", "ip", "ipNet", "url"]:
                        rearm_func = getattr(self, "rearm_" + ioc_name)
                        rearmed_value = rearm_func(raw_value)
                    else:
                        rearmed_value = raw_value

                    # Validate
                    if ioc_name in self.validate:
                        validate_func = getattr(self, "is_valid_" + ioc_name)
                        if (not validate_func(rearmed_value)):
                            log.debug(
                                "Droping invalid %s match: %s @ %d Raw: %s" % (
                                          ioc_name, rearmed_value,
                                          start_offset, raw_value))
                            continue

                    # Store result tuple (name,value,start,raw_value)
                    results.append((ioc_name, rearmed_value,
                                    start_offset, raw_value))
        return results

    def search_data(self, data, targets=None):
        ''' Wrapper for search_raw that:
            (1) Builds IOCs on the returned rearmed value
            (2) Removes duplicated IOCs that appeared at different positions
            Returns a set of IOCs '''
        results = set()
        for m in self.search_raw(data, targets):
            # Lowercase domains to avoid having same domain capitalized and not
            ioc_value = m[1] if m[0] != 'fqdn' else m[1].lower()
            # Create IOC
            try:
                found_ioc = self.create_ioc(m[0], ioc_value)
            except ValueError:
                log.warning("Failed to create IOC %s %s" % (m[0], m[1]))
                continue
            # Store IOC
            results.add(found_ioc)
        return results

    def search_phone_numbers(self, text, country=None, language=None):
        ''' Search for phone numbers in given text, returns a set of IOCs '''
        iocs = set()
        seen = set()
        # Build list of countries to check
        countries = []
        if country:
            countries = [country]
        elif language:
            countries = lang_countries.get(language, [])
        else:
            countries = [None]
        # Search using each country
        for cc in countries:
            matches = phonenumbers.PhoneNumberMatcher(text, cc)
            for match in matches:
                # If have already found this string,
                # skip as it cannot belong to multiple countries
                digit_str = re.sub('[^0-9]','', match.raw_string)
                if digit_str[-9:] in seen:
                    continue
                seen.add(digit_str[-9:])
                phone = phonenumbers.format_number(match.number,
                                          phonenumbers.PhoneNumberFormat.E164)
                phone_ioc = self.create_ioc("phoneNumber", phone)
                iocs.add(phone_ioc)
        # Return IOCs
        return iocs

    def search_url(self, url, additional_targets=None):
        ''' Search URL for URL-IOCs '''
        url_targets = {
            'facebookHandle',
            'githubHandle',
            'instagramHandle',
            'linkedinHandle',
            'packageName',
            'pinterestHandle',
            'telegramHandle',
            'twitterHandle',
            'whatsappHandle',
            'youtubeHandle',
            'youtubeChannel'
        }
        if additional_targets:
            url_targets.update(additional_targets)
        return self.search_data(url, url_targets)

