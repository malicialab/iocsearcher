# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import os
import re
import logging
import configparser
import ipaddress
import phonenumbers
from base64 import b32decode
from hashlib import sha3_256, sha256
from urllib.parse import urlparse
from intervaltree import Interval, IntervalTree
import base58
import bech32
import binascii
import cashaddress
import cbor
import struct
import solders
from eth_hash.auto import keccak
from solders.pubkey import Pubkey
import iocsearcher.ioc
import iocsearcher.monero.base58

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

# List of supported blockchain addresses
blockchain_map = {
    'bitcoin' : 'btc',
    'bitcoincash' : 'bch',
    'cardano' : 'ada',
    'dashcoin' : 'dash',
    'dogecoin' : 'doge',
    'ethereum' : 'eth',
    'litecoin' : 'ltc',
    'monero' : 'xmr',
    'ripple' : 'xrp',
    'solana' : 'sol',
    'stellar' : 'xlm',
    'tezos' : 'xtz',
    'tron' : 'trx',
    'zcash' : 'zec'
}
blockchain_types = blockchain_map.keys()

# Table for computing Bitcoin Bech32 checksum
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Normalization available for these types
can_normalize = {
    'bitcoin',
    'email',
    'facebookHandle',
    'fqdn',
    'githubHandle',
    'iban',
    'instagramHandle',
    'phoneNumber',
    'pinterestHandle',
    'telegramHandle',
    'twitterHandle',
    'url',
    'youtubeHandle'
}

class Searcher:
    # Static regular expressions for rearming IOCs
    re_dots = re.compile(r'\[\.\]|\[\]|\(dot\)|\[dot\]|\(\.\)', re.I)
    re_at = re.compile(r' at |\(at\)| \(at\) |\[at\]| \[at\] ', re.I)
    re_http = re.compile(r'^(hxxp|h___p|httx|hpp)', re.I)
    re_ethereum_nonchecksummed = re.compile(
                                    "^(0x)?([0-9a-f]{40}|[0-9A-F]{40})$")

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
            self.create_ioc = iocsearcher.ioc.create_ioc
        # Read TLDs
        self.tlds = self.read_tlds(self.tld_filepath)
        self.tlds.add("onion")
        log.debug("Read %d TLDs" % len(self.tlds))
        # Initialize patterns
        self.patterns = {}
        # Read patterns
        num_patterns = self.read_patterns(self.patterns_ini)
        log.debug("Read regexps for %d IOCs" % num_patterns)

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
    def rearm_ip4(cls, s):
        return cls.rearm_dots(s)

    @classmethod
    def rearm_ip4Net(cls, s):
        return cls.rearm_dots(s)

    @classmethod
    def rearm_url(cls, s):
        s = re.sub(cls.re_http, 'http', s)
        return cls.rearm_dots(s)

    @classmethod
    def normalize_bitcoin(cls, s):
        # While Bech address should be lowercase sometimes they are capitalized
        # so we normalized them
        if s.startswith('BC1'):
            return s.lower()
        else:
            return s

    @classmethod
    def normalize_email(cls, s):
        # The local-part could in principle be case-sensitive,
        # but most mailboxes (e.g., Gmail) do not allow that and
        # attackers do exploit different capitalizations
        return s.lower()

    @classmethod
    def normalize_fqdn(cls, s):
        return s.lower()

    @classmethod
    def normalize_facebookHandle(cls, s):
        return s.lower()

    @classmethod
    def normalize_githubHandle(cls, s):
        return s.lower()

    @classmethod
    def normalize_instagramHandle(cls, s):
        return s.lower()

    @classmethod
    def normalize_pinterestHandle(cls, s):
        return s.lower()

    @classmethod
    def normalize_telegramHandle(cls, s):
        return s.lower()

    @classmethod
    def normalize_twitterHandle(cls, s):
        return s.lower()

    @classmethod
    def normalize_youtubeHandle(cls, s):
        return s.lower()

    @classmethod
    def normalize_url(cls, s):
        # Parse URL into components
        # scheme://netloc/path;params?query#fragment
        try:
            parsed = urlparse(s)
        except ValueError:
            return s
        # Handle (incorrectly parsed) URLs with no scheme
        if (not parsed.scheme):
            tokens = parsed.path.split('/')
            new_netloc = tokens[0].lower()
            if len(tokens) > 1:
                new_path = '/'.join(tokens[1:])
                return new_netloc + '/' + new_path
            else:
                return new_netloc
        # Lower case scheme
        new_scheme = parsed.scheme.lower()
        parsed = parsed._replace(scheme=new_scheme)
        # Lower case hostname and remove trailing dot if present
        if parsed.username or parsed.password:
            credentials = "{}:{}@".format(parsed.username, parsed.password)
        else:
            credentials = ""
        if parsed.port:
            port = ":{}".format(parsed.port)
        else:
            port = ""
        if parsed.hostname[-1] == '.':
            hostname = parsed.hostname[:-1]
        else:
            hostname = parsed.hostname
        new_netloc = "{}{}{}".format(credentials, hostname, port)
        parsed = parsed._replace(netloc=new_netloc)
        # Remove trailing backslash if only scheme and netloc present
        if (parsed.scheme and (parsed.path == '/') and
            (not parsed.params) and (not parsed.query) and
            (not parsed.fragment)):
            parsed = parsed._replace(path='')
        # Return URL as a string
        return parsed.geturl()

    @classmethod
    def normalize_iban(cls, s):
        return s.replace(' ','')

    @classmethod
    def normalize_phoneNumber(cls, s):
        try:
            p = phonenumbers.parse(s, None)
            ioc_value = phonenumbers.format_number(p,
                                  phonenumbers.PhoneNumberFormat.E164)
            return ioc_value
        except:
            return s

    def is_valid_tld(self, s):
        """Check if given string is a valid TLD according to IANA list"""
        # To help address common issues such a period not followed by a space
        # we allow 'COM' and 'com', but not 'Com' and 'CoM'
        if re.match('[A-Z][a-z]', s):
            return False
        # Check that TLD in lowercase appears in IANA list
        s = s.lower()
        return (self.tlds is None) or (s in self.tlds) or s.startswith('xn--')

    def is_valid_fqdn(self, s):
        """Check if given string ends with valid TLD according to IANA"""
        # Check valid characters
        if not re.match('^(\*\.)?[a-zA-Z0-9_\-\.]+$', s):
            return False
        # Remove trailing dot if present
        if s[-1] == '.':
            s = s[:-1]
        # Parse fqdn into labels
        labels = s.split('.')
        # Check there are at least two labels
        num_labels = len(labels)
        if num_labels < 2:
            return False
        # Check the labels
        ctr = num_labels
        for l in labels:
            # No label should be empty
            if not l:
                return False
            # According to RFC 5322 labels should not start or end with hyphen
            if l[0] == '-' or l[-1] == '-':
                return False
            # We are lenient in accepting underscores in FQDNs,
            # except if they appear in SLD or TLD
            if ctr <= 2 and '_' in l:
                return False
            ctr -= 1
        # Filter domains that are all in lowercase,
        # except for the first character of the TLD
        # This may happen when the text does not place a space after a period
        tld = labels[-1]
        num_uppercase = sum(1 for c in s if c.isupper())
        if (num_uppercase == 1) and tld[0].isupper():
            return False
        # Check if last label is valid TLD
        return self.is_valid_tld(tld)

    def is_valid_email(self, s):
        """Check given string is a valid email"""
        # Split into local-part and fqdn
        tokens = s.split('@')
        if len(tokens) != 2:
            return False
        # RFC 5322 does not allow the local-part:
        #  - to contain two or more consecutive dots (checked by regexp)
        #  - to start with a dot (checked by regexp)
        #  - to end with a dot (checked here)
        if tokens[0][-1] == '.':
            return False
        # The following local-part could in theory be valid
        # but most likely they are anonymized
        # Ignoring these ones is a trade-off
        if re.match('^([xX\.]+|[\-]+|[_]+)$', tokens[0]):
            return False
        return self.is_valid_fqdn(tokens[1])

    def is_valid_packageName(self, s):
        """Check if given string starts with valid TLD according to IANA"""
        tokens = s.split('.')
        return (len(tokens) > 1) and self.is_valid_tld(tokens[0])

    @classmethod
    def is_valid_ip4(cls, s, ignore_private=True, ignore_local=True,
                      ignore_multicast=True, ignore_loopback=True,
                      ignore_reserved=True, ignore_unspecified=True):
        """Check if given string is a valid IPv4 address"""
        try:
            addr = ipaddress.IPv4Address(s)
        except ValueError:
            return False
        if ignore_private and addr.is_private:
            return False
        if ignore_local and addr.is_link_local:
            return False
        if ignore_multicast and addr.is_multicast:
            return False
        if ignore_loopback and addr.is_loopback:
            return False
        if ignore_reserved and addr.is_reserved:
            return False
        if ignore_unspecified and addr.is_unspecified:
            return False
        return True

    @classmethod
    def is_valid_ip6(cls, s, ignore_private=True, ignore_local=True,
                      ignore_multicast=True, ignore_loopback=True,
                      ignore_reserved=True, ignore_unspecified=True):
        """Check if given string is a valid IPv6 address"""
        try:
            addr = ipaddress.IPv6Address(s)
        except ValueError:
            return False
        if ignore_private and addr.is_private:
            return False
        if ignore_local and addr.is_link_local:
            return False
        if ignore_multicast and addr.is_multicast:
            return False
        if ignore_loopback and addr.is_loopback:
            return False
        if ignore_reserved and addr.is_reserved:
            return False
        if ignore_unspecified and addr.is_unspecified:
            return False
        return True

    @staticmethod
    def is_valid_ip4Net(s):
        """Check if given string is a valid IPv4 or IPv6 network"""
        try:
            ipaddress.IPv4Network(s)
            return True
        except ValueError:
            return False

    def is_valid_url(self, s):
        """Check if given string is a valid URL by extracting host
            and checking if IP or valid TLD"""
        # Parse the URL with special handling for urlparse if no scheme
        try:
            if ("://" in s[0:15]):
                parsed = urlparse(s)
            else:
                parsed = urlparse("http://" + s)
        except ValueError:
            return False
        # If no hostname, invalid
        if not parsed.hostname:
            return False
        # Parse hostname
        tokens = parsed.hostname.split('.')
        # Validate URLs with IP address
        if tokens[-1].isdigit():
            # Avoid ipNet
            if re.match('/[0-9]{1,2}$', parsed.path):
                return False
            return __class__.is_valid_ip4(parsed.hostname)
        # Validate Onion URLs
        elif tokens[-1] == 'onion':
            return self.is_valid_onionAddress(tokens[-2])
        # Validate URLs with FQDN
        else:
            return self.is_valid_fqdn(parsed.hostname)

    @staticmethod
    def is_valid_nif(s):
        """Check if given string is a valid Spanish NIF or NIE"""
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
        """Check if given string has valid UUID version and variant"""
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
        """Extract entity from copyright string"""
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
        """Check if given copyright string has a non-empty entity"""
        entity = __class__.copyright_entity(s)
        return entity != ""

    @staticmethod
    def is_valid_base58_checksum(s, alphabet=base58.BITCOIN_ALPHABET):
        """Check if input has a valid checksum after Base58 decoding"""
        try:
            payload = base58.b58decode(s, alphabet=alphabet)
        except ValueError:
            return False
        expected_checksum = payload[-4:]
        checksum = sha256(sha256(payload[:-4]).digest()).digest()[:4]
        return checksum == expected_checksum

    @staticmethod
    def bech32_polymod(values):
        """Compute the Bech32 checksum for the given values"""
        gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= gen[i] if ((b >> i) & 1) else 0
        return chk

    @staticmethod
    def is_valid_bech32(s):
        """Check if input is valid Bech32 address by validating checksum"""
        pos = s.rfind('1')
        hrp = s[:pos]
        payload = s[pos+1:]
        # Compute values
        values = [BECH32_CHARSET.find(x) for x in payload]
        # Expand the HRP into values for checksum computation
        exp_hrp = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
        # Compute checksum
        checksum = __class__.bech32_polymod(exp_hrp + values)
        # Check that checksum has Bech32 or Bech32-m values
        return (checksum == 1) or (checksum == 734539939)

    @staticmethod
    def is_valid_bitcoin(s):
        """Check if given string is a valid Bitcoin address"""
        # Normalize (since normalization happens after validation)
        if s.startswith('BC1'):
            s = s.lower()
        # Validate depending on encoding
        if s.startswith('bc1'):
            return __class__.is_valid_bech32(s)
        else:
            return __class__.is_valid_base58_checksum(s)

    @staticmethod
    def is_valid_bitcoincash(s):
        """Check if given string is a valid BitcoinCash address"""
        addr_str = s if s.startswith('bitcoincash:') else 'bitcoincash:' + s
        return cashaddress.convert.is_valid(addr_str)

    @staticmethod
    def is_valid_cardano(s):
        """Check if given string is a valid Cardano Shelley/Byron address"""
        # https://cips.cardano.org/cips/cip19/
        # Validate Shelley address
        if s[0:5] == 'addr1':
                try:
                    hrp, _payload32 = bech32.bech32_decode(s)
                    payload = bech32.convertbits(_payload32, 5, 8, False)
                    atype = payload[0] >> 4
                    network = payload[0] & 15
                    # Valid if mainnet and shelley type (0 to 7 inclusive)
                    return (network == 1) and (atype <= 7)
                except:
                    return False
        # Validate Byron address
        else:
            try:
                decoded_address = cbor.loads(base58.b58decode(s))
                tagged_address = decoded_address[0]
                expected_checksum = decoded_address[1]
                checksum = binascii.crc32(tagged_address.value)
                return checksum == expected_checksum
            except:
                return False

    @staticmethod
    def is_valid_dashcoin(s):
        """Check if given string is a valid Dashcoin address"""
        return __class__.is_valid_base58_checksum(s)

    @staticmethod
    def is_valid_dogecoin(s):
        """Check if given string is a valid Dogecoin address"""
        return __class__.is_valid_base58_checksum(s)

    @classmethod
    def is_valid_ethereum(cls, s):
        """Check if given string is a valid Ethererum address"""
        addr = s[2:] if s.startswith('0x') else s
        # If all lowercase or all uppercases, return true
        if re.match(cls.re_ethereum_nonchecksummed, addr):
            return True
        # Otherwise, validate checksum
        addr_hash = keccak.new(addr.lower().encode('utf-8')).digest().hex()
        for i, letter in enumerate(addr):
            if any([
                    int(addr_hash[i], 16) >= 8 and letter.upper() != letter,
                    int(addr_hash[i], 16) < 8 and letter.lower() != letter
            ]):
                return False
        return True

    @staticmethod
    def is_valid_litecoin(s):
        """Check if given string is a valid Litecoin address"""
        # Validate depending on encoding
        if s.startswith('ltc1'):
            return __class__.is_valid_bech32(s)
        else:
            return __class__.is_valid_base58_checksum(s)

    @staticmethod
    def is_valid_monero(s):
        """Check if given string is a valid Monero address"""
        # FIX: Monero Base58 decode can throw ValueError: Overflow 
        # (looks like with long strings)
        try:
            _decoded = iocsearcher.monero.base58.decode(s)
        except ValueError:
            return False
        decoded_address = bytearray(binascii.unhexlify(_decoded))
        expected_checksum = decoded_address[-4:]
        payload = decoded_address[:-4]
        checksum = keccak.new(payload).digest()[:4]
        return checksum == expected_checksum

    @staticmethod
    def is_valid_ripple(s):
        """Check if given string is a valid Ripple address"""
        return __class__.is_valid_base58_checksum(s,
                                              alphabet=base58.RIPPLE_ALPHABET)

    @staticmethod
    def is_valid_solana(s):
        """Check if given string is a valid Solana address"""
        try:
            pub_key = Pubkey.from_string(s)
        except ValueError:
            return False
        return (pub_key.LENGTH == 32) and pub_key.is_on_curve()

    @staticmethod
    def is_valid_stellar(s):
        """Check if given string is a valid Stellar address"""
        # Check human-readable part (HRP)
        if s[0] != 'G':
            return False

        # Decode address
        try:
            decoded = b32decode(s)
        except binascii.Error:
            return False

        # Get fields
        version_byte = decoded[0:1]
        payload = decoded[0:-2]
        data = decoded[1:-2]
        checksum = decoded[-2:]

        # Check type is 'account'
        account_version = binascii.a2b_hex('30')
        if version_byte != account_version:
            return False

        # Compute checksum
        computed_checksum = binascii.crc_hqx(payload, 0)
        computed_checksum = struct.pack('<H', computed_checksum)

        # Validate checksum
        return computed_checksum == checksum

    @staticmethod
    def is_valid_tezos(s):
        """Check if given string is a valid Tezos address"""
        return __class__.is_valid_base58_checksum(s)

    @staticmethod
    def is_valid_tron(s):
        """Check if given string is a valid Tron address"""
        return __class__.is_valid_base58_checksum(s)

    @staticmethod
    def is_valid_zcash(s):
        """Check if given string is a valid ZCash transparent address"""
        return __class__.is_valid_base58_checksum(s)

    @staticmethod
    def is_valid_telegramHandle(s):
        """Check if given string is a valid Telegram handle"""
        return s not in {'joinchat', 'share', 'username'}

    @staticmethod
    def is_valid_twitterHandle(s):
        """Check if given string is a valid Twitter handle"""
        return s not in {'author_handle', 'home', 'https', 'intent',
                          'personalization', 'privacy',
                          'rules', 'search', 'security', 'settings', 'share',
                          'terms', 'tos', 'web', 'widgets', 'your_twitter_da'}

    @staticmethod
    def is_valid_facebookHandle(s):
        """Check if given string is a valid Facebook handle"""
        return s not in {'2008', 'about', 'ads', 'business', 'dialog', 'docs',
                            'events', 'help',
                            'full', 'groups', 'legal', 'pages', 'people',
                            'plugins', 'policy', 'policy.php', 'policies',
                            'privacy', 'profile.php', 'settings',
                            'share', 'share.php', 'sharer', 'sharer.php'}

    @staticmethod
    def is_valid_instagramHandle(s):
        """Check if given string is a valid Instagram handle"""
        return s not in {'about', 'invites', 'legal'}

    @staticmethod
    def is_valid_pinterestHandle(s):
        """Check if given string is a valid Pinterest handle"""
        return s not in {'https', 'pin', 'static'}

    @staticmethod
    def is_valid_githubHandle(s):
        """Check if given string is a valid GitHub handle"""
        return s not in {'about', 'auth', 'buttons', 'contact', 'events',
                          'fluidicon', 'github', 'notifications', 'pricing',
                          'readme', 'security', 'site', '_private'}

    @staticmethod
    def is_valid_linkedinHandle(s):
        """Check if given string is a valid LinkedIn handle"""
        return True

    @staticmethod
    def is_valid_youtubeHandle(s):
        """Check if given string is a valid YouTube handle"""
        return s not in {'channel', 'embed', 'feed', 'iframe',
                          'player', 'playlist', 'privacynotice',
                          'shorts', 'static', 'user', 'watch', 'yt'}

    @staticmethod
    def is_valid_youtubeChannel(s):
        """Check if given string is a valid YouTube channel"""
        return True

    @staticmethod
    def is_valid_phone(s, country=None, language=None, lax=False):
        """Check if given string is a valid phone"""
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
        if lax:
            digit_str = re.sub('[^0-9]','', s)
            l = len(digit_str)
            # Minimum length is 5 for some islands,
            # but most countries have at least 7 digits
            return (l >= 7) and (l <= 15)
        # Otherwise, not a valid phone
        return False

    @staticmethod
    def is_valid_phoneNumber(s):
        """Check if given string is a valid phone"""
        return __class__.is_valid_phone(s)

    @staticmethod
    def is_valid_onionAddress(s):
        """Return true if the input string is a valid Tor onion v3 address"""
        l = len(s)
        # v2 addresses cannot really be validated
        if l == 16:
            return True
        # Validate v3 addresses
        elif l == 56:
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
        # Invalid address length
        else:
            return False

    @staticmethod
    def is_valid_iban(s):
        """Return true if the input string is a valid IBAN
            An IBAN comprises of 15-32 alphanumeric characters with format:
              2 characters for country code
              2 control characters (checksum)
              up to 28 account characters depending on country
            Validator checks length for country and IBAN checksum
        """
        iban_length = {
            "AD":24, "AE":23, "AT":20, "AZ":28, "BA":20, "BE":16,
            "BG":22, "BH":22, "BR":29, "CH":21, "CR":22, "CY":28,
            "CZ":24, "DE":22, "DK":18, "DO":28, "EE":20, "ES":24,
            "FI":18, "FO":18, "FR":27, "GB":22, "GI":23, "GL":18,
            "GR":27, "GT":28, "HR":21, "HU":28, "IE":22, "IL":23,
            "IS":26, "IT":27, "JO":30, "KW":30, "KZ":20, "LB":28,
            "LI":21, "LT":20, "LU":20, "LV":21, "MC":27, "MD":24,
            "ME":22, "MK":19, "MR":27, "MT":31, "MU":30, "NL":18,
            "NO":15, "PK":24, "PL":28, "PS":29, "PT":25, "QA":29,
            "RO":24, "RS":22, "SA":24, "SE":24, "SI":19, "SK":24,
            "SM":27, "TN":24, "TR":26, "AL":28, "BY":28, "DJ":27,
            "EG":29, "GE":22, "IQ":23, "LC":32, "SC":31, "ST":25,
            "SV":28, "TL":23, "UA":29, "VA":22, "VG":24, "XK":20,
            "BI":27, "FK":18, "LY":25, "MN":20, "NI":28, "RV":33,
            "SD":18, "SO":23
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

    @staticmethod
    def is_valid_tox(s):
        """Check if given string is a valid TOX ID"""
        if len(s) != 76:
            return False

        # Public key (32 bytes) + NoSpam (4 bytes) + Checksum (2 bytes)
        size = 64 + 8
        _data = s[:size]
        data = bytearray(binascii.unhexlify(_data))
        _checksum = s[size:]
        checksum = bytearray(binascii.unhexlify(_checksum))

        # Compute checksum
        calculated = bytearray([0x00] * 2)
        for i in range(36):
            calculated[i % 2] = calculated[i % 2] ^ data[i]

        # Compare calculated and checksum
        return bytes(calculated) == checksum

    def add_regexp(self, ioc_name, ioc_pattern, validate=False):
        """Adds compiled regexp. Returns true if regexp added"""
        # Add IOC to validation list
        if validate:
            self.validate.add(ioc_name)
        # Compile regexp and store it
        if ioc_name and ioc_pattern:
            self.patterns.setdefault(ioc_name, []).append(ioc_pattern)
            return True
        return False

    def remove_regexps(self, ioc_name):
        """Remove all regexps for given ioc_name"""
        del self.patterns[ioc_name]

    def read_patterns(self, filepath):
        """Reads regexps in INI file. Returns number of regexps added"""
        ctr = 0
        # Read configuration file
        config = configparser.ConfigParser()
        config.read_file(open(filepath, "r", encoding="utf8"))

        # Iterate on sections
        for sec in config.sections():
            # IOC name is section without trailing digits separated by hyphen
            ioc_name = re.sub('\-[0-9]+$','', sec)
            # Read pattern
            try:
                ioc_pattern = config.get(sec, 'pattern')
            except configparser.Error as exc:
                log.warning("Could not extract pattern in %s: %s" % (sec, exc))
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
            except configparser.Error:
                flags = 0

            # Read whether IOC needs to be validated
            try:
                validate = config.getboolean(sec, 'validate')
            except configparser.Error:
                validate = False

            # Compile regexp and store it
            compiled_regexp = re.compile(ioc_pattern, flags)

            # Add compiled regexp
            if self.add_regexp(ioc_name, compiled_regexp, validate=validate):
                ctr += 1

        return ctr

    @staticmethod
    def read_tlds(filepath):
        """Reads TLDs in IANA file and returns them as a set"""
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
        """Return alternate regex for input strings"""
        if not elements:
            return None
        sorted_l = sorted(list(elements), key=len, reverse=True)
        boundary = "\\b" if match_word else ""
        return "%s(%s)%s" % (boundary, "|".join(sorted_l), boundary)

    def add_iocs_regex(self, iocs, ignore_case=True, match_word=True):
        """Add alternate pattern for each ioc type in input list"""
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
        """Apply targets regexps to input data,
            Returns list of (type, rearmed_value, start_offset, raw_value)"""
        results = []
        # Select targets
        if targets is None:
            targets = self.patterns.keys()
        for ioc_name in targets:
            # Get regular expressions for target
            regexes = self.patterns.get(ioc_name, None)
            if regexes is None:
                log.warning("No regexp for target '%s'" % ioc_name)
                continue
            # Iterate on regexps for target
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

                    # Rearm value
                    if ioc_name in ["email", "fqdn", "ip4", "ip4Net", "url"]:
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

                    # Normalize value
                    if ioc_name in can_normalize:
                        normalize_func = getattr(self, "normalize_" + ioc_name)
                        normalized_value = normalize_func(rearmed_value)
                    else:
                        normalized_value = rearmed_value

                    # Store result tuple (name,value,start,raw_value)
                    results.append((ioc_name, normalized_value,
                                    start_offset, raw_value))
        return results

    def search_data(self, data, targets=None, no_overlaps=False):
        """Wrapper for search_raw that:
            (1) Builds IOCs on the returned rearmed value
            (2) Removes duplicated IOCs that appeared at different positions
            Returns a set of IOCs"""
        results = set()
        # Scan text with regexp
        matches = self.search_raw(data, targets)
        # Remove overlaps if needed
        if no_overlaps:
            matches = self.remove_overlaps(matches)
        # Process matches
        for m in matches:
            # Create IOC
            try:
                found_ioc = self.create_ioc(m[0], m[1])
            except ValueError:
                log.warning("Failed to create IOC %s %s" % (m[0], m[1]))
                continue
            # Store IOC
            results.add(found_ioc)
        return results

    def search_phone_numbers(self, text, country=None, language=None):
        """Search for phone numbers in given text, returns a set of IOCs"""
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
        """Search URL for URL-IOCs"""
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

    @staticmethod
    def remove_overlaps(l):
        """Remove overlapping indicators
            Assumes input is list of (type, rearmed_val, start_off, raw_val)
        """
        # Sort list by (start,length of raw_value,type)
        l.sort(key=lambda e : (e[2],-len(e[3]), e[0]))
        # Create an interval tree to identify IOC overlaps
        t = IntervalTree()
        # Accumulator for list of IOCs that will be reported
        acc = []
        # Iterate over the input IOCs
        for (ioc_type, rearmed_value, start, raw_value) in l:
            # Compute IOC end
            # IntervalTree uses ranges of type [start,end)
            length = len(raw_value)
            end = start + length
            # Check for overlapping fields already in IntervalTree
            overlaps = t.overlap(start,end)
            should_add = True
            # For any overlaps, check if IOC is contained
            # If so, ignore IOC
            for interval in overlaps:
                if (start >= interval.begin) and (end <= interval.end):
                    should_add = False
            # If not contained, include it
            if should_add:
                acc.append((ioc_type, rearmed_value, start, raw_value))
            # Add IOC to IntervalTree
            t[start:end] = (ioc_type, rearmed_value, start, raw_value)
        # Return non-overlapping fields
        return acc

    def normalize_text(self, text, targets=None, macros=None):
        """Normalize text replacing IOCs with macros"""
        # Extract raw matches
        raw_matches = self.search_raw(text, targets=targets)
        # Remove overlaps
        raw_matches = self.remove_overlaps(raw_matches)
        # Replace matches with macros
        ioc_cnt = {}
        replacements = {}
        new_text = text
        for ioc_type, ioc_value, start, raw_value in raw_matches:
            # Select appropriate macro
            macro = macros.get(ioc_type, None) if macros else None
            if macro is None:
                ctr = ioc_cnt.get(ioc_type, 0)
                if ctr == 0:
                    macro = "<%s>" % ioc_type.upper()
                else:
                    macro = "<%s%d>" % (ioc_type.upper(), ctr)
                ioc_cnt[ioc_type] = ctr + 1
            # Replace raw value with macro at all positions
            new_text = new_text.replace(raw_value, macro)
            # Store replacement info
            replacements[macro] = (ioc_type, ioc_value, raw_value)
        # Return text and replacement info
        return new_text, replacements

