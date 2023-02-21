# iocsearcher

_iocsearcher_ is a Python library and command-line tool to extract
indicators of compromise (IOCs),
also known as cyber observables,
from HTML, PDF, and text files.
It can identify both defanged (e.g., IP address 1[.]2[.]3.[4]) and
unmodified IOCs (e.g., IP address 1.2.3.4).

## Supported IOCs

_iocsearcher_ can extract the following IOC types:

- URLs (url)
- Domain names (fqdn)
- IP addresses (ip)
- IP subnets (ipNet)
- Hashes (fileMd5,fileSha1,fileSha256)
- Email addresses (email)
- Copyright strings (copyright)
- CVE vulnerability identifiers (cve)
- Tor v3 addresses (onionAddress)
- Social network handles (facebookHandle,githubHandle,instagramHandle,
linkedinHandle,pinterestHandle,telegramHandle,twitterHandle,whatsappHandle,
youtubeHandle,youtubeChannel)
- Advertisement/analytics identifiers (googleAdsense, googleAnalytics, googleTagManager)
- Blockchain addresses (bitcoin,bitcoincash,dashcoin,dogecoin,ethereum,litecoin,monero,tezos,zcash)
- Payment addresses (webmoney)
- Chinese Internet Content Provider licenses (icp)
- Bank account numbers (iban)
- Trademarks (trademark)
- Universal unique identifiers (uuid)
- Android package name (packageName)
- Spanish NIF identifiers (nif)

## Installation

~~~ sh
pip install iocsearcher
~~~

If you get an error, try installing Python developer tools first:
~~~ sh
sudo apt install python3-dev
pip install iocsearcher
~~~

## Command Line Usage

To find IOCs in a given file just provide the -f (--file) option.
By default, found IOCs are printed to stdout,
defanged IOCs are rearmed, and
IOCs are deduplicated so they only appear once.

~~~ sh
iocsearcher -f file.pdf
iocsearcher -f page.html
iocsearcher -f input.txt
~~~

You can use the -o (--output) option to place IOCs to a file instead of stdout:

~~~ sh
iocsearcher -f file.pdf -o iocs.txt
~~~

By default all regexp are applied to the input.
If you are only interested in some specific IOC types,
it is more efficient to specify those using
the -t (--target) option, which can be applied multiple times:

~~~ sh
iocsearcher -f file.pdf -t url -t email
~~~

You can also search for IOCs in all files in a directory using
the -d (--dir) option.
IOCs extracted from each file will be placed in their own .iocs file.
You can also place all IOCs founds across the input files
in the same output file by also adding the -o (--output) option:

~~~ sh
iocsearcher -d directoryWithFiles -o all.iocs
~~~

In HTML files, only the readable text is examined
(i.e., think of the text shown by Firefox's Reader View).
If you want to scan the whole HTML content you can use the -r (--raw) option:

~~~ sh
iocsearcher -f page.html -r
~~~

If you have a file that you want to interpret as text avoiding
filetype detection, you can use the -F (--forcetext) option:

~~~ sh
iocsearcher -f input.txt -F
~~~

You can store the text extracted from a PDF/HTML file using the
-T (--text) option, which will produce a .text file for each input file:

~~~ sh
iocsearcher -f file.pdf -T
~~~

By default IOCs are deduplicated, you can instead output the offset of
each IOC without deduplication by using the -v (--verbose) option:

~~~ sh
iocsearcher -f file.pdf -v
~~~


## Library Usage

You can also use _iocsearcher_ as a library by creating a
_Searcher_ object and then invoking the functions
_search_data_ to identify rearmed and deduplicated IOCs and
_search_raw_ to identify all matches, their offsets, and the defanged string.
The _Searcher_ object needs to be created only once to parse the regexps.
Then, it can be reused to find IOCs in multiple input strings.

~~~ sh
python3
>>> import iocsearcher
>>> from iocsearcher.searcher import Searcher
>>> test = 'Find this email contact[AT]example[dot]com'
>>> searcher = Searcher()
>>> searcher.search_data(test)
{('email', 'contact@example.com'), ('fqdn', 'example.com')}
>>> searcher.search_data(test, targets={'email'})
{('email', 'contact@example.com')}
>>> searcher.search_raw(test)
[('email', 'contact@example.com', 16, 'contact[AT]example[dot]com'), ('fqdn', 'example.com', 27, 'example[dot]com')]
~~~

You can also open a document without needing to provide its type,
get its text, and then use a _Searcher_ object to search for IOCs in the text:

~~~ sh
python3
>>> import iocsearcher
>>> from iocsearcher.document import open_document
>>> from iocsearcher.searcher import Searcher
>>> doc = open_document(filepath)
>>> text,_ = doc.get_text() if doc is not None else ""
>>> searcher = Searcher()
>>> searcher.search_data(text)
~~~

If the file is not a PDF, HTML, or text document,
then _open_document_ throws a warning and returns None

## Defang and Rearm

Many security reports defang (i.e., remove the teeth from) malicious
indicators, especially network indicators such as URLs, domains,
IP addresses, and email addresses.
This practice helps to prevent users from inadvertently clicking on a
malicious indicator and start a network connection to it.
Defanged indicators do not follow the indicator specification and thus
required relaxed regular expressions to detect them.

_iocsearcher_ supports some popular defang operations
and rearms the IOCs by default so that deduplication works even if the
same IOC has been defanged in different ways.

However, it is not possible to support all defang operations,
as every analyst can come up with their own.
If you think _iocsearcher_ is missing support for some popular
defang operation, let us know by providing pointers to reports that use them.

## Customizing the Regular Expressions

The default regular expressions used by _iocsearcher_ are stored in
_data/patterns.ini_

If you want to modify a regexp, add a regexp,
change the IOC type associated to a regexp, or disable validation
for an existing regexp, you can create a copy of _patterns.ini_,
edit your copy, and pass it as input to _iocsearcher_
using the -P (--patterns) option:

~~~ sh
iocsearcher -f file.pdf -P mypatterns.ini
~~~

Note that if you add a new regexp, the output will be the outermost group
if a group exists, and the whole match if the regexp has no groups.

## Related Tools

There exist multiple other open-source IOC extraction tools.
In our [FGCS journal paper](https://arxiv.org/abs/2208.00042)
we propose a novel evaluation methodology for IOC extraction tools and
apply it to compare _iocsearcher_ with the following tools:

- [Jager](https://github.com/sroberts/jager) (Python)
- [IOC-parser](https://github.com/armbues/ioc_parser) (Python)
- [Cacador](https://github.com/sroberts/cacador) (Go)
- [CyObstract](https://github.com/cmu-sei/cyobstract) (Python)
- [IOC Finder](https://github.com/fhightower/ioc-finder) (Python)
- [IOC Extract](https://github.com/InQuest/python-iocextract) (Python)
- [IOC-Extractor](https://github.com/ninoseki/ioc-extractor) (Python)

We encourage you to read our paper if you have questions about how
_iocsearcher_ compares with the above tools and to try
the above tools if _iocsearcher_ does not meet your goals.

## References

The design and evaluation of _iocsearcher_ and the comparison with prior
IOC extraction tools are detailed in our
[FGCS journal paper](https://arxiv.org/abs/2208.00042):

> Juan Caballero, Gibran Gomez, Srdjan Matic, Gustavo Sánchez, Silvia Sebastián, and Arturo Villacañas.
GoodFATR: A Platform for Automated Threat Report Collection and IOC Extraction.
In Future Generation Computer Systems, 2023.

# Contributors

The main developer and maintainer for _iocsearcher_ is Juan Caballero.
Other members of the MaliciaLab at the
[IMDEA Software Institute](http://software.imdea.org)
have contributed fixes and helped with testing:
Gibran Gomez, Silvia Sebastian, Srdjan Matic

