import re
import random
from typing import Callable
import re_generate

# A grammar maps rule names either a string or a sequence of rule names
# A terminal always maps to a regex
# A nonterminal always maps to a list of rule names

# unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
UNRESERVED_PAT: str = r"(?:[A-Za-z0-9\-\._~])"

# pct-encoded = "%" HEXDIG HEXDIG
PCT_ENCODED_PAT: str = r"(?:%[A-F0-9][A-F0-9])"

# sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
SUB_DELIMS_PAT: str = r"(?:[!\$&'\(\)\*\+,;=])"

# pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
PCHAR_PAT: str = rf"(?:{UNRESERVED_PAT}|{PCT_ENCODED_PAT}|{SUB_DELIMS_PAT}|:|@)"

# query = *( pchar / "/" / "?" )
QUERY_PAT: str = rf"(?P<query>(?:{PCHAR_PAT}|/|\?)*)"

# fragment = *( pchar / "/" / "?" )
FRAGMENT_PAT: str = rf"(?P<fragment>(?:{PCHAR_PAT}|/|\?)*)"

# scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
SCHEME_PAT: str = r"(?P<scheme>[A-Za-z][A-Za-z0-9\+\-\.]*)"

# segment = *pchar
SEGMENT_PAT: str = rf"(?:{PCHAR_PAT}*)"

# segment-nz = 1*pchar
SEGMENT_NZ_PAT: str = rf"(?:{PCHAR_PAT}+)"

# segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
SEGMENT_NZ_NC_PAT: str = rf"(?:(?:{UNRESERVED_PAT}|{PCT_ENCODED_PAT}|{SUB_DELIMS_PAT}|@)+)"

# path-absolute = "/" [ segment-nz *( "/" segment ) ]
PATH_ABSOLUTE_PAT: str = rf"(?P<path_absolute>/(?:{SEGMENT_NZ_PAT}(?:/{SEGMENT_PAT})*)?)"

# path-empty = 0<pchar>
PATH_EMPTY_PAT: str = r"(?P<path_empty>)"

# path-rootless = segment-nz *( "/" segment )
PATH_ROOTLESS_PAT: str = rf"(?P<path_rootless>{SEGMENT_NZ_PAT}(?:/{SEGMENT_PAT})*)"

# path-abempty = *( "/" segment )
PATH_ABEMPTY_PAT: str = rf"(?P<path_abempty>(?:/{SEGMENT_PAT})*)"

# path-noscheme = segment-nz-nc *( "/" segment )
PATH_NOSCHEME_PAT: str = rf"(?P<path_noscheme>{SEGMENT_NZ_NC_PAT}(?:/{SEGMENT_PAT})*)"

# userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
USERINFO_PAT: str = rf"(?P<userinfo>(?:{UNRESERVED_PAT}|{PCT_ENCODED_PAT}|{SUB_DELIMS_PAT}|:)*)"

# dec-octet = DIGIT                 ; 0-9
#           / %x31-39 DIGIT         ; 10-99
#           / "1" 2DIGIT            ; 100-199
#           / "2" %x30-34 DIGIT     ; 200-249
#           / "25" %x30-35          ; 250-255
DEC_OCTET_PAT: str = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"

# IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
IPV4ADDRESS_PAT: str = rf"(?:{DEC_OCTET_PAT}\.{DEC_OCTET_PAT}\.{DEC_OCTET_PAT}\.{DEC_OCTET_PAT})"

# h16 = 1*4HEXDIG
H16_PAT: str = r"(?:[0-9A-F]{1,4})"

# ls32 = ( h16 ":" h16 ) / IPv4address
LS32_PAT: str = rf"(?:{H16_PAT}:{H16_PAT}|{IPV4ADDRESS_PAT})"

# IPv6address =                            6( h16 ":" ) ls32
#             /                       "::" 5( h16 ":" ) ls32
#             / [               h16 ] "::" 4( h16 ":" ) ls32
#             / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
#             / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
#             / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
#             / [ *4( h16 ":" ) h16 ] "::"              ls32
#             / [ *5( h16 ":" ) h16 ] "::"              h16
#             / [ *6( h16 ":" ) h16 ] "::"
IPV6ADDRESS_PAT: str = (
    "(?:"
    + r"|".join(
        (
            rf"(?:{H16_PAT}:){{6}}{LS32_PAT}",
            rf"::(?:{H16_PAT}:){{5}}{LS32_PAT}",
            rf"(?:{H16_PAT})?::(?:{H16_PAT}:){{4}}{LS32_PAT}",
            rf"(?:(?:{H16_PAT}:){{0,1}}{H16_PAT})?::(?:{H16_PAT}:){{3}}{LS32_PAT}",
            rf"(?:(?:{H16_PAT}:){{0,2}}{H16_PAT})?::(?:{H16_PAT}:){{2}}{LS32_PAT}",
            rf"(?:(?:{H16_PAT}:){{0,3}}{H16_PAT})?::(?:{H16_PAT}:){{1}}{LS32_PAT}",
            rf"(?:(?:{H16_PAT}:){{0,4}}{H16_PAT})?::{LS32_PAT}",
            rf"(?:(?:{H16_PAT}:){{0,5}}{H16_PAT})?::{H16_PAT}",
            rf"(?:(?:{H16_PAT}:){{0,6}}{H16_PAT})?::",
        )
    )
    + ")"
)

# IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
IPVFUTURE_PAT: str = rf"(?:v[0-9A-F]+\.(?:{UNRESERVED_PAT}|{SUB_DELIMS_PAT}|:)+)"

# IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
IP_LITERAL_PAT: str = rf"(?:\[(?:{IPV6ADDRESS_PAT}|{IPVFUTURE_PAT})\])"

# reg-name = *( unreserved / pct-encoded / sub-delims )
REG_NAME_PAT: str = rf"(?:(?:{UNRESERVED_PAT}|{PCT_ENCODED_PAT}|{SUB_DELIMS_PAT})*)"

# host = IP-literal / IPv4address / reg-name
HOST_PAT: str = rf"(?P<host>{IP_LITERAL_PAT}|{IPV4ADDRESS_PAT}|{REG_NAME_PAT})"

# port = *DIGIT
# PORT_PAT: str = r"(?P<port>[0-9]*)"
# WHATWG version (fits in uint16_t):
PORT_PAT: str = r"(?P<port>0*[1-9]?[0-9]?[0-9]?[0-9]?|0*6553[0-5]|0*655[0-2][0-9]|0*65[0-4][0-9][0-9]|0*6[0-4][0-9][0-9][0-9])"

# authority = [ userinfo "@" ] host [ ":" port ]
AUTHORITY_PAT: str = rf"(?:(?:{USERINFO_PAT}@)?{HOST_PAT}(?::{PORT_PAT})?)"

# hier-part = "//" authority path-abempty
#           / path-absolute
#           / path-rootless
#           / path-empty
HIER_PART_PAT: str = (
    rf"(?:(?://{AUTHORITY_PAT}{PATH_ABEMPTY_PAT})|{PATH_ABSOLUTE_PAT}|{PATH_ROOTLESS_PAT}|{PATH_EMPTY_PAT})"
)

# URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
URI_PAT: str = rf"\A(?:{SCHEME_PAT}:{HIER_PART_PAT}(?:\?{QUERY_PAT})?(?:#{FRAGMENT_PAT})?)\Z"
URI_RE: re.Pattern = re.compile(URI_PAT.encode("ASCII"))

# relative-part = "//" authority path-abempty
#                  / path-absolute
#                  / path-noscheme
#                  / path-empty
RELATIVE_PART_PAT: str = (
    rf"(?:(?://{AUTHORITY_PAT}{PATH_ABEMPTY_PAT})|{PATH_ABSOLUTE_PAT}|{PATH_NOSCHEME_PAT}|{PATH_EMPTY_PAT})"
)

# relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
RELATIVE_REF_PAT: str = rf"\A(?:{RELATIVE_PART_PAT}(?:\?{QUERY_PAT})?(?:#{FRAGMENT_PAT})?)\Z"
RELATIVE_REF_RE: re.Pattern = re.compile(RELATIVE_REF_PAT.encode("ASCII"))

grammar_rules: dict[str, bytes] = {
    "scheme": SCHEME_PAT.encode("ASCII"),
    "userinfo": USERINFO_PAT.encode("ASCII"),
    "host": HOST_PAT.encode("ASCII"),
    "port": PORT_PAT.encode("ASCII"),
    "path_abempty": PATH_ABEMPTY_PAT.encode("ASCII"),
    "path_absolute": PATH_ABSOLUTE_PAT.encode("ASCII"),
    "path_rootless": PATH_ROOTLESS_PAT.encode("ASCII"),
    "path_empty": PATH_EMPTY_PAT.encode("ASCII"),
    "path_noscheme": PATH_NOSCHEME_PAT.encode("ASCII"),
    "query": QUERY_PAT.encode("ASCII"),
    "fragment": FRAGMENT_PAT.encode("ASCII"),
}


def generate_random_match(rule_name: str) -> bytes:
    return re_generate.generate_random_match_from_pattern(grammar_rules[rule_name])


INSERTABLE_RULES: list[str] = ["query", "fragment", "scheme"]
INSERTABLE_RULES_WITH_HOST: list[str] = ["port", "userinfo"]


def grammar_insert(b: bytes) -> bytes:
    match: re.Match[bytes] | None = re.match(URI_RE, b)
    if match is None:
        match = re.match(RELATIVE_REF_RE, b)
    if match is None:
        raise ValueError("Mutation precondition didn't hold.")

    rules_to_fill: list[str] = [
        s
        for s in INSERTABLE_RULES + (INSERTABLE_RULES_WITH_HOST if match["host"] is not None else [])
        if match[s] is None
    ]

    if len(rules_to_fill) == 0:
        raise ValueError("Mutation precondition didn't hold.")

    rule_name: str = random.choice(rules_to_fill)
    return serialize(match.groupdict() | {rule_name: generate_random_match(rule_name)})


def grammar_replace(b: bytes) -> bytes:
    match: re.Match[bytes] | None = re.match(URI_RE, b)
    if match is None:
        match = re.match(RELATIVE_REF_RE, b)
    if match is None:
        raise ValueError("Mutation precondition didn't hold.")

    groupdict: dict[str, bytes | None] = match.groupdict()
    rule_name: str = random.choice([r for r in groupdict if groupdict[r] is not None])
    return serialize(groupdict | {rule_name: generate_random_match(rule_name)})


def grammar_delete(b: bytes) -> bytes:
    match: re.Match[bytes] | None = re.match(URI_RE, b)
    if match is None:
        match = re.match(RELATIVE_REF_RE, b)
    if match is None:
        raise ValueError("Mutation precondition didn't hold.")
    groupdict: dict[str, bytes | None] = match.groupdict()
    rule_name: str = random.choice([r for r in groupdict if groupdict[r] is not None])
    groupdict[rule_name] = None
    return serialize(groupdict)


def serialize(match: dict[str, bytes | None] | re.Match[bytes]) -> bytes:
    """
    Deliberately permissive serializer for URI_RE and RELATIVE_REF_RE re.Match objects.
    """
    if isinstance(match, re.Match):
        match = match.groupdict()

    result = b""
    if match["scheme"] is not None:
        result += match["scheme"] + b":"
    if any(match[rule_name] is not None for rule_name in ("userinfo", "host", "port")):
        result += b"//"
    if match["userinfo"] is not None:
        result += match["userinfo"] + b"@"
    if match["host"] is not None:
        result += match["host"]
    if match["port"] is not None:
        result += b":" + match["port"]
    for path_type in (
        pt
        for pt in ("path_absolute", "path_abempty", "path_rootless", "path_empty", "path_noscheme")
        if pt in match
    ):
        path_bytes: bytes | None = match[path_type]
        if path_bytes is not None:
            result += path_bytes
    if match["query"] is not None:
        result += b"?" + match["query"]
    if match["fragment"] is not None:
        result += b"#" + match["fragment"]
    return result


GRAMMAR_MUTATORS: list[Callable[[bytes], bytes]] = [grammar_delete, grammar_insert, grammar_replace]
