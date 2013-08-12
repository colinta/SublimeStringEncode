# coding: utf8
import urllib
import base64
import re
import json
from functools import cmp_to_key

import sublime_plugin

import re
import sys

class StringEncode(sublime_plugin.TextCommand):
    def run(self, edit):
        for region in self.view.sel():
            if region.empty():
                continue
            text = self.view.substr(region)
            replacement = self.encode(text)
            self.view.replace(edit, region, replacement)


html_escape_table = {
    u"\"": "&quot;", u"'": "&#039;", u"<": "&lt;", u">": "&gt;", u"¡": "&iexcl;", u"¢": "&cent;", u"£": "&pound;", u"¤": "&curren;", u"¥": "&yen;", u"¦": "&brvbar;", u"§": "&sect;", u"¨": "&uml;", u"©": "&copy;", u"ª": "&ordf;", u"«": "&laquo;", u"¬": "&not;", u"®": "&reg;", u"¯": "&macr;", u"°": "&deg;", u"±": "&plusmn;", u"²": "&sup2;", u"³": "&sup3;", u"´": "&acute;", u"µ": "&micro;", u"¶": "&para;", u"·": "&middot;", u"¸": "&cedil;", u"¹": "&sup1;", u"º": "&ordm;", u"»": "&raquo;", u"¼": "&frac14;", u"½": "&frac12;", u"¾": "&frac34;", u"¿": "&iquest;", u"À": "&Agrave;", u"Á": "&Aacute;", u"Â": "&Acirc;", u"Ã": "&Atilde;", u"Ä": "&Auml;", u"Å": "&Aring;", u"Æ": "&AElig;", u"Ç": "&Ccedil;", u"È": "&Egrave;", u"É": "&Eacute;", u"Ê": "&Ecirc;", u"Ë": "&Euml;", u"Ì": "&Igrave;", u"Í": "&Iacute;", u"Î": "&Icirc;", u"Ï": "&Iuml;", u"Ð": "&ETH;", u"Ñ": "&Ntilde;", u"Ò": "&Ograve;", u"Ó": "&Oacute;", u"Ô": "&Ocirc;", u"Õ": "&Otilde;", u"Ö": "&Ouml;", u"×": "&times;", u"Ø": "&Oslash;", u"Ù": "&Ugrave;", u"Ú": "&Uacute;", u"Û": "&Ucirc;", u"Ü": "&Uuml;", u"Ý": "&Yacute;", u"Þ": "&THORN;", u"ß": "&szlig;", u"à": "&agrave;", u"á": "&aacute;", u"â": "&acirc;", u"ã": "&atilde;", u"ä": "&auml;", u"å": "&aring;", u"æ": "&aelig;", u"ç": "&ccedil;", u"è": "&egrave;", u"é": "&eacute;", u"ê": "&ecirc;", u"ë": "&euml;", u"ì": "&igrave;", u"í": "&iacute;", u"î": "&icirc;", u"ï": "&iuml;", u"ð": "&eth;", u"ñ": "&ntilde;", u"ò": "&ograve;", u"ó": "&oacute;", u"ô": "&ocirc;", u"õ": "&otilde;", u"ö": "&ouml;", u"÷": "&divide;", u"ø": "&oslash;", u"ù": "&ugrave;", u"ú": "&uacute;", u"û": "&ucirc;", u"ü": "&uuml;", u"ý": "&yacute;", u"þ": "&thorn;", u"ÿ": "&yuml;", u"Œ": "&OElig;", u"œ": "&oelig;", u"Š": "&Scaron;", u"š": "&scaron;", u"Ÿ": "&Yuml;", u"ƒ": "&fnof;", u"ˆ": "&circ;", u"˜": "&tilde;", u"Α": "&Alpha;", u"Β": "&Beta;", u"Γ": "&Gamma;", u"Δ": "&Delta;", u"Ε": "&Epsilon;", u"Ζ": "&Zeta;", u"Η": "&Eta;", u"Θ": "&Theta;", u"Ι": "&Iota;", u"Κ": "&Kappa;", u"Λ": "&Lambda;", u"Μ": "&Mu;", u"Ν": "&Nu;", u"Ξ": "&Xi;", u"Ο": "&Omicron;", u"Π": "&Pi;", u"Ρ": "&Rho;", u"Σ": "&Sigma;", u"Τ": "&Tau;", u"Υ": "&Upsilon;", u"Φ": "&Phi;", u"Χ": "&Chi;", u"Ψ": "&Psi;", u"Ω": "&Omega;", u"α": "&alpha;", u"β": "&beta;", u"γ": "&gamma;", u"δ": "&delta;", u"ε": "&epsilon;", u"ζ": "&zeta;", u"η": "&eta;", u"θ": "&theta;", u"ι": "&iota;", u"κ": "&kappa;", u"λ": "&lambda;", u"μ": "&mu;", u"ν": "&nu;", u"ξ": "&xi;", u"ο": "&omicron;", u"π": "&pi;", u"ρ": "&rho;", u"ς": "&sigmaf;", u"σ": "&sigma;", u"τ": "&tau;", u"υ": "&upsilon;", u"φ": "&phi;", u"χ": "&chi;", u"ψ": "&psi;", u"ω": "&omega;", u"ϑ": "&thetasym;", u"ϒ": "&upsih;", u"ϖ": "&piv;", u"–": "&ndash;", u"—": "&mdash;", u"‘": "&lsquo;", u"’": "&rsquo;", u"‚": "&sbquo;", u"“": "&ldquo;", u"”": "&rdquo;", u"„": "&bdquo;", u"†": "&dagger;", u"‡": "&Dagger;", u"•": "&bull;", u"…": "&hellip;", u"‰": "&permil;", u"′": "&prime;", u"″": "&Prime;", u"‹": "&lsaquo;", u"›": "&rsaquo;", u"‾": "&oline;", u"⁄": "&frasl;", u"€": "&euro;", u"ℑ": "&image;", u"℘": "&weierp;", u"ℜ": "&real;", u"™": "&trade;", u"ℵ": "&alefsym;", u"←": "&larr;", u"↑": "&uarr;", u"→": "&rarr;", u"↓": "&darr;", u"↔": "&harr;", u"↵": "&crarr;", u"⇐": "&lArr;", u"⇑": "&uArr;", u"⇒": "&rArr;", u"⇓": "&dArr;", u"⇔": "&hArr;", u"∀": "&forall;", u"∂": "&part;", u"∃": "&exist;", u"∅": "&empty;", u"∇": "&nabla;", u"∈": "&isin;", u"∉": "&notin;", u"∋": "&ni;", u"∏": "&prod;", u"∑": "&sum;", u"−": "&minus;", u"∗": "&lowast;", u"√": "&radic;", u"∝": "&prop;", u"∞": "&infin;", u"∠": "&ang;", u"∧": "&and;", u"∨": "&or;", u"∩": "&cap;", u"∪": "&cup;", u"∫": "&int;", u"∴": "&there4;", u"∼": "&sim;", u"≅": "&cong;", u"≈": "&asymp;", u"≠": "&ne;", u"≡": "&equiv;", u"≤": "&le;", u"≥": "&ge;", u"⊂": "&sub;", u"⊃": "&sup;", u"⊄": "&nsub;", u"⊆": "&sube;", u"⊇": "&supe;", u"⊕": "&oplus;", u"⊗": "&otimes;", u"⊥": "&perp;", u"⋅": "&sdot;", u"⌈": "&lceil;", u"⌉": "&rceil;", u"⌊": "&lfloor;", u"⌋": "&rfloor;", u"〈": "&lang;", u"〉": "&rang;", u"◊": "&loz;", u"♠": "&spades;", u"♣": "&clubs;", u"♥": "&hearts;", u"♦": "&diams;",
}
xml_escape_table = {
    u"\"": "&quot;", u"'": "&#039;", u"<": "&lt;", u">": "&gt;"
}
html_reserved_list = (u"\"", u"'", u"<", u">", u"&")


class HtmlEntitizeCommand(StringEncode):
    def encode(self, text):
        text = text.replace('&', '&amp;')
        for k in html_escape_table:
            v = html_escape_table[k]
            text = text.replace(k, v)
        ret = ''
        for i, c in enumerate(text):
            if ord(c) > 127:
                ret += hex(ord(c)).replace('0x', '&#x') + ';'
            else:
                ret += c
        return ret


class HtmlDeentitizeCommand(StringEncode):
    def encode(self, text):
        for k in html_escape_table:
            v = html_escape_table[k]
            text = text.replace(v, k)
        while re.search('&#[xX][a-fA-F0-9]+;', text):
            match = re.search('&#[xX]([a-fA-F0-9]+);', text)
            text = text.replace(match.group(0), unichr(int('0x' + match.group(1), 16)))
        text = text.replace('&amp;', '&')
        return text


class SafeHtmlEntitizeCommand(StringEncode):
    def encode(self, text):
        for k in html_escape_table:
            # skip HTML reserved characters
            if k in html_reserved_list:
                continue
            v = html_escape_table[k]
            text = text.replace(k, v)
        ret = ''
        for i, c in enumerate(text):
            if ord(c) > 127:
                ret += hex(ord(c)).replace('0x', '&#x') + ';'
            else:
                ret += c
        return ret


class SafeHtmlDeentitizeCommand(StringEncode):
    def encode(self, text):
        for k in html_escape_table:
            # skip HTML reserved characters
            if k in html_reserved_list:
                continue
            v = html_escape_table[k]
            text = text.replace(v, k)
        while re.search('&#[xX][a-fA-F0-9]+;', text):
            match = re.search('&#[xX]([a-fA-F0-9]+);', text)
            text = text.replace(match.group(0), unichr(int('0x' + match.group(1), 16)))
        text = text.replace('&amp;', '&')
        return text


class XmlEntitizeCommand(StringEncode):
    def encode(self, text):
        text = text.replace('&', '&amp;')
        for k in xml_escape_table:
            v = xml_escape_table[k]
            text = text.replace(k, v)
        ret = ''
        for i, c in enumerate(text):
            if ord(c) > 127:
                ret += hex(ord(c)).replace('0x', '&#x') + ';'
            else:
                ret += c
        return ret


class XmlDeentitizeCommand(StringEncode):
    def encode(self, text):
        for k in xml_escape_table:
            v = xml_escape_table[k]
            text = text.replace(v, k)
        text = text.replace('&amp;', '&')
        return text


class JsonEscapeCommand(StringEncode):
    def encode(self, text):
        return json.dumps(text)


class JsonUnescapeCommand(StringEncode):
    def encode(self, text):
        return json.loads(text)


class UrlEncodeCommand(StringEncode):
    def encode(self, text):
        return urllib.parse.quote(text)


class UrlDecodeCommand(StringEncode):
    def encode(self, text):
        return urllib.parse.unquote(text)


class Base64EncodeCommand(StringEncode):
    def encode(self, text):
        return base64.b64encode(text)


class Base64DecodeCommand(StringEncode):
    def encode(self, text):
        return base64.b64decode(text)


class Escaper(StringEncode):
    def encode(self, text):
        return re.sub(r'(?<!\\)(%s)' % self.meta, r'\\\1', text)


class EscapeRegexCommand(Escaper):
    meta = r'[\\*.+^$()\[\]\{\}]'


class EscapeLikeCommand(Escaper):
    meta = r'[%_]'


class HexDecCommand(StringEncode):
    def encode(self, text):
        return str(int(text, 16))


class DecHexCommand(StringEncode):
    def encode(self, text):
        return hex(int(text))


class UnicodeHexCommand(StringEncode):
    def encode(self, text):
        hex_text = u''
        text_bytes = bytes(text, 'utf-16')

        if text_bytes[0:2] == b'\xff\xfe':
            endian = 'little'
            text_bytes = text_bytes[2:]
        elif text_bytes[0:2] == b'\xfe\xff':
            endian = 'big'
            text_bytes = text_bytes[2:]

        char_index = 0
        for c in text_bytes:
            if char_index == 0:
                c1 = c
                char_index += 1
            elif char_index == 1:
                c2 = c
                if endian == 'little':
                    c1, c2 = c2, c1
                tmp = (c1 << 8) + c2
                if tmp < 0x80:
                    hex_text += chr(tmp)
                    char_index = 0
                elif tmp >= 0xd800 and tmp <= 0xdbff:
                    char_index += 1
                else:
                    hex_text += '\\u' + '{0:04x}'.format(tmp)
                    char_index = 0
            elif char_index == 2:
                c3 = c
                char_index += 1
            elif char_index == 3:
                c4 = c
                if endian == 'little':
                    c3, c4 = c4, c3
                tmp1 = ((c1 << 8) + c2) - 0xd800
                tmp2 = ((c3 << 8) + c4) - 0xdc00
                tmp = (tmp1 * 0x400) + tmp2 + 0x10000
                hex_text += '\\U' + '{0:08x}'.format(tmp)
                char_index = 0
        return hex_text


class HexUnicodeCommand(StringEncode):
    def encode(self, text):
        uni_text = text

        endian = sys.byteorder

        r = re.compile(r'\\u([0-9a-fA-F]{2})([0-9a-fA-F]{2})')
        rr = r.search(uni_text)
        while rr:
            first_byte = int(rr.group(1), 16)

            if first_byte >= 0xd8 and first_byte <= 0xdf:
                # Surrogate pair
                pass
            else:
                if endian == 'little':
                    b1 = int(rr.group(2), 16)
                    b2 = int(rr.group(1), 16)
                else:
                    b1 = int(rr.group(1), 16)
                    b2 = int(rr.group(2), 16)

                ch = bytes([b1, b2]).decode('utf-16')

                uni_text = uni_text.replace(rr.group(0), ch)
            rr = r.search(uni_text, rr.start(0)+1)

        # Surrogate pair (2 bytes + 2 bytes)
        r = re.compile(r'\\u([0-9a-fA-F]{2})([0-9a-fA-F]{2})\\u([0-9a-fA-F]{2})([0-9a-fA-F]{2})')
        rr = r.search(uni_text)
        while rr:
            if endian == 'little':
                b1 = int(rr.group(2), 16)
                b2 = int(rr.group(1), 16)
                b3 = int(rr.group(4), 16)
                b4 = int(rr.group(3), 16)
            else:
                b1 = int(rr.group(1), 16)
                b2 = int(rr.group(2), 16)
                b3 = int(rr.group(3), 16)
                b4 = int(rr.group(4), 16)

            ch = bytes([b1, b2, b3, b4]).decode('utf-16')

            uni_text = uni_text.replace(rr.group(0), ch)
            rr = r.search(uni_text)

        # Surrogate pair (4 bytes)
        r = re.compile(r'\\U([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})')
        rr = r.search(uni_text)
        while rr:
            tmp = (int(rr.group(1), 16) << 24) \
                + (int(rr.group(2), 16) << 16) \
                + (int(rr.group(3), 16) <<  8) \
                + (int(rr.group(4), 16))

            if (tmp <= 0xffff):
                ch = chr(tmp)
            else:
                tmp -= 0x10000
                c1 = 0xd800 + int(tmp / 0x400)
                c2 = 0xdc00 + int(tmp % 0x400)
                if endian == 'little':
                    b1 = c1 & 0xff
                    b2 = c1 >> 8
                    b3 = c2 & 0xff
                    b4 = c2 >> 8
                else:
                    b1 = c1 >> 8
                    b2 = c1 & 0xff
                    b3 = c2 >> 8
                    b4 = c2 & 0xff

                ch = bytes([b1, b2, b3, b4]).decode('utf-16')

            uni_text = uni_text.replace(rr.group(0), ch)
            rr = r.search(uni_text)

        return uni_text

