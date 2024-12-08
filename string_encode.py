# coding: utf8
import base64
import codecs
import gzip
import hashlib
import json
import re
import sublime
import sublime_plugin
import sys

from .stringencode.escape_table import (
    html_escape_table,
    html5_escape_table,
    html_reserved_list,
    xml_escape_table
)

import urllib.parse
quote_plus = urllib.parse.quote_plus
unquote_plus = urllib.parse.unquote_plus

__all__ = [
    "StringEncodePaste",
    "Gzip64EncodeCommand",
    "Gzip64DecodeCommand",
    "UnicodeEscapeCommand",
    "HtmlEntitizeCommand",
    "HtmlDeentitizeCommand",
    "CssEscapeCommand",
    "CssUnescapeCommand",
    "SafeHtmlEntitizeCommand",
    "SafeHtmlDeentitizeCommand",
    "XmlEntitizeCommand",
    "XmlDeentitizeCommand",
    "JsonEscapeCommand",
    "JsonUnescapeCommand",
    "UrlEncodeCommand",
    "UrlDecodeCommand",
    "Base64EncodeCommand",
    "Base64DecodeCommand",
    "Md5EncodeCommand",
    "Sha1EncodeCommand",
    "Sha384EncodeCommand",
    "Sha256EncodeCommand",
    "Sha512EncodeCommand",
    "EscapeRegexCommand",
    "EscapeLikeCommand",
    "HexDecCommand",
    "DecHexCommand",
    "UnicodeHexCommand",
    "HexUnicodeCommand",
]

def pad64(value):
    mod = len(value) % 4
    if mod == 3:
        value.extend(b'=')
    elif mod == 2:
        value.extend(b'==')
    return value


class StringEncodePaste(sublime_plugin.WindowCommand):
    def run(self, **kwargs):
        items = [
            ('Html Entitize', 'html_entitize'),
            ('Html Deentitize', 'html_deentitize'),
            ('Unicode Escape', 'unicode_escape'),
            ('Css Escape', 'css_escape'),
            ('Css Unescape', 'css_unescape'),
            ('Safe Html Entitize', 'safe_html_entitize'),
            ('Safe Html Deentitize', 'safe_html_deentitize'),
            ('Xml Entitize', 'xml_entitize'),
            ('Xml Deentitize', 'xml_deentitize'),
            ('Json Escape', 'json_escape'),
            ('Json Unescape', 'json_unescape'),
            ('Url Encode', 'url_encode'),
            ('Url Decode', 'url_decode'),
            ('Base64 Encode', 'base64_encode'),
            ('Base64 Decode', 'base64_decode'),
            ('Md5 Encode', 'md5_encode'),
            ('Sha1 Encode', 'sha1_encode'),
            ('Sha256 Encode', 'sha256_encode'),
            ('Sha384 Encode', 'sha384_encode'),
            ('Sha512 Encode', 'sha512_encode'),
            ('Escape Regex', 'escape_regex'),
            ('Escape Like', 'escape_like'),
            ('Hex Dec', 'hex_dec'),
            ('Dec Hex', 'dec_hex'),
            ('Unicode Hex', 'unicode_hex'),
            ('Hex Unicode', 'hex_unicode'),
            ('Gzip64 Encode', 'gzip64_encode'),
            ('Gzip64 Decode', 'gzip64_decode'),
        ]

        lines = list(map(lambda line: line[0], items))
        commands = list(map(lambda line: line[1], items))
        view = self.window.active_view()
        if not view:
            return

        def on_done(item):
            if item == -1:
                return
            view.run_command(commands[item], {'source': 'clipboard'})

        self.window.show_quick_panel(lines, on_done)


class StringEncode(sublime_plugin.TextCommand):
    def run(self, edit, **kwargs):
        regions = self.view.sel()

        if kwargs.get('source') == 'clipboard':
            del kwargs['source']
            text = sublime.get_clipboard()
            replacement = self.encode(text, **kwargs)
            for region in regions:
                if region.empty():
                    self.view.insert(edit, region.begin(), replacement)
                else:
                    self.view.replace(edit, region, replacement)
            return

        elif 'source' in kwargs:
            self.view.show_popup('Unsupported source {0!r}'.format(kwargs['source']))
            return

        if any(map(lambda region: region.empty(), regions)):
            regions = [sublime.Region(0, self.view.size())]
        for region in regions:
            text = self.view.substr(region)
            replacement = self.encode(text, **kwargs)
            self.view.replace(edit, region, replacement)


class Gzip64EncodeCommand(StringEncode):

    def encode(self, text):
        return str(base64.b64encode(gzip.compress(bytes(text, 'utf-8'))), 'ascii')


class Gzip64DecodeCommand(StringEncode):

    def encode(self, text):
        value = pad64(bytearray(text, 'ascii'))
        return str(gzip.decompress(base64.b64decode(value)), 'utf-8')


class UnicodeEscapeCommand(StringEncode):

    def encode(self, text):
        return codecs.decode(text, 'unicode-escape')


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
        for k in html5_escape_table:
            v = html5_escape_table[k]
            text = text.replace(v, k)
        while re.search(r'&#[xX][a-fA-F0-9]+;', text):
            match = re.search(r'&#[xX]([a-fA-F0-9]+);', text)
            text = text.replace(
                match.group(0), chr(int('0x' + match.group(1), 16)))
        while re.search(r'&#[0-9]+;', text):
            match = re.search(r'&#([0-9]+);', text)
            text = text.replace(
                match.group(0), chr(int(match.group(1), 10)))
        text = text.replace('&amp;', '&')
        return text


class CssEscapeCommand(StringEncode):

    def encode(self, text):
        ret = ''
        for i, c in enumerate(text):
            if ord(c) > 127:
                ret += hex(ord(c)).replace('0x', '\\')
            else:
                ret += c
        return ret


class CssUnescapeCommand(StringEncode):

    def encode(self, text):
        while re.search(r'\\[a-fA-F0-9]+', text):
            match = re.search(r'\\([a-fA-F0-9]+)', text)
            text = text.replace(
                match.group(0), chr(int('0x' + match.group(1), 16)))
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
        while re.search(r'&#[xX][a-fA-F0-9]+;', text):
            match = re.search(r'&#[xX]([a-fA-F0-9]+);', text)
            text = text.replace(
                match.group(0), chr(int('0x' + match.group(1), 16)))
        while re.search(r'&#[0-9]+;', text):
            match = re.search(r'&#([0-9]+);', text)
            text = text.replace(
                match.group(0), chr(int(match.group(1), 10)))
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
        if text[:1] == "'" and text[-1:] == "'":
            return self.encode(text[1:-1])
        if text[:1] != '"' and text[-1:] != '"':
            return self.encode('"' + text.replace('"', '\\"') + '"')
        return json.loads(text)


class UrlEncodeCommand(StringEncode):

    def encode(self, text, old_school=True):
        quoted = quote_plus(text)
        if old_school:
            return quoted.replace("+", "%20")
        return quoted


class UrlDecodeCommand(StringEncode):

    def encode(self, text):
        return unquote_plus(text)


class Base64EncodeCommand(StringEncode):

    def encode(self, text):
        return str(base64.b64encode(bytes(text, 'utf-8')), 'ascii')


class Base64DecodeCommand(StringEncode):

    def encode(self, text):
        value = pad64(bytearray(text, 'ascii'))
        return str(base64.b64decode(value), 'utf-8')


class Md5EncodeCommand(StringEncode):

    def encode(self, text):
        return hashlib.md5(bytes(text, 'utf-8')).hexdigest()


class Sha1EncodeCommand(StringEncode):

    def encode(self, text):
        return hashlib.sha1(bytes(text, 'utf-8')).hexdigest()


class Sha256EncodeCommand(StringEncode):

    def encode(self, text):
        return hashlib.sha256(bytes(text, 'utf-8')).hexdigest()


class Sha384EncodeCommand(StringEncode):

    def encode(self, text):
        return hashlib.sha384(bytes(text, 'utf-8')).hexdigest()


class Sha512EncodeCommand(StringEncode):

    def encode(self, text):
        return hashlib.sha512(bytes(text, 'utf-8')).hexdigest()


class Escaper(StringEncode):

    def encode(self, text):
        return re.sub(r'(?<!\\)(%s)' % self.meta, r'\\\1', text)


class EscapeRegexCommand(Escaper):
    meta = r'[?\\*.+^$()\[\]\{\}\|]'


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
            rr = r.search(uni_text, rr.start(0) + 1)

        # Surrogate pair (2 bytes + 2 bytes)
        r = re.compile(
            r'\\u([0-9a-fA-F]{2})([0-9a-fA-F]{2})\\u([0-9a-fA-F]{2})([0-9a-fA-F]{2})')
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
        r = re.compile(
            r'\\U([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})')
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
