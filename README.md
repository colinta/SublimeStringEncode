StringEncode
============

Encodes text.  "Encode" in this context refers to HTML entities or URL encoding, not character encodings.  Most of these commands work in both directions (e.g. you can encode *to* html entities, or *from* html entities).

- Html entities
- Css (e.g. unicode characters)
- Xml entities
- Json strings
- Urls
- Base64 encoding
- Hash: Md5, Sha256, Sha512
- Regex escape
- SQL 'LIKE' escape
- Hexadecimal / Decimal
- Unicode Hexadecimal representation

This plugin was intended to be used with selections, but if you *don't* have any text selected, it will act on *the entire document*.  This can be handy (if you're base64-encoding a file, for instance), but also have unintended consequences.  For instance, you probably should not use `URL Decode` on an entire text document.

You can also encode the clipboard, use the `string_encode_paste` command, and you will be presented with a menu to choose the encoding, and the clipboard will be encoded and inserted.

Installation
------------

1. Using Package Control, install "StringEncode"

Or:

1. Open the Sublime Text Packages folder
    - OS X: ~/Library/Application Support/Sublime Text 3/Packages/
    - Windows: %APPDATA%/Sublime Text 3/Packages/
    - Linux: ~/.Sublime Text 3/Packages/ or ~/.config/sublime-text-3/Packages

2. clone this repo
3. Install keymaps for the commands (see Example.sublime-keymap for my preferred keys)

Commands
--------

This list continues to grow, see [Default.sublime-commands](https://github.com/colinta/SublimeStringEncode/blob/master/Default.sublime-commands#L1) for the entire list.

`string_encode_paste`: Converts the clipboard to the desired encoding.

`html_entitize`: Converts characters to their HTML entity

`html_deentitize`: Converts HTML entities to a character

`url_encode`: Uses urllib.quote to escape special URL characters.
- Accepts an `old_school` argument (default: `True`).  Setting it to `False`
  will return `%20` instead of `+` when encoding spaces.

`url_decode`: Uses urllib.unquote to convert escaped URL characters

`json_escape`: Escapes a string and surrounds it in quotes, according to the JSON encoding.

`json_unescape`: Unescapes a string (include the quotes!) according to JSON encoding.

`base64_encode` (also `base16`, `base32`): Uses base16/32/64 to encode into base64

`base64_decode`: Decodes from base16/32/64

`gzip64_encode`: Gzip and then base64 encode

`gzip64_decode`: Base64 decode and then Gunzip

`md5_encode`: Uses sha package to create md5 hash

`sha256_encode` (also `sha1`, `sha384`, `sha512`): Uses sha package to create sha1/256/384/512 hash

`escape_regex`: Escapes regex meta characters

`escape_like`: Escapes SQL-LIKE meta characters

`safe_html_entitize`: Converts characters to their HTML entity, but preserves HTML reserved characters

`safe_html_deentitize`: Converts HTML entities to a character, but preserves HTML reserved characters

`xml_entitize`: Converts characters to their XML entity

`xml_deentitize`: Converts XML entities to a character

