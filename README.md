StringEncode plugin for Sublime Text 2
======================================

Converts characters from one "encoding" to another using a transformation (think HTML entities, not character encodings).

Installation
------------

1. Open the Sublime Text 2 Packages folder
    - OS X: ~/Library/Application Support/Sublime Text 2/Packages/
    - Windows: %APPDATA%/Sublime Text 2/Packages/
    - Linux: ~/.Sublime Text 2/Packages/
2. clone this repo
3. Install keymaps for the commands (see Example.sublime-keymap for my preferred keys)

Commands
--------

`html_entitize`: Converts characters to their HTML entity

`html_deentitize`: Converts HTML entities to a character

`url_encode`: Uses urllib.quote to escape special URL characters

`url_decode`: Uses urllib.unquote to convert escaped URL characters

`base64_encode`: Uses base64 to encode into base64

`base64_decode`: Uses base64 to decode from base64

`escape_regex`: Escapes regex meta characters

`escape_like`: Escapes SQL-LIKE meta characters

`safe_html_entitize`: Converts characters to their HTML entity, but preserves HTML reserved characters

`safe_html_deentitize`: Converts HTML entities to a character, but preserves HTML reserved characters

TODO
----

`xml_entitize`: Converts characters to their XML entity

`xml_deentitize`: Converts XML entities to a character
