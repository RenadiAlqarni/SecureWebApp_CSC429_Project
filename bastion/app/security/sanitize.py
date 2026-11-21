"""
Input sanitization for user-generated content (comments).

XSS defence in secure mode has three independent layers:

  1. sanitize_comment() (this file) - on input, all HTML markup is removed and
     only the visible text is kept. The contents of dangerous elements such as
     <script> and <style> are dropped entirely. Control characters are removed
     and length is capped.
  2. Output encoding - templates print comments with {{ c.body }}; Jinja2's
     autoescaping turns < > & " ' into HTML entities, so whatever survived is
     shown as text and never parsed as markup.
  3. Content-Security-Policy header (headers.py) - the browser refuses to run
     inline scripts and event handlers even if layers 1 and 2 were bypassed.

The vulnerable build skips all three and prints comments with |safe.

Python's built-in html.parser is used instead of hand-written regular
expressions because regexes cannot reliably parse HTML (nested and malformed
tags, attributes without quotes, entities). The `bleach` library used to be
the standard tool for this but is deprecated, so no extra dependency is added.
"""
import re
import unicodedata
from html.parser import HTMLParser

MAX_COMMENT_LENGTH = 500

# Elements whose *content* is not visible text and must be discarded.
_DROP_CONTENT = {"script", "style", "iframe", "object", "embed", "noscript",
                 "template", "svg", "math", "textarea", "title"}

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class _TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in _DROP_CONTENT:
            self._skip += 1

    def handle_startendtag(self, tag, attrs):
        pass  # self-closing tags (<img/>, <svg/>) have no text content

    def handle_endtag(self, tag):
        if tag in _DROP_CONTENT and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def strip_tags(text):
    parser = _TextOnly()
    parser.feed(text)
    parser.close()
    return "".join(parser.parts)


def sanitize_comment(text):
    """Return a plain-text, length-limited version of `text` that contains no HTML."""
    text = unicodedata.normalize("NFKC", text or "")
    text = _CONTROL_CHARS.sub("", text)
    # Run twice so markup hidden inside entities (&lt;script&gt;) is removed too.
    text = strip_tags(strip_tags(text))
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:MAX_COMMENT_LENGTH]
