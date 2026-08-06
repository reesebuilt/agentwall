"""A JSON reader that keeps every value's source lexeme.

The audit format hashes the bytes a record's own line already contains, not a
reserialization of parsed values, so a verifier needs a reader that hands back
spans into the source rather than Python objects. ``json.loads`` cannot do that.

It also cannot do the other thing the format requires: report two members of one
object that share a decoded key. Every JSON parser resolves that silently and
none of them agree about how, so by the time ``json.loads`` returns, the evidence
that a record was edited is gone. This scanner refuses the document instead.

The scanner is strict RFC 8259: no comments, no trailing commas, no single
quotes, no raw control characters inside strings, no leading zeros or leading
plus on numbers, exactly one value per input.
"""

from __future__ import annotations

OBJECT = "object"
ARRAY = "array"
STRING = "string"
NUMBER = "number"
LITERAL = "literal"

_WHITESPACE = " \t\n\r"
_DIGITS = "0123456789"
_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


class JsonError(Exception):
    """A line that is not valid JSON."""

    def __init__(self, message: str, offset: int) -> None:
        super().__init__(message)
        self.message = message
        self.offset = offset


class TruncatedJson(JsonError):
    """Input ended in the middle of a value.

    Kept distinct from every other syntax error because the format treats a
    truncated final line as a torn tail, which a hard kill produces
    legitimately, and treats any other malformed line as tampering.
    """


class DuplicateKey(JsonError):
    """Two members of one object decode to the same key."""

    def __init__(self, key: str, offset: int) -> None:
        super().__init__("duplicate member " + repr(key), offset)
        self.key = key


class Member:
    """One object member, with the key's source span kept alongside its value.

    ``key`` is decoded because sorting compares decoded keys. The span is kept
    because emission uses the original lexeme, which is not the same thing.
    """

    __slots__ = ("key", "key_start", "key_end", "value")

    def __init__(self, key: str, key_start: int, key_end: int, value: "Value") -> None:
        self.key = key
        self.key_start = key_start
        self.key_end = key_end
        self.value = value


class Value:
    """A JSON value plus the exact source span it came from."""

    __slots__ = ("kind", "src", "start", "end", "members", "items")

    def __init__(self, kind: str, src: str, start: int, end: int) -> None:
        self.kind = kind
        self.src = src
        self.start = start
        self.end = end
        self.members: list[Member] | None = None
        self.items: list[Value] | None = None

    @property
    def lexeme(self) -> str:
        """The value exactly as the source wrote it, escapes and all."""
        return self.src[self.start : self.end]

    def get(self, name: str) -> "Value | None":
        """Look a member up by decoded key. Duplicates are impossible here."""
        if self.members is None:
            return None
        for member in self.members:
            if member.key == name:
                return member.value
        return None

    def has(self, name: str) -> bool:
        return self.get(name) is not None

    @property
    def text(self) -> str:
        """The decoded contents of a string value."""
        if self.kind != STRING:
            raise TypeError("not a string")
        return decode_string(self.src, self.start, self.end)

    @property
    def is_null(self) -> bool:
        return self.kind == LITERAL and self.lexeme == "null"


def sort_key(key: str) -> bytes:
    """Order keys by UTF-16 code unit, as the format requires.

    Encoding to UTF-16 big-endian and comparing bytes gives exactly that order,
    because every code unit becomes two bytes most significant first. It is not
    code point order: an astral character leads with a high surrogate in
    0xD800..0xDBFF and therefore sorts below U+FF21, whose code point is lower.

    ``surrogatepass`` is needed because a JSON source may spell an unpaired
    surrogate, which is a legal lexeme and has to sort somewhere.
    """
    return key.encode("utf-16-be", "surrogatepass")


def decode_string(src: str, start: int, end: int) -> str:
    """Decode a string lexeme, quotes included in the span, to its key value.

    Surrogate pairs are combined so that ``"\\ud835\\udc00"`` and the literal
    character decode alike, which is what makes them sort alike. An unpaired
    surrogate is kept as the lone code point it spells.
    """
    body = src[start + 1 : end - 1]
    if "\\" not in body:
        return body
    out: list[str] = []
    i = 0
    length = len(body)
    while i < length:
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        esc = body[i + 1]
        if esc == "u":
            unit = int(body[i + 2 : i + 6], 16)
            i += 6
            if 0xD800 <= unit <= 0xDBFF and body[i : i + 2] == "\\u":
                low = int(body[i + 2 : i + 6], 16)
                if 0xDC00 <= low <= 0xDFFF:
                    out.append(chr(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)))
                    i += 6
                    continue
            out.append(chr(unit))
            continue
        out.append(_ESCAPES[esc])
        i += 2
    return "".join(out)


class _Scanner:
    __slots__ = ("src", "pos", "limit")

    def __init__(self, src: str) -> None:
        self.src = src
        self.pos = 0
        self.limit = len(src)

    def _end(self, what: str) -> TruncatedJson:
        return TruncatedJson("input ended while reading " + what, self.pos)

    def _bad(self, what: str) -> JsonError:
        return JsonError(what + " at offset " + str(self.pos), self.pos)

    def skip_whitespace(self) -> None:
        src = self.src
        pos = self.pos
        limit = self.limit
        while pos < limit and src[pos] in _WHITESPACE:
            pos += 1
        self.pos = pos

    def value(self) -> Value:
        if self.pos >= self.limit:
            raise self._end("a value")
        ch = self.src[self.pos]
        if ch == "{":
            return self.object()
        if ch == "[":
            return self.array()
        if ch == '"':
            return self.string()
        if ch == "-" or ch in _DIGITS:
            return self.number()
        if self.src.startswith("true", self.pos):
            return self._literal(4)
        if self.src.startswith("false", self.pos):
            return self._literal(5)
        if self.src.startswith("null", self.pos):
            return self._literal(4)
        # A prefix of a literal at end of input is truncation, not garbage.
        for word in ("true", "false", "null"):
            if word.startswith(self.src[self.pos : self.limit]):
                raise self._end("a literal")
        raise self._bad("unexpected character " + repr(ch))

    def _literal(self, size: int) -> Value:
        start = self.pos
        self.pos += size
        return Value(LITERAL, self.src, start, self.pos)

    def string(self) -> Value:
        src = self.src
        limit = self.limit
        start = self.pos
        pos = start + 1
        while True:
            if pos >= limit:
                self.pos = pos
                raise self._end("a string")
            ch = src[pos]
            if ch == '"':
                pos += 1
                break
            if ch == "\\":
                if pos + 1 >= limit:
                    self.pos = pos
                    raise self._end("a string escape")
                esc = src[pos + 1]
                if esc == "u":
                    hexits = src[pos + 2 : pos + 6]
                    if len(hexits) < 4:
                        self.pos = pos
                        raise self._end("a unicode escape")
                    for hexit in hexits:
                        if hexit not in "0123456789abcdefABCDEF":
                            self.pos = pos
                            raise self._bad("bad unicode escape")
                    pos += 6
                    continue
                if esc not in _ESCAPES:
                    self.pos = pos
                    raise self._bad("bad escape " + repr("\\" + esc))
                pos += 2
                continue
            if ch < " ":
                self.pos = pos
                raise self._bad("raw control character in string")
            pos += 1
        self.pos = pos
        return Value(STRING, src, start, pos)

    def number(self) -> Value:
        src = self.src
        limit = self.limit
        start = self.pos
        pos = start
        if pos < limit and src[pos] == "-":
            pos += 1
        if pos >= limit:
            self.pos = pos
            raise self._end("a number")
        if src[pos] == "0":
            pos += 1
        elif src[pos] in _DIGITS:
            while pos < limit and src[pos] in _DIGITS:
                pos += 1
        else:
            self.pos = pos
            raise self._bad("expected a digit")
        if pos < limit and src[pos] == ".":
            pos += 1
            if pos >= limit:
                self.pos = pos
                raise self._end("a fraction")
            if src[pos] not in _DIGITS:
                self.pos = pos
                raise self._bad("expected a digit after the decimal point")
            while pos < limit and src[pos] in _DIGITS:
                pos += 1
        if pos < limit and src[pos] in "eE":
            pos += 1
            if pos < limit and src[pos] in "+-":
                pos += 1
            if pos >= limit:
                self.pos = pos
                raise self._end("an exponent")
            if src[pos] not in _DIGITS:
                self.pos = pos
                raise self._bad("expected a digit in the exponent")
            while pos < limit and src[pos] in _DIGITS:
                pos += 1
        self.pos = pos
        return Value(NUMBER, src, start, pos)

    def array(self) -> Value:
        start = self.pos
        self.pos += 1
        items: list[Value] = []
        self.skip_whitespace()
        if self.pos >= self.limit:
            raise self._end("an array")
        if self.src[self.pos] == "]":
            self.pos += 1
            node = Value(ARRAY, self.src, start, self.pos)
            node.items = items
            return node
        while True:
            self.skip_whitespace()
            items.append(self.value())
            self.skip_whitespace()
            if self.pos >= self.limit:
                raise self._end("an array")
            ch = self.src[self.pos]
            if ch == ",":
                self.pos += 1
                continue
            if ch == "]":
                self.pos += 1
                break
            raise self._bad("expected , or ] in an array")
        node = Value(ARRAY, self.src, start, self.pos)
        node.items = items
        return node

    def object(self) -> Value:
        start = self.pos
        self.pos += 1
        members: list[Member] = []
        seen: set[str] = set()
        self.skip_whitespace()
        if self.pos >= self.limit:
            raise self._end("an object")
        if self.src[self.pos] == "}":
            self.pos += 1
            node = Value(OBJECT, self.src, start, self.pos)
            node.members = members
            return node
        while True:
            self.skip_whitespace()
            if self.pos >= self.limit:
                raise self._end("an object member")
            if self.src[self.pos] != '"':
                raise self._bad("expected a member name")
            key_node = self.string()
            key = decode_string(self.src, key_node.start, key_node.end)
            if key in seen:
                raise DuplicateKey(key, key_node.start)
            seen.add(key)
            self.skip_whitespace()
            if self.pos >= self.limit:
                raise self._end("an object member")
            if self.src[self.pos] != ":":
                raise self._bad("expected :")
            self.pos += 1
            self.skip_whitespace()
            members.append(Member(key, key_node.start, key_node.end, self.value()))
            self.skip_whitespace()
            if self.pos >= self.limit:
                raise self._end("an object")
            ch = self.src[self.pos]
            if ch == ",":
                self.pos += 1
                continue
            if ch == "}":
                self.pos += 1
                break
            raise self._bad("expected , or } in an object")
        node = Value(OBJECT, self.src, start, self.pos)
        node.members = members
        return node


def parse(src: str) -> Value:
    """Read one JSON value and require it to be the whole input."""
    scanner = _Scanner(src)
    scanner.skip_whitespace()
    if scanner.pos >= scanner.limit:
        raise TruncatedJson("no value", 0)
    node = scanner.value()
    scanner.skip_whitespace()
    if scanner.pos != scanner.limit:
        raise JsonError("trailing data after the value", scanner.pos)
    return node
