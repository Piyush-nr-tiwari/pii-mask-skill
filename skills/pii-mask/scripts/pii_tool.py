#!/usr/bin/env python3
"""PII scanner and masker for the /pii-mask skill.

Never prints a raw PII value. Findings are reported as type + location +
masked preview only, so it is safe to show its output in chat.

Usage:
  python pii_tool.py scan <file>                       # exit 1 if PII found
  python pii_tool.py mask <in> <out> [--terms FILE]    # writes masked copy
  python pii_tool.py text <in> <run-dir>/.work/x.txt   # readable text of any format
  python pii_tool.py compare <original> <masked>       # what changed (per column for tables), no values
  python pii_tool.py clean <run-dir>                   # delete <run-dir>/.work

Agents should need nothing but these commands (plus Read/Write), so one
permission rule for this script covers the whole run.

Supported: .txt .md .csv .tsv .json .log .xml .yaml .yml .html, code/other
text files, .xlsx, .docx, .pdf. The masked copy always keeps the input's
format (PDF in, PDF out, layout kept; needs PyMuPDF).

Terms file (for things only a reader can recognise, like names and
addresses): one entry per line, "TYPE<TAB>value". TYPE is NAME, ADDRESS or
OTHER. Lines starting with # are ignored.
"""
import csv
import io
import math
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------- masking rules

def _star(s):
    return "*" * len(s)


def mask_word(w):
    """First letter kept, rest starred: Piyush -> P*****. Digits fully starred."""
    if not w:
        return w
    if w.isdigit():
        return _star(w)
    return w[0] + _star(w[1:])


def mask_name(v):
    tokens = re.findall(r"[^\W_]+", v)
    if len(tokens) > 2 and all(len(t) == 1 for t in tokens):
        # Letter-spaced text ("J O H N  D O E"): keep the first letter only.
        first = [True]

        def one(m):
            if first[0]:
                first[0] = False
                return m.group(0)
            return "*"
        return re.sub(r"[^\W_]", one, v)
    return re.sub(r"[^\W_]+", lambda m: mask_word(m.group(0)), v)


def mask_address(v):
    parts = v.split(",")
    out = []
    for i, p in enumerate(parts):
        last = i == len(parts) - 1 and len(parts) > 1
        if last:  # keep the city / state, star numbers (PIN / ZIP)
            out.append(re.sub(r"\d", "*", p))
        else:
            out.append(re.sub(r"[^\W_]+", lambda m: mask_word(m.group(0)), p))
    return ",".join(out)


def mask_email(v):
    local, _, domain = v.partition("@")
    return local[:1] + "***@" + domain


def _keep_ends(digits, head, tail):
    if len(digits) <= head + tail:
        return _star(digits)
    return digits[:head] + "*" * (len(digits) - head - tail) + digits[-tail:]


def mask_phone(v):
    m = re.match(r"\s*(\+\d{1,3}|00\d{1,3})?[\s-]?(.*)", v)
    cc, rest = m.group(1) or "", m.group(2)
    digits = re.sub(r"\D", "", rest)
    if not cc and len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
        cc = "0"
    body = _keep_ends(digits, 2, 2)
    return (cc + " " if cc else "") + body


def mask_last4(v):
    """Keep the last 4 characters of an ID, star the rest, keep separators.

    Short IDs keep less, so a mask never shows half the value or more:
    8+ characters keep 4, 5-7 keep 2, 4 or fewer are fully starred.
    """
    v = str(v).strip()
    n = sum(c.isalnum() for c in v)
    keep = 4 if n >= 8 else 2 if n >= 5 else 0
    out, seen = [], 0
    for c in v:
        if c.isalnum():
            seen += 1
            out.append(c if seen > n - keep else "*")
        else:
            out.append(c)
    return "".join(out)


def mask_aadhaar(v):
    d = re.sub(r"\D", "", v)
    return "**** **** " + d[-4:]


def mask_card(v):
    d = re.sub(r"\D", "", v)
    return "**** **** **** " + d[-4:]


def mask_ssn(v):
    d = re.sub(r"\D", "", v)
    return "***-**-" + d[-4:]


def mask_ip(v):
    a = v.split(".")
    return ".".join(a[:2] + ["*", "*"])


def mask_handle_url(m):
    return m.group(1) + mask_word(m.group(2))


def mask_date(v):
    """Hide day and month, keep the year: 14/07/1988 -> **/**/1988, 02-10-97 -> **-**-97."""
    v = str(v)
    # ISO date, optionally with a time (how spreadsheet date cells read): 1988-07-14 00:00:00
    m = re.fullmatch(r"\s*(\d{4})-\d{1,2}-\d{1,2}(?:[ T]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?\s*", v)
    if m:
        return "**/**/" + m.group(1)
    m = re.fullmatch(r"\s*\d{1,2}([/.\-])\d{1,2}\1(\d{4}|\d{2})\s*", v)
    if m:
        return f"**{m.group(1)}**{m.group(1)}{m.group(2)}"
    y = re.search(r"(\d{4})\s*$", v)
    return "**/**/" + y.group(1) if y else re.sub(r"\d", "*", v)


def mask_zip(v):
    return re.sub(r"[0-9A-Za-z]", "*", str(v))


# ---------------------------------------------------------------- detectors
# Order matters: earlier detectors win when spans overlap.

# Shared/role inboxes are not about a person, so they are left alone.
ROLE_MAILBOXES = {"support", "help", "helpdesk", "info", "contact", "sales", "admin", "noreply", "no-reply",
                  "donotreply", "billing", "accounts", "hr", "careers", "jobs", "team", "hello", "office",
                  "service", "customercare", "care", "feedback", "press", "media", "legal", "privacy",
                  "security", "abuse", "postmaster", "webmaster", "orders", "returns", "refunds"}

NB = r"(?<![\w*])"   # not preceded by a word char or an existing mask star
NA = r"(?![\w*])"


def _luhn(num):
    d = [int(c) for c in num][::-1]
    s = sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])
    return s % 10 == 0


DETECTORS = [
    ("EMAIL", re.compile(r"(?<![\w.*+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), mask_email,
     lambda s: s.split("@")[0].lower() not in ROLE_MAILBOXES),
    ("PROFILE_URL", re.compile(
        r"((?:https?://)?(?:www\.)?(?:linkedin\.com/in|github\.com|twitter\.com|x\.com|instagram\.com|facebook\.com|t\.me)/)"
        r"([A-Za-z0-9_.-]{2,})(?![\w*-])", re.I), None, mask_handle_url),
    ("UPI_ID", re.compile(r"(?<![\w.*-])[A-Za-z0-9._-]{2,}@(?:ok(?:axis|sbi|icici|hdfcbank)|ybl|ibl|axl|paytm|upi|apl|okbizaxis|waicici|wahdfcbank)\b", re.I), mask_email, None),
    ("CARD_NUMBER", re.compile(r"(?<![\d*])(?:\d[ -]?){12,18}\d(?![\d*])"), mask_card,
     lambda s: _luhn(re.sub(r"\D", "", s)) and 13 <= len(re.sub(r"\D", "", s)) <= 19),
    ("PAN", re.compile(NB + r"[A-Z]{5}\d{4}[A-Z]" + NA), mask_last4, None),
    ("SSN", re.compile(r"(?<![\d*])\d{3}-\d{2}-\d{4}(?![\d*])"), mask_ssn, None),
    ("IP_ADDRESS", re.compile(r"(?<![\d*])(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d*])(?!\.\d)"), mask_ip, None),
    ("PHONE", re.compile(r"(?<![\d*])(?:(?:\+|00)91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?![\d*])"), mask_phone, None),
    ("PHONE", re.compile(r"(?<![\w*])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?![\d*])"), mask_phone,
     lambda s: 8 <= len(re.sub(r"\D", "", s)) <= 15),
    ("PHONE", re.compile(r"(?<![\d*])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\d*])"), mask_phone, None),
    ("AADHAAR", re.compile(r"(?<![\d*])[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?![\d*])"), mask_aadhaar, None),
]

# Values that are only PII because of the label in front of them.
LABELED = re.compile(
    r"(?i)\b(passport(?:\s*(?:no\.?|number|#))?|a/c(?:\s*no\.?)?|account\s*(?:no\.?|number|#)|"
    r"voter\s*id|epic(?:\s*no\.?)?|(?:driving|driver'?s?)\s*licen[cs]e(?:\s*(?:no\.?|number|#))?|dl\s*(?:no\.?|#)|"
    r"employee\s*id|emp\s*id|uan|pf\s*(?:no\.?|number)|customer\s*id|patient\s*id|mrn|"
    r"policy\s*(?:no\.?|number)|national\s*id|tax\s*id|tin|ssn|aadhaa?r(?:\s*no\.?)?)"
    r"(\s*[:#=\-]?\s*)([A-Za-z0-9][A-Za-z0-9/.\-]{3,24})(?![\w*])")
DOB = re.compile(
    r"(?i)\b(dob|d\.o\.b\.?|date\s*of\s*birth|birth\s*date|born(?:\s*on)?)"
    r"(\s*(?:[:=\-]|\b(?:is|was)\b)?\s*)"
    r"(\d{4}-\d{2}-\d{2}|\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}|\d{1,2}\s+[A-Za-z]{3,9},?\s+\d{4}|[A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4})"
    r"(?![\d*])")

# Column headers that mean "every value in this column is PII".
# Headers are normalised first ("customerName", "customer_name" -> "customer name"),
# so whole-word matching works on every naming style.
# A header containing "name" is a person's name unless it names a thing.
_NOT_A_PERSON = re.compile(
    r"(?i)\b(company|companies|business|firm|org|organi[sz]ation|product|item|sku|file|host|domain|brand|"
    r"bank|branch|plan|course|project|event|store|shop|city|town|state|country|region|district|street|road|"
    r"place|server|sheet|table|column|field|app|application|device|model|category|dept|department|team|"
    r"vendor|merchant|supplier|school|college|university|hospital|employer|campaign|channel|type|group|"
    r"program|programme|tag|label|role|title|job|position|display|screen|user)\b")
_HEADER_RULES = [
    ("ADDRESS", re.compile(r"(?i)^(?!.*\b(e ?-?mail|ip|mac|web|url)\b).*\b(address|street|addr|residence|"
                           r"house (no|number)|address line \d)\b")),
    ("ZIP", re.compile(r"(?i)\b(zip|zip ?code|postal ?code|post ?code|postcode|pin ?code|pincode)\b")),
    ("DOB", re.compile(r"(?i)^dob$|\bdate of birth\b|\bbirth ?date\b|\bbirthday\b|\bd\.o\.b\b")),
    ("ID", re.compile(
        r"(?i)\b(licen[cs]e|passport|ssn|social security|aadhaa?r|national id|voter|tax id|iban|mrn|"
        r"medical record)\b|^pan( (no|number|card))?$|^(tin|nin|itin)$|"
        r"\b(account|acct|a/c) ?(no|num|number|#)|\bnhs ?(no|number)\b|"
        r"\b(employee|emp|patient|member|student|insurance|policy) ?(id|no|num|number|#)")),
]
# Columns that describe a document rather than identify it: "License Issue Date", "Licence Class".
_ID_DESCRIPTOR = re.compile(r"(?i)\b(date|issued|issue|expiry|expiration|expires|valid|state|class|type|"
                            r"status|country|category|verified|count|endorsements?|restrictions?)\b")


def _norm_header(h):
    h = re.sub(r"([a-z])([A-Z])", r"\1 \2", str(h or "")).replace("_", " ").replace("-", " ")
    return re.sub(r"\s+", " ", h).strip()


def header_type(h):
    """The PII kind every value in a column holds, from its header, or None."""
    h = _norm_header(h)
    if not h or len(h) > 60:
        return None
    for typ, rx in _HEADER_RULES:
        if rx.search(h):
            if typ == "ID" and _ID_DESCRIPTOR.search(h):
                return None
            return typ
    if re.search(r"(?i)\b(birth ?place|place of birth|country of birth)\b", h):
        return None
    if re.search(r"(?i)\b((full|first|last|middle|given|family|sur|fore|maiden) ?name|surname|forename)\b", h):
        return "NAME"
    if re.search(r"(?i)\bnames?\b", h) and not _NOT_A_PERSON.search(h):
        return "NAME"
    if re.fullmatch(r"(?i)(patient|customer|client|employee|contact person|father|mother|spouse|guardian|"
                    r"nominee|candidate|applicant|beneficiary|insured|policy ?holder|account ?holder|"
                    r"card ?holder)", h):
        return "NAME"
    return None


def _column_hints(headers):
    return {i: t for i, t in ((i, header_type(h)) for i, h in enumerate(headers)) if t}


def find_spans(text):
    """Return non-overlapping (start, end, type, masked) for pattern PII in text."""
    taken = []
    out = []

    def free(a, b):
        return all(b <= s or a >= e for s, e in taken)

    for typ, rx, fn, extra in DETECTORS:
        for m in rx.finditer(text):
            a, b = m.span()
            if not free(a, b):
                continue
            if typ == "PROFILE_URL":
                masked = extra(m)
            else:
                if extra and not extra(m.group(0)):
                    continue
                masked = fn(m.group(0))
            taken.append((a, b))
            out.append((a, b, typ, masked))
    for m in LABELED.finditer(text):
        a, b = m.span(3)
        val = m.group(3).rstrip(".-/")
        b = a + len(val)
        if "*" in val or not any(c.isdigit() for c in val) or not free(a, b):
            continue
        taken.append((a, b))
        out.append((a, b, "LABELED_ID", mask_last4(val)))
    for m in DOB.finditer(text):
        a, b = m.span(3)
        if not free(a, b):
            continue
        taken.append((a, b))
        out.append((a, b, "DATE_OF_BIRTH", mask_date(m.group(3))))
    return sorted(out)


def load_terms(path):
    terms = []
    if not path:
        return terms
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        typ, _, val = line.partition("\t")
        typ, val = typ.strip().upper(), val.strip()
        if not val:
            typ, val = "OTHER", typ
        if len(val) < 2:
            continue
        fn = {"NAME": mask_name, "ADDRESS": mask_address}.get(typ, mask_name)
        terms.append((typ, val, fn))
    terms.sort(key=lambda t: -len(t[1]))  # longest first
    return terms


def mask_spans(text, terms):
    """All (start, end, type, masked) spans to replace, in original-text positions.

    Patterns first (so an email or URL is masked as a whole), then the
    reader-supplied terms (names, addresses), longest first, in whatever
    text the patterns did not claim.
    """
    spans = find_spans(text)
    taken = [(a, b) for a, b, _, _ in spans]
    for typ, val, fn in terms:
        rx = re.compile(r"(?<![\w*])" + re.escape(val) + r"(?![\w*])", re.I)
        for m in rx.finditer(text):
            a, b = m.span()
            if all(b <= s or a >= e for s, e in taken):
                taken.append((a, b))
                spans.append((a, b, typ, fn(m.group(0))))
    return sorted(spans)


def mask_text(text, terms, counts):
    for a, b, typ, masked in reversed(mask_spans(text, terms)):
        counts[typ] += 1
        text = text[:a] + masked + text[b:]
    return text


def _is_masked(v):
    v = str(v).strip()
    return v == "" or "*" in v or v.upper() in {"NA", "N/A", "NONE", "NULL", "-"}


def mask_column_value(typ, v):
    v = str(v)
    if typ == "ID":
        # A known pattern (SSN, card, Aadhaar...) keeps its usual mask; anything else keeps its last characters.
        masked = mask_text(v, [], Counter())
        return masked if masked != v else mask_last4(v)
    return {"NAME": mask_name, "ADDRESS": mask_address, "DOB": mask_date, "ZIP": mask_zip}[typ](v)


# ---------------------------------------------------------------- file I/O

TEXT_EXT = {".txt", ".md", ".json", ".log", ".xml", ".yaml", ".yml", ".html", ".htm",
            ".ini", ".cfg", ".env", ".py", ".js", ".ts", ".java", ".sql", ".sh", ".rtf"}


def read_units(path):
    """Yield (location, text) units, plus header-column info for tables."""
    p = Path(path)
    ext = p.suffix.lower()
    if ext in (".csv", ".tsv"):
        delim = "\t" if ext == ".tsv" else ","
        rows = list(csv.reader(io.StringIO(p.read_text(encoding="utf-8-sig", errors="replace")), delimiter=delim))
        yield from _table_units(rows, lambda r, c: f"row {r + 1}, col {c + 1}")
    elif ext == ".xlsx":
        import openpyxl
        wb = openpyxl.load_workbook(p, data_only=False)
        for ws in wb.worksheets:
            rows = [[("" if c is None else str(c)) for c in row] for row in ws.iter_rows(values_only=True)]
            yield from _table_units(rows, lambda r, c, n=ws.title: f"{n}!{openpyxl.utils.get_column_letter(c + 1)}{r + 1}")
    elif ext == ".docx":
        import docx
        d = docx.Document(p)
        for i, para in enumerate(_docx_paragraphs(d)):
            yield f"paragraph {i + 1}", para.text, None
    elif ext == ".pdf":
        pymupdf = _pymupdf()
        with pymupdf.open(p) as doc:
            for pi, page in enumerate(doc):
                lines = _pdf_lines(page)
                if not lines and page.get_images():
                    yield f"page {pi + 1}", "[NO TEXT LAYER: scanned or image-only page, cannot be masked]", None
                for li, (line, _) in enumerate(lines):
                    yield f"page {pi + 1}, line {li + 1}", line, None
    else:
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines()):
            yield f"line {i + 1}", line, None


def _table_units(rows, loc):
    hints = _column_hints(rows[0]) if rows else {}
    for r, row in enumerate(rows):
        for c, v in enumerate(row):
            yield loc(r, c), str(v), (hints.get(c) if r > 0 else None)


def _pymupdf():
    try:
        import pymupdf
    except ImportError:
        try:
            import fitz as pymupdf
        except ImportError:
            print("REFUSED: PDF support needs PyMuPDF. Install it with: pip install pymupdf")
            sys.exit(2)
    return pymupdf


def _pdf_lines(page):
    """Visual lines of a PDF page: [(text, info)], info[i] = (char, span) or None.

    Characters are grouped by baseline and sorted left to right, so the
    result doesn't depend on content-stream order. That matters because the
    masker writes its replacement text at the end of the stream, and scan,
    text, compare and mask must all see the same lines.
    """
    chars = []
    for block in page.get_text("rawdict")["blocks"]:
        if block.get("type") != 0:
            continue
        for line in block["lines"]:
            for span in line["spans"]:
                span["dir"] = line["dir"]
                for ch in span["chars"]:
                    if ch["c"]:
                        chars.append((ch["origin"][1], ch["origin"][0], ch, span))
    chars.sort(key=lambda t: (t[0], t[1]))
    rows, cur = [], []
    for item in chars:
        if cur and item[0] - cur[0][0] > 0.4 * max(cur[0][3]["size"], 1):
            rows.append(cur)
            cur = []
        cur.append(item)
    if cur:
        rows.append(cur)
    out = []
    for row in rows:
        row.sort(key=lambda t: t[1])
        text, info, prev = [], [], None
        for _, _, ch, span in row:
            if prev is not None:
                gap = ch["bbox"][0] - prev["bbox"][2]
                size = max(span["size"], 1)
                if gap > 2.5 * size:          # column break: never let a pattern run across it
                    text.append("   ")
                    info.extend([None] * 3)
                elif gap > 0.2 * size and ch["c"] != " " and prev["c"] != " ":
                    text.append(" ")
                    info.append(None)
            text.append(ch["c"])
            info.extend([(ch, span)] * len(ch["c"]))
            prev = ch
        s = "".join(text)
        if s.strip():
            out.append((s, info))
    return out


def _inside(ch, rects):
    cx, cy = (ch["bbox"][0] + ch["bbox"][2]) / 2, (ch["bbox"][1] + ch["bbox"][3]) / 2
    return any(r.x0 <= cx <= r.x1 and r.y0 <= cy <= r.y1 for r in rects)


def _kept_chars(lines, redacted):
    """(char, x, y) of every visible character that the redactions must leave in place."""
    return [(x[0]["c"], x[0]["origin"][0], x[0]["origin"][1])
            for _, info in lines for x in info
            if x is not None and x[0]["c"].strip() and not _inside(x[0], redacted)]


def _char_index(page):
    now = {}
    for _, info in _pdf_lines(page):
        for x in info:
            if x is not None:
                now.setdefault((x[0]["c"], round(x[0]["origin"][1])), []).append(x[0]["origin"][0])
    return now


def _misplaced(page, kept):
    now = _char_index(page)
    return [k for k in kept if not any(abs(v - k[1]) < 0.4 for v in now.get((k[0], round(k[2])), []))]


def _shift_of(page, run):
    """How far left a run of kept characters has moved (0 if in place, None if not found)."""
    now = _char_index(page)
    c0, x0, y0 = run[0]
    for s in sorted(x0 - v for v in now.get((c0, round(y0)), []) if v <= x0 + 0.4):
        if all(any(abs(v - (x - s)) < 0.4 for v in now.get((c, round(y)), [])) for c, x, y in run[1:]):
            return s
    return None


# A number between two strings inside a TJ array: a horizontal adjustment.
_TJ_NUM = re.compile(rb"(?<=[>)])\s*(-?\d+(?:\.\d+)?)(?=\s*[<(])")


def _repair_shifts(doc, page, kept, anchors):
    """Undo the text shift some MuPDF releases leave after a redaction.

    MuPDF 1.28 (PyMuPDF 2.x) replaces a removed run with a TJ adjustment that
    is short by the first removed glyph's width, so the rest of the line
    slides left. For each redaction we measure the slide on the kept text
    after it, then correct whichever adjustment puts that text back. Every
    change is verified against the original positions and undone if it
    doesn't help, so this can only move text back to where it was.
    """
    if len(page.get_contents()) != 1:
        page.clean_contents()
    xref = page.get_contents()[0]
    bad = _misplaced(page, kept)
    for run, size in anchors:
        if not bad:
            break
        shift = _shift_of(page, run)
        if not shift or abs(shift) < 0.4:
            continue
        stream = doc.xref_stream(xref)
        nums = sorted(_TJ_NUM.finditer(stream), key=lambda m: not m.group(1).endswith(b".0001"))
        for m in nums:
            new = float(m.group(1)) - shift * 1000 / size
            doc.update_stream(xref, stream[:m.start(1)] + f"{new:.4f}".encode() + stream[m.end(1):])
            page = doc.reload_page(page)
            now = _misplaced(page, kept)
            if len(now) < len(bad):
                bad = now
                break
            doc.update_stream(xref, stream)
            page = doc.reload_page(page)
    return page, bad


def _pdf_font(span):
    # The font name is more reliable than the serif flag, which many PDF makers set wrongly.
    name = span["font"].lower()
    bold = span["flags"] & 16 or any(w in name for w in ("bold", "black", "heavy", "semibold"))
    if "sans" in name or any(w in name for w in ("arial", "helvetica", "calibri", "verdana", "roboto",
                                                   "inter", "segoe", "tahoma", "lato", "open", "carlito")):
        serif = False
    elif any(w in name for w in ("serif", "times", "georgia", "garamond", "cambria", "roman", "book",
                                 "tinos", "merriweather", "palatino")):
        serif = True
    else:
        serif = span["flags"] & 4
    if serif:
        return "tibo" if bold else "tiro"
    return "hebo" if bold else "helv"


def _mask_pdf(src, dst, terms, counts):
    """Mask a PDF in place: redact each PII run and write its masked form in the same spot."""
    pymupdf = _pymupdf()
    doc = pymupdf.open(src)
    if doc.needs_pass:
        print("REFUSED: the PDF is password-protected.")
        return 2
    scanned = []
    for pi, page in enumerate(doc):
        lines = _pdf_lines(page)
        if not lines and page.get_images():
            scanned.append(pi + 1)
        redacted, inserts, after = [], [], []
        for text, info in lines:
            for a, b, typ, masked in mask_spans(text, terms):
                cells = [x for x in info[a:b] if x is not None]
                if not cells:
                    continue
                counts[typ] += 1
                rect = pymupdf.Rect()
                for ch, _ in cells:
                    rect |= pymupdf.Rect(ch["bbox"])
                redacted.append(rect)
                after.append((info[b:], cells[0][1]["size"]))
                # Shrink to the middle band so neighbours that only touch the edge survive.
                h, w0, w1 = rect.height, cells[0][0]["bbox"], cells[-1][0]["bbox"]
                core = pymupdf.Rect(rect.x0 + (w0[2] - w0[0]) * 0.3, rect.y0 + h * 0.3,
                                    rect.x1 - (w1[2] - w1[0]) * 0.3, rect.y1 - h * 0.3)
                page.add_redact_annot(core, fill=False, cross_out=False)
                ch0, span = cells[0]
                font, size = _pdf_font(span), span["size"]
                dx, dy = span["dir"]
                angle = round(math.degrees(math.atan2(-dy, dx)) / 90) * 90 % 360
                room = rect.width if angle in (0, 180) else rect.height
                need = pymupdf.get_text_length(masked, fontname=font, fontsize=size)
                if need > room * 0.95 > 0:   # stay inside the old text's box
                    size *= max(room * 0.95 / need, 0.5)
                inserts.append((pymupdf.Point(ch0["origin"]), masked, font, size,
                                pymupdf.sRGB_to_pdf(span["color"]), angle))
        if redacted:
            kept = _kept_chars(lines, redacted)
            # The first few kept characters after each redaction, to measure any slide.
            anchors = []
            for tail, size in after:
                run = [(x[0]["c"], x[0]["origin"][0], x[0]["origin"][1]) for x in tail
                       if x is not None and x[0]["c"].strip() and not _inside(x[0], redacted)][:5]
                if run:
                    anchors.append((run, size))
            page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_NONE,
                                  graphics=pymupdf.PDF_REDACT_LINE_ART_NONE,
                                  text=pymupdf.PDF_REDACT_TEXT_REMOVE)
            page, moved = _repair_shifts(doc, page, kept, anchors)
            if moved:
                print(f"REFUSED: removing the PII moved {len(moved)} character(s) of kept text on page "
                      f"{pi + 1} and it could not be put back, so no masked copy was written.")
                return 2
            for point, masked, font, size, color, angle in inserts:
                page.insert_text(point, masked, fontname=font, fontsize=size, color=color,
                                 rotate=angle)
        # Clickable links still carry the raw email / profile address.
        for link in page.get_links():
            uri = link.get("uri") or ""
            hits = mask_text(uri, terms, Counter()) != uri
            near = uri and any(link["from"].intersects(r) for r in redacted)
            if hits or near:
                page.delete_link(link)
                counts["LINK_TARGET"] += 1
        for annot in page.annots():
            info = annot.info
            new = mask_text(info.get("content", ""), terms, counts)
            if new != info.get("content", ""):
                annot.set_info(content=new)
                annot.update()
        for w in page.widgets() or []:
            if isinstance(w.field_value, str):
                new = mask_text(w.field_value, terms, counts)
                if new != w.field_value:
                    w.field_value = new
                    w.update()
    meta = {k: v for k, v in (doc.metadata or {}).items()
            if k in ("title", "author", "subject", "keywords", "creator", "producer") and v}
    if meta:
        new = {k: mask_text(v, terms, counts) for k, v in meta.items()}
        if meta.get("author") and "*" not in new["author"]:
            new["author"] = mask_name(meta["author"])
            counts["METADATA"] += 1
        doc.set_metadata(new)
    toc = doc.get_toc(simple=False)
    if toc:
        doc.set_toc([[t[0], mask_text(t[1], terms, counts), *t[2:]] for t in toc])
    # Drop the places PII hides out of sight: XMP metadata, attachments,
    # scripts, thumbnails and invisible text.
    doc.scrub(metadata=False, remove_links=False, reset_fields=False, redactions=False,
              clean_pages=True, hidden_text=True, xml_metadata=True, attached_files=True,
              embedded_files=True, javascript=True, thumbnails=True, reset_responses=True)
    doc.save(dst, garbage=4, deflate=True, clean=True)
    doc.close()
    if scanned:
        print(f"WARNING: page(s) {', '.join(map(str, scanned))} have no text layer (scanned?). "
              "They could not be masked, so the file is NOT clean.")
    return 0


def _docx_paragraphs(d):
    def walk(container):
        for para in container.paragraphs:
            yield para
        for t in getattr(container, "tables", []):
            for row in t.rows:
                for cell in row.cells:
                    yield from walk(cell)
    yield from walk(d)
    for s in d.sections:
        for part in (s.header, s.footer):
            yield from walk(part)


# ---------------------------------------------------------------- commands

def cmd_scan(path):
    findings = []
    for loc, text, col in read_units(path):
        if col and not _is_masked(text):
            findings.append((loc, f"{col} (column)", mask_column_value(col, text)))
        for a, b, typ, masked in find_spans(text):
            findings.append((loc, typ, masked))
    if not findings:
        print("CLEAN: no pattern-detectable PII found. (Names and addresses in free text still need a human-style read.)")
        return 0
    print(f"FOUND {len(findings)} possible PII item(s). Raw values are never printed.")
    for loc, typ, masked in findings[:200]:
        print(f"  {loc}: {typ} -> would mask as {masked}")
    if len(findings) > 200:
        print(f"  ... and {len(findings) - 200} more")
    c = Counter(t for _, t, _ in findings)
    print("By type: " + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
    return 1


def cmd_mask(src, dst, terms_path):
    s, d = Path(src), Path(dst)
    if s.suffix.lower() != d.suffix.lower():
        print(f"REFUSED: the masked copy must keep the input's format ({s.suffix} -> {d.suffix}). "
              f"Use an output name ending in {s.suffix}.")
        return 2
    # Pre-approved script: only ever write inside a .pii-masked/ folder, and never over the input.
    if ".pii-masked" not in [x.lower() for x in d.resolve().parts] or d.resolve() == s.resolve():
        print("REFUSED: the masked copy must be written inside a .pii-masked/ folder.")
        return 2
    terms = load_terms(terms_path)
    counts = Counter()
    d.parent.mkdir(parents=True, exist_ok=True)
    ext = s.suffix.lower()
    if ext in (".csv", ".tsv"):
        delim = "\t" if ext == ".tsv" else ","
        raw = _read_raw(s, "utf-8-sig")
        eol = "\r\n" if "\r\n" in raw else "\n"
        rows = list(csv.reader(io.StringIO(raw, newline=""), delimiter=delim))
        rows = _mask_table(rows, terms, counts)
        buf = io.StringIO()
        csv.writer(buf, delimiter=delim, lineterminator=eol).writerows(rows)
        _write_raw(d, buf.getvalue())
    elif ext == ".xlsx":
        import openpyxl
        wb = openpyxl.load_workbook(s)
        for ws in wb.worksheets:
            first = next(ws.iter_rows(min_row=1, max_row=1), [])
            hints = {first[i].column: t for i, t in _column_hints([c.value for c in first]).items()}
            for row in ws.iter_rows():
                for cell in row:
                    if cell.value is None or cell.data_type == "f":
                        continue
                    v = str(cell.value)
                    if cell.row > 1 and cell.column in hints and not _is_masked(v):
                        counts[hints[cell.column]] += 1
                        cell.value = mask_column_value(hints[cell.column], v)
                        continue
                    new = mask_text(v, terms, counts)
                    if new != v:
                        cell.value = new
        wb.save(d)
    elif ext == ".docx":
        import docx
        doc = docx.Document(s)
        for para in _docx_paragraphs(doc):
            _mask_docx_para(para, terms, counts)
        doc.save(d)
    elif ext == ".pdf":
        rc = _mask_pdf(s, d, terms, counts)
        if rc:
            return rc
    else:
        _write_raw(d, mask_text(_read_raw(s), terms, counts))
    total = sum(counts.values())
    print(f"MASKED {total} item(s) -> {d}")
    if counts:
        print("By type: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0


def _read_raw(path, enc="utf-8"):
    # newline="" keeps the original line endings (LF or CRLF) untouched.
    with open(path, encoding=enc, errors="replace", newline="") as f:
        return f.read()


def _write_raw(path, text):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def _mask_table(rows, terms, counts):
    hints = _column_hints(rows[0]) if rows else {}
    out = []
    for r, row in enumerate(rows):
        new = []
        for c, v in enumerate(row):
            if r > 0 and c in hints and not _is_masked(v):
                counts[hints[c]] += 1
                new.append(mask_column_value(hints[c], v))
            else:
                new.append(mask_text(v, terms, counts))
        out.append(new)
    return out


def _mask_docx_para(para, terms, counts):
    # Try run by run first (keeps formatting); fall back to whole paragraph
    # when a value is split across runs.
    for run in para.runs:
        new = mask_text(run.text, terms, counts)
        if new != run.text:
            run.text = new
    probe = Counter()
    full = mask_text(para.text, terms, probe)
    if full != para.text and para.runs:
        counts.update(probe)
        para.runs[0].text = full
        for run in para.runs[1:]:
            run.text = ""


def _in_work_dir(p):
    parts = [x.lower() for x in Path(p).resolve().parts]
    return ".work" in parts


def cmd_text(src, out):
    # The text contains raw PII, so it may only be written inside a .work folder.
    if not _in_work_dir(out):
        print("REFUSED: text output must go inside the run's .work folder.")
        return 2
    o = Path(out)
    o.parent.mkdir(parents=True, exist_ok=True)
    with open(o, "w", encoding="utf-8", newline="") as f:
        for loc, text, _ in read_units(src):
            f.write(f"[{loc}] {text}\n")
    print(f"TEXT written -> {o}")
    return 0


def cmd_compare(original, masked):
    a = [(loc, text) for loc, text, _ in read_units(original)]
    b = [(loc, text) for loc, text, _ in read_units(masked)]
    ext_o, ext_m = Path(original).suffix.lower(), Path(masked).suffix.lower()
    if ext_o != ext_m:
        print(f"FORMAT DIFFERS: original={ext_o} masked={ext_m}  <-- the masked copy must keep the input's format")
    if ext_o == ".pdf" and ext_m == ".pdf":
        pymupdf = _pymupdf()
        with pymupdf.open(original) as x, pymupdf.open(masked) as y:
            po, pm = len(x), len(y)
            print(f"Pages: original={po} masked={pm}" + ("" if po == pm else "  <-- DIFFERS"))
            io_, im = sum(len(p.get_images()) for p in x), sum(len(p.get_images()) for p in y)
            print(f"Images: original={io_} masked={im} (images are kept as they are; check them for photos)")
    print(f"Units (lines/cells/paragraphs): original={len(a)} masked={len(b)}"
          + ("" if len(a) == len(b) else "  <-- STRUCTURE DIFFERS"))
    changed = [a[i][0] for i in range(min(len(a), len(b))) if a[i][1] != b[i][1]]
    print(f"Changed units: {len(changed)} (each should hold PII; values not shown)")
    if ext_o in (".xlsx", ".csv", ".tsv"):
        # Per column, so a whole column of PII reads as one line and a stray change stands out.
        def col_of(loc):
            m = re.match(r"(.*!)([A-Z]+)\d+$", loc) or re.match(r"row \d+, (col \d+)$", loc)
            return "".join(g for g in m.groups() if g) if m else loc
        per_col = Counter(col_of(loc) for loc in changed)
        total = Counter(col_of(loc) for loc, _ in a)
        print("Changed by column (changed / cells in column):")
        for col, n in per_col.items():
            print(f"  {col}: {n} / {total[col]}")
    limit = 2000
    for loc in changed[:limit]:
        print(f"  {loc}")
    if len(changed) > limit:
        print(f"  ... and {len(changed) - limit} more")
    if ext_o == ext_m and ext_o not in (".xlsx", ".docx", ".pdf"):
        eo = "CRLF" if "\r\n" in _read_raw(original) else "LF"
        em = "CRLF" if "\r\n" in _read_raw(masked) else "LF"
        print(f"Line endings: original={eo} masked={em}" + ("" if eo == em else "  <-- DIFFERS"))
    return 0 if len(a) == len(b) else 1


def cmd_clean(run_dir):
    w = Path(run_dir) / ".work"
    if ".pii-masked" not in [x.lower() for x in Path(run_dir).resolve().parts]:
        print("REFUSED: clean only works on a folder inside .pii-masked/.")
        return 2
    if w.exists():
        shutil.rmtree(w)
        print(f"DELETED {w}")
    else:
        print("Nothing to clean.")
    return 0


def main(argv):
    if len(argv) >= 2 and argv[0] == "scan":
        return cmd_scan(argv[1])
    if len(argv) >= 3 and argv[0] == "text":
        return cmd_text(argv[1], argv[2])
    if len(argv) >= 3 and argv[0] == "compare":
        return cmd_compare(argv[1], argv[2])
    if len(argv) >= 2 and argv[0] == "clean":
        return cmd_clean(argv[1])
    if len(argv) >= 3 and argv[0] == "mask":
        terms = None
        if "--terms" in argv:
            terms = argv[argv.index("--terms") + 1]
        return cmd_mask(argv[1], argv[2], terms)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(sys.argv[1:]))
