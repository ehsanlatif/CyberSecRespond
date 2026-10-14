"""Pure-stdlib binary/document format builders for the synthetic forensic disk.

Every artifact this module emits is (a) a *valid enough* file that `file(1)` classifies it
correctly and a real viewer can open it, and (b) **offline-recoverable** with the tools the
agent's image ships (`strings`, `pdftotext`, `zcat`, `xxd`, `jq`): the semantic content is
always present as extractable text — an OCR/text layer for images, an uncompressed content
stream for PDFs, ASCII + UTF-16LE copies inside binary blobs (registry hives, event logs).

No third-party dependencies — just zlib/struct/binascii/gzip from the stdlib. Keeping these
builders in one place lets build_disk.py stay about *forensic semantics*, not file plumbing.
"""
from __future__ import annotations

import binascii
import gzip as _gzip
import io
import struct
import zlib

# --------------------------------------------------------------------------- PDF (text layer)

def pdf_bytes(title: str, paragraphs: list[str]) -> bytes:
    """A multi-page PDF with an *uncompressed* text content stream, so both a viewer and
    `pdftotext`/`strings -a` recover every word. Helvetica 10pt, manual wrap + pagination."""
    def esc(s: str) -> str:
        return (s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)"))

    # wrap to ~95 cols, then paginate ~58 lines/page
    wrapped: list[str] = []
    for para in [title, "=" * len(title), ""] + list(paragraphs):
        p = para.rstrip("\n")
        if not p:
            wrapped.append("")
            continue
        while len(p) > 95:
            cut = p.rfind(" ", 40, 95)
            cut = cut if cut > 0 else 95
            wrapped.append(p[:cut])
            p = p[cut:].lstrip()
        wrapped.append(p)
    pages = [wrapped[i:i + 58] for i in range(0, max(len(wrapped), 1), 58)] or [[""]]

    objs: list[bytes] = []          # obj bodies, 1-indexed by position
    font_obj = 3 + len(pages) * 2   # after catalog(1), pages(2), then page/content pairs

    def content_stream(lines: list[str]) -> bytes:
        body = ["BT", "/F1 10 Tf", "12 TL", "54 740 Td"]
        for ln in lines:
            body.append(f"({esc(ln)}) Tj T*")
        body.append("ET")
        s = "\n".join(body).encode("latin-1", "replace")
        return b"<< /Length %d >>\nstream\n%s\nendstream" % (len(s), s)

    kids = " ".join(f"{3 + 2 * i} 0 R" for i in range(len(pages)))
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")                       # 1
    objs.append(b"<< /Type /Pages /Kids [%s] /Count %d >>"
                % (kids.encode(), len(pages)))                              # 2
    for i, plines in enumerate(pages):                                      # page + content pairs
        cnum = 3 + 2 * i + 1
        objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                    b"/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>"
                    % (font_obj, cnum))
        objs.append(content_stream(plines))
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")  # font

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, body in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n%s\nendobj\n" % (i, body))
    xref_pos = out.tell()
    out.write(b"xref\n0 %d\n" % (len(objs) + 1))
    out.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
              % (len(objs) + 1, xref_pos))
    return out.getvalue()


# --------------------------------------------------------------------------- PNG (+ text layer)

def _png_chunk(typ: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + typ + data
            + struct.pack(">I", binascii.crc32(typ + data) & 0xFFFFFFFF))


def _png(width: int, height: int, rows: list[bytearray], texts: list[tuple[str, str]]) -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)   # 8-bit truecolour RGB
    raw = b"".join(b"\x00" + bytes(r) for r in rows)              # filter type 0 per scanline
    out = sig + _png_chunk(b"IHDR", ihdr)
    for k, v in texts:                                            # tEXt: uncompressed, strings-visible
        out += _png_chunk(b"tEXt", k.encode("latin-1", "replace") + b"\x00"
                          + v.encode("latin-1", "replace"))
    out += _png_chunk(b"IDAT", zlib.compress(raw, 9)) + _png_chunk(b"IEND", b"")
    return out


def png_page_bytes(ocr_text: str, *, embed_text: bool = True,
                   width: int = 620, height: int = 800) -> bytes:
    """A page-image raster (white page, colour header band, gray 'text-line' rules) whose full
    transcription rides in a tEXt 'ocr'/'Description' layer — the scanned-report pattern. Pass
    embed_text=False for a true image-only modality-swap probe (doc 01 §5 probe E / §6 Δ1)."""
    rows = [bytearray([255, 255, 255] * width) for _ in range(height)]
    for y in range(24, 84):                                       # header band
        for x in range(width):
            rows[y][x * 3:x * 3 + 3] = bytes((32, 64, 120))
    y = 120                                                       # faux text lines
    for _ in range((height - 160) // 26):
        for x in range(54, width - 54):
            rows[y][x * 3:x * 3 + 3] = bytes((90, 90, 90))
            rows[y + 1][x * 3:x * 3 + 3] = bytes((150, 150, 150))
        y += 26
    texts = [("Software", "synthetic forensic range (page image)")]
    if embed_text:
        texts += [("ocr", ocr_text), ("Description", ocr_text[:800])]
    return _png(width, height, rows, texts)


def png_chart_bytes(title: str, series: list[tuple[str, float]], *,
                    embed_text: bool = True, width: int = 560, height: int = 260) -> bytes:
    """A bar chart raster with the underlying numbers in a tEXt layer. Genuinely drawn bars
    (dark on white) so it renders; the data is recoverable regardless."""
    rows = [bytearray([255, 255, 255] * width) for _ in range(height)]
    base, top, left = height - 30, 30, 60
    peak = max((v for _, v in series), default=1.0) or 1.0
    n = max(len(series), 1)
    bw = max(8, (width - left - 30) // (n * 2))
    for i, (_, v) in enumerate(series):
        x0 = left + i * bw * 2
        h = int((base - top) * (v / peak))
        for x in range(x0, min(x0 + bw, width)):
            for yy in range(base - h, base):
                rows[yy][x * 3:x * 3 + 3] = bytes((200, 60, 40))
    for x in range(left, width - 20):                              # x axis
        rows[base][x * 3:x * 3 + 3] = bytes((20, 20, 20))
    for y in range(top, base):                                     # y axis
        rows[y][left * 3:left * 3 + 3] = bytes((20, 20, 20))
    data = "; ".join(f"{k}={v}" for k, v in series)
    texts = [("Title", title)]
    if embed_text:
        texts += [("ocr", f"{title} :: {data}"), ("data", data)]
    return _png(width, height, rows, texts)


# --------------------------------------------------------------------------- binaries

def elf_bytes(strings_: list[str], *, exec_type: bool = True, size_pad: int = 4096) -> bytes:
    """A header-valid 64-bit LSB x86-64 ELF (so `file` says 'ELF 64-bit LSB, stripped') with
    the given strings embedded for `strings`/`sha256sum` forensics. Not runnable — a sample."""
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    hdr = e_ident + struct.pack("<HHIQQQIHHHHHH",
                                2 if exec_type else 3, 0x3E, 1,   # ET_EXEC/DYN, EM_X86_64, v1
                                0x400000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    payload = ("\n".join([".interp /lib64/ld-linux-x86-64.so.2", "GCC: (GNU) 11.4.0",
                          "__libc_start_main", "malloc", "socket", "connect"] + strings_)
               ).encode("latin-1", "replace")
    blob = hdr + payload
    if len(blob) < size_pad:                                       # deterministic non-zero pad
        blob += bytes(((i * 37 + 11) & 0xFF) for i in range(size_pad - len(blob)))
    return blob


def pe_bytes(strings_: list[str], *, size_pad: int = 4096) -> bytes:
    """A header-valid PE32+ (x86-64) image (so `file` says 'PE32+ executable') carrying the
    given strings. Minimal DOS stub + PE signature + COFF/optional header magic."""
    dos = bytearray(b"MZ" + b"\x90" * 0x3A)
    dos += struct.pack("<I", 0x80)                                 # e_lfanew -> PE header @0x80
    dos += b"This program cannot be run in DOS mode.\r\n$"
    dos += b"\x00" * (0x80 - len(dos))
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)  # x86-64, 1 section
    opt = struct.pack("<H", 0x20B) + b"\x0e\x00" + b"\x00" * 0xEC   # PE32+ magic + linker ver
    pe = b"PE\x00\x00" + coff + opt
    payload = ("\n".join(["KERNEL32.dll", "ADVAPI32.dll", "CryptEncrypt",
                          "GetProcAddress"] + strings_)).encode("latin-1", "replace")
    blob = bytes(dos) + pe + payload
    if len(blob) < size_pad:
        blob += bytes(((i * 41 + 7) & 0xFF) for i in range(size_pad - len(blob)))
    return blob


def inert_sample_bytes(label: str, strings_: list[str], *, size_pad: int = 1024) -> bytes:
    """A clearly-INERT forensic 'binary' sample — NOT a runnable executable. A labelled text
    header + (defanged) strings + a short benign pseudo-hexdump. `file(1)` reports plain text;
    `sha256sum`/`strings`/`grep` still work, so the "hash the dropped binary" forensic step is
    preserved without ever writing a real PE/ELF (or any live payload) to a corporate machine."""
    head = ("SYNTHETIC-INERT-SAMPLE (%s) — not a runnable executable; content defanged for a "
            "DFIR evaluation. Original was a dropped binary; compute sha256 to record its hash.\n\n"
            % label)
    body = head + "\n".join(strings_) + "\n\n--- pseudo hexdump (benign filler) ---\n"
    rows = []
    for i in range(0, min(size_pad, 512), 16):
        row = " ".join("%02x" % (((i + j) * 37 + 11) & 0x7F) for j in range(16))
        rows.append("%08x  %s" % (i, row))
    return (body + "\n".join(rows) + "\n").encode("latin-1", "replace")


def _u16le(s: str) -> bytes:
    return s.encode("utf-16-le", "replace")


def evtx_bytes(records: list[str]) -> bytes:
    """A Windows EVTX-magic ('ElfFile\\x00') blob with event XML embedded as ASCII *and*
    UTF-16LE, so both `strings` and `strings -e l` recover the records (as real evtx does)."""
    head = b"ElfFile\x00" + b"\x00" * 24 + struct.pack("<Q", len(records))
    body = bytearray(head)
    for r in records:
        body += b"\x2a\x2a\x00\x00" + r.encode("latin-1", "replace") + b"\n"
        body += _u16le(r) + b"\x00\x00"
    if len(body) < 4096:
        body += bytes(4096 - len(body))
    return bytes(body)


def hive_bytes(entries: list[str]) -> bytes:
    """A registry-hive-magic ('regf') blob with key/value strings in UTF-16LE (+ ASCII), the
    way `strings -e l` reads a real SOFTWARE/SYSTEM/NTUSER.DAT hive."""
    head = b"regf" + b"\x00" * 60
    body = bytearray(head)
    for e in entries:
        body += b"vk" + _u16le(e) + b"\x00\x00"
        body += b"# " + e.encode("latin-1", "replace") + b"\n"
    if len(body) < 4096:
        body += bytes(4096 - len(body))
    return bytes(body)


def gzip_bytes(data: bytes, name: str = "") -> bytes:
    """A gzip member (rotated-log style) — the agent must `zcat`/`gzip -dc` to read it."""
    buf = io.BytesIO()
    with _gzip.GzipFile(fileobj=buf, mode="wb", filename=name, mtime=0) as gz:
        gz.write(data)
    return buf.getvalue()
