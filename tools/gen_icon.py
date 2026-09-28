"""Genere assets/icon.png et assets/icon.ico (pur Python, sans Pillow).

Design : cadre rouge sur fond sombre, lettres FCK / MT rendues avec la
fonte bloc embarquee de fckmt.fonts. Rejouer :
    python tools/gen_icon.py
"""
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fckmt import fonts  # noqa: E402

SIZE = 256
BG = (18, 8, 10, 255)
RED = (232, 17, 45, 255)
WHITE = (245, 245, 245, 255)
BORDER = 6


def _text_width(text, scale):
    return fonts.text_width(text) * scale


def render_icon(size=SIZE):
    pixels = [list(BG) for _ in range(size * size)]

    def fill_rect(x0, y0, x1, y1, color):
        for y in range(max(0, y0), min(size, y1)):
            row = y * size
            for x in range(max(0, x0), min(size, x1)):
                pixels[row + x] = list(color)

    fill_rect(0, 0, size, BORDER, RED)
    fill_rect(0, size - BORDER, size, size, RED)
    fill_rect(0, 0, BORDER, size, RED)
    fill_rect(size - BORDER, 0, size, size, RED)

    lines = [("FCK", RED), ("MT", WHITE)]
    scale = 14
    gap = 14
    widths = [_text_width(text, scale) for text, _ in lines]
    heights = [fonts.HEIGHT * scale for _ in lines]
    total_h = sum(heights) + gap * (len(lines) - 1)
    x_start = max(BORDER + 4, (size - max(widths)) // 2)
    y = (size - total_h) // 2

    for (text, color), width, height in zip(lines, widths, heights):
        blocks = fonts.render(text)
        x = x_start + (max(widths) - width) // 2
        for row_index, row in enumerate(blocks):
            col = 0
            while col < len(row):
                if row[col] == "█":
                    start = col
                    while col < len(row) and row[col] == "█":
                        col += 1
                    fill_rect(x + start * scale, y + row_index * scale,
                              x + col * scale, y + (row_index + 1) * scale, color)
                else:
                    col += 1
        y += height + gap

    return size, b"".join(bytes(p) for p in pixels)


def write_png(path, size, rgba):
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    raw = b"".join(b"\x00" + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as handle:
        handle.write(png)
    return len(png)


def downscale(size, rgba, new_size):
    out = bytearray(new_size * new_size * 4)
    for y in range(new_size):
        src_y = y * size // new_size
        for x in range(new_size):
            src_x = x * size // new_size
            src = (src_y * size + src_x) * 4
            dst = (y * new_size + x) * 4
            out[dst:dst + 4] = rgba[src:src + 4]
    return bytes(out)


def bmp_dib(size, rgba):
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                         size * size * 4, 0, 0, 0, 0)
    rows = bytearray()
    for y in range(size - 1, -1, -1):
        for x in range(size):
            r, g, b, a = rgba[(y * size + x) * 4:(y * size + x) * 4 + 4]
            rows += bytes((b, g, r, a))
    row_bytes = ((size + 31) // 32) * 4
    mask = bytearray()
    for y in range(size - 1, -1, -1):
        bits = 0
        count = 0
        line = bytearray()
        for x in range(size):
            alpha = rgba[(y * size + x) * 4 + 3]
            bits = (bits << 1) | (1 if alpha < 128 else 0)
            count += 1
            if count == 8:
                line.append(bits)
                bits = 0
                count = 0
        if count:
            line.append(bits << (8 - count))
        while len(line) < row_bytes:
            line.append(0)
        mask += line
    return header + bytes(rows) + bytes(mask)


def write_ico(path, base_size, rgba):
    entries = []
    images = []
    offset = 6 + 16 * 4
    for target in (16, 32, 48):
        data = bmp_dib(target, downscale(base_size, rgba, target))
        entries.append((target, target, data))
    png_bytes = bytearray()

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    raw = b"".join(b"\x00" + rgba[y * base_size * 4:(y + 1) * base_size * 4]
                   for y in range(base_size))
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", base_size, base_size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")

    blobs = [data for _, _, data in entries] + [bytes(png)]
    sizes = [(w, h) for w, h, _ in entries] + [(0, 0)]
    for (w, h), blob in zip(sizes, blobs):
        images.append((w, h, blob))

    out = struct.pack("<HHH", 0, 1, len(images))
    cursor = 6 + 16 * len(images)
    directory = b""
    body = b""
    for w, h, blob in images:
        directory += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(blob), cursor)
        body += blob
        cursor += len(blob)
    with open(path, "wb") as handle:
        handle.write(out + directory + body)
    return 6 + 16 * len(images) + len(body)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assets = os.path.join(root, "assets")
    os.makedirs(assets, exist_ok=True)
    size, rgba = render_icon(SIZE)
    png_path = os.path.join(assets, "icon.png")
    ico_path = os.path.join(assets, "icon.ico")
    print(f"icon.png : {write_png(png_path, size, rgba)} octets")
    print(f"icon.ico : {write_ico(ico_path, size, rgba)} octets")


if __name__ == "__main__":
    main()
