"""Fonte ASCII par blocs embarquee (5 lignes) pour banniere et titres de modules."""

GLYPHS = {
    "A": [" ## ", "#  #", "####", "#  #", "#  #"],
    "B": ["### ", "#  #", "### ", "#  #", "### "],
    "C": [" ###", "#   ", "#   ", "#   ", " ###"],
    "D": ["### ", "#  #", "#  #", "#  #", "### "],
    "E": ["####", "#   ", "### ", "#   ", "####"],
    "F": ["####", "#   ", "### ", "#   ", "#   "],
    "G": [" ###", "#   ", "# ##", "#  #", " ###"],
    "H": ["#  #", "#  #", "####", "#  #", "#  #"],
    "I": ["####", " ## ", " ## ", " ## ", "####"],
    "J": ["### ", "   #", "   #", "#  #", " ## "],
    "K": ["#  #", "# # ", "##  ", "# # ", "#  #"],
    "L": ["#   ", "#   ", "#   ", "#   ", "####"],
    "M": ["#   #", "## ##", "# # #", "#   #", "#   #"],
    "N": ["#  #", "## #", "# ##", "#  #", "#  #"],
    "O": [" ## ", "#  #", "#  #", "#  #", " ## "],
    "P": ["### ", "#  #", "### ", "#   ", "#   "],
    "Q": [" ## ", "#  #", "#  #", " ## ", "  ##"],
    "R": ["### ", "#  #", "### ", "# # ", "#  #"],
    "S": [" ###", "#   ", " ## ", "   #", "### "],
    "T": ["####", " ## ", " ## ", " ## ", " ## "],
    "U": ["#  #", "#  #", "#  #", "#  #", " ## "],
    "V": ["#  #", "#  #", "#  #", " ## ", " ## "],
    "W": ["#   #", "#   #", "# # #", "## ##", "#   #"],
    "X": ["#  #", " ## ", " ## ", " ## ", "#  #"],
    "Y": ["#  #", "#  #", " ## ", " ## ", " ## "],
    "Z": ["####", "  ##", " ## ", "#   ", "####"],
    "0": [" ## ", "#  #", "#  #", "#  #", " ## "],
    "1": ["  # ", "### ", "  # ", "  # ", "####"],
    "2": [" ###", "#  #", "  ##", " #  ", "####"],
    "3": ["### ", "   #", " ## ", "   #", "### "],
    "4": ["#  #", "#  #", "####", "   #", "   #"],
    "5": ["####", "#   ", "### ", "   #", "### "],
    "6": [" ## ", "#   ", "### ", "#  #", " ## "],
    "7": ["####", "   #", "  ##", " #  ", " #  "],
    "8": [" ## ", "#  #", " ## ", "#  #", " ## "],
    "9": [" ## ", "#  #", " ###", "   #", " ## "],
    " ": ["  ", "  ", "  ", "  ", "  "],
    "-": ["   ", "   ", "###", "   ", "   "],
    ".": [" ", " ", " ", " ", "#"],
    ",": [" ", " ", " ", " ", "#"],
    ":": [" ", "#", " ", "#", " "],
    ";": [" ", "#", " ", "#", " "],
    "/": [" #", " #", "# ", "# ", "# "],
    "\\": ["# ", "# ", " #", " #", " #"],
    "_": ["   ", "   ", "   ", "   ", "###"],
    "&": [" ## ", "#  #", "# ##", "#  #", " ## "],
    "!": ["#", "#", "#", " ", "#"],
    "?": [" ###", "#  #", "  ##", "    ", "  ##"],
    "+": ["    ", " ## ", "####", " ## ", "    "],
    "=": ["    ", "####", "    ", "####", "    "],
    "<": ["  #", " # ", "#  ", " # ", "  #"],
    ">": ["#  ", " # ", "  #", " # ", "#  "],
    "*": ["    ", "# # ", " ## ", "# # ", "    "],
    "'": ["#", "#", " ", " ", " "],
    "\"": ["# #", "# #", "   ", "   ", "   "],
    "(": [" #", "# ", "# ", "# ", " #"],
    ")": ["# ", " #", " #", " #", "# "],
    "[": ["##", "# ", "# ", "# ", "##"],
    "]": ["##", " #", " #", " #", "##"],
    "%": ["#  #", "  # ", " #  ", "#   ", "#  #"],
    "#": [" # # ", "#####", " # # ", "#####", " # # "],
    "@": [" ### ", "#   #", "# ###", "#    ", " ### "],
    "$": ["  #  ", "#### ", " ### ", "#### ", "  #  "],
}

HEIGHT = 5
_UNKNOWN = GLYPHS["?"]
_BLANK = GLYPHS[" "]


def glyph_width(ch):
    return len(GLYPHS.get(ch, _UNKNOWN)[0])


def text_width(text):
    return sum(glyph_width(ch) for ch in text.upper()) + max(0, len(text) - 1)


def render(text, block="█", empty=" "):
    """Rend un texte en 5 lignes de blocs (les lignes sont trimées a droite)."""
    upper = str(text).upper()
    glyphs = [GLYPHS.get(ch, _BLANK if ch == " " else _UNKNOWN) for ch in upper]
    if not glyphs:
        return [""] * HEIGHT
    lines = []
    for row in range(HEIGHT):
        parts = [g[row] for g in glyphs]
        line = " ".join(parts)
        line = line.replace("#", block)
        if empty != " ":
            line = line.replace(" ", empty)
        lines.append(line.rstrip())
    return lines


def print_block(text, color=None, indent="", block="█"):
    from . import ui

    for row in render(text, block=block):
        print(ui.paint(indent + row, color) if color else indent + row)


def _pack_words(words, max_chars):
    lines = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= max_chars:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def _hard_split(words, max_chars):
    """Repli : coupe net a max_chars, meme au-dela de max_lines."""
    chopped = []
    for word in words:
        while len(word) > max_chars:
            chopped.append(word[:max_chars])
            word = word[max_chars:]
        if word:
            chopped.append(word)
    return _pack_words(chopped, max_chars)


def pack_title(name, max_chars=14, max_lines=3):
    """Decoupe un titre de module en lignes courtes pour l'art ASCII.

    Repli : si la decoupe douce deborde (trop de lignes ou ligne trop
    large), on retombe sur une coupure dure par paquets de max_chars —
    le titre est toujours rendu, jamais vide pour un nom non vide.
    """
    words = [w for w in str(name).upper().replace("-", " ").split() if w]
    if not words:
        return []
    lines = _pack_words(words, max_chars)
    if len(lines) <= max_lines and max(len(l) for l in lines) <= max_chars + 6:
        return lines
    return _hard_split(words, max_chars) or lines
