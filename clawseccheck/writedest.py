"""Where a skill's code file WRITES: destination spans, read-only and verdict-free.

C-755 (the tensorlake persistence form): checks/_vet.py binds an agent / IDE config path
to a write destination instead of pairing it with a write verb by character distance.
This module is the parser half of that rule - it never decides what a destination
means; _vet.py owns the targets and the verdict.

* `mask_code` blanks comments, Python docstrings and shell heredoc bodies (and, in a
  second view, string contents except f-string / template holes), same length.
* `dest_spans` returns every write destination: a write/copy/mkdir call's destination
  argument by POSITION, a pathlib-style write method's receiver, or - in a shell file at
  command position, or inside the string / argv list handed to os.system, subprocess.*,
  child_process exec/spawn - a redirect target or the destination word of
  cp/mv/install/ln/rsync/tee/touch/mkdir/sed -i/dd of=. A command printed by
  echo/print/console.log is never parsed as one. Each destination carries the spans of
  the data written to it when that is visible (the data argument, `.write(X)` chained on
  open(), `json.dump(X, open(...))`, a `with open(...) as f` block, a heredoc body).
* Every pass is linear: brackets are paired once per file (`bracket_table`), never
  re-scanned per call. Argument lists and statements are read for at most SPAN chars.

Stdlib only; never executes or imports what it reads.
"""
from __future__ import annotations

import re

_CALL_RE = re.compile(
    r"(?<![\w$])(?:(?P<w0>writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|"
    r"outputFileSync|outputFile|writeJsonSync|writeJson|outputJsonSync|outputJson)|"
    r"(?P<w1>copyFileSync|copyFile|cpSync|copytree|copy2|copyfile|copy|move|renameSync|"
    r"rename|symlinkSync|symlink|linkSync)|"
    r"(?P<d0>makedirs|mkdirSync|mkdirp|mkdirs|ensureDirSync|ensureDir|mkdir)|"
    r"(?P<op>open))\s*\("
)
_METHOD_RE = re.compile(
    r"\.\s*(?:(?P<w>write_text|write_bytes|touch|symlink_to|hardlink_to)|(?P<d>mkdir)|"
    r"(?P<op>open))\s*\("
)
_PY_EXEC_RE = re.compile(
    r"\b(?:os\.(?:system|popen)|subprocess\.(?:run|call|check_call|check_output|Popen|"
    r"getoutput|getstatusoutput))\s*\("
)
_JS_EXEC_RE = re.compile(
    r"(?<![\w$])(?:execSync|exec|spawnSync|spawn|execFileSync|execFile|execaSync|execa)\s*\("
)
_WRITE_MODE_RE = re.compile(r"""^\s*(?:mode\s*=\s*)?[rbtfu]*["'][^"'\n]*[wax+]""")
_SH_WRAPPERS = frozenset({"sudo", "doas", "command", "exec", "env", "nohup", "time"})
# Reserved words that may precede a command on the same line (`do cp ...`, `! cp ...`).
_SH_KEYWORDS = frozenset({"if", "then", "else", "elif", "while", "until", "do", "!", "{",
                          "fi", "done"})
# Options whose VALUE is the next word (never a file operand). `-t` is the destination
# for cp/mv/ln/install and is read from here.
_TGT = frozenset({"-t", "--target-directory", "-S", "--suffix"})
_OPT_VALUES = {
    "cp": _TGT, "mv": _TGT, "ln": _TGT,
    "install": _TGT | {"-m", "--mode", "-o", "--owner", "-g", "--group", "-M"},
    "rsync": frozenset({"-e", "--rsh", "--exclude", "--include", "--filter", "-f",
                        "--exclude-from", "--include-from", "--files-from", "--link-dest",
                        "--compare-dest", "--copy-dest", "--backup-dir", "--suffix",
                        "--chmod", "--chown", "-T", "--temp-dir", "--partial-dir",
                        "--log-file", "--password-file"}),
    "touch": frozenset({"-r", "--reference", "-d", "--date", "-t"}),
    "sed": frozenset({"-e", "--expression", "-f", "--file", "-l", "--line-length"}),
    "mkdir": frozenset({"-m", "--mode", "--context"}),
}
_SH_LAST = frozenset({"cp", "mv", "install", "ln", "rsync"})
_SH_ALL = frozenset({"tee", "touch", "mkdir"})
_HEREDOC_RE = re.compile(r"""<<-?[ \t]*(["']?)([A-Za-z_]\w*)\1""")
_HEREDOC_OP_RE = re.compile(r"(?<!<)<<(?!<)")
# A `/` that starts a JS regex literal follows one of these (or a keyword below).
_JS_REGEX_PREV = frozenset("(,=:[!&|?{};+-*%<>~^")
_JS_REGEX_KW_RE = re.compile(r"(?:return|typeof|case|in|of|void|delete|throw|new|yield|await)$")
_SH_ASSIGN_WORD_RE = re.compile(r"[A-Za-z_]\w*=")
SPAN = 600  # chars read for one statement / call argument list


def mask_code(body: str, lang: str) -> tuple[str, str, list[tuple[int, int, int]]]:
    """(masked, code, heredocs). *masked*: comments, Python docstrings and shell heredoc
    bodies blanked (same length, newlines kept). *code*: masked plus every string
    literal's contents blanked, except f-string `{...}` / template `${...}` holes - the
    view identifier references and call names are read from. *heredocs*: (line-start of
    the `<<` line, body start, body end) for each shell heredoc."""
    out = list(body)
    code = list(body)
    n = len(body)
    heredocs: list[tuple[int, int, int]] = []

    def blank(a: int, b: int, *views) -> None:
        for v in views:
            for k in range(a, b):
                if v[k] != "\n":
                    v[k] = " "

    no_closer: set[str] = set()  # quote types proven never to close from here on
    i = 0
    while i < n:
        c = body[i]
        if lang == "py" and c == "#" or lang == "sh" and c == "#" and (
            i == 0 or body[i - 1] in " \t\n;&|("
        ):
            j = body.find("\n", i)
            j = n if j == -1 else j
            blank(i, j, out, code)
            i = j
            continue
        if lang == "js" and body.startswith("//", i):
            j = body.find("\n", i)
            j = n if j == -1 else j
            blank(i, j, out, code)
            i = j
            continue
        if lang == "js" and body.startswith("/*", i):
            j = body.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(i, j, out, code)
            i = j
            continue
        if lang == "sh" and c == "\n":
            # heredoc: the line just ended opens one or more bodies
            ls = body.rfind("\n", 0, i) + 1
            hm = None
            line_code = "".join(code[ls:i])
            line_out = "".join(out[ls:i])
            for cm in _HEREDOC_OP_RE.finditer(line_code):
                # `<<` outside quotes (blanked in the code view), not `<<<`, not a
                # shift inside `(( ))` / `$(( ))`, with a word delimiter after it
                if "((" in line_code[:cm.start()] and "))" in line_code[cm.end():]:
                    continue
                dm = _HEREDOC_RE.match(line_out, cm.start())
                if dm:
                    hm = dm
            if hm is not None:
                delim, strip = hm.group(2), body[ls + hm.start() + 2: ls + hm.start() + 3] == "-"
                k = i + 1
                while k < n:
                    e = body.find("\n", k)
                    e = n if e == -1 else e
                    line = body[k:e]
                    if (line.strip() if strip else line) == delim:
                        heredocs.append((ls, i + 1, k))
                        blank(i + 1, k, out, code)
                        i = e
                        break
                    k = e + 1
                else:
                    heredocs.append((ls, i + 1, n))
                    blank(i + 1, n, out, code)
                    i = n
                continue
            i += 1
            continue
        if c in no_closer:
            i += 1  # an earlier quote of this type already ran to the end unclosed
            continue
        if lang == "js" and c == "/":
            k = i - 1
            while k >= 0 and code[k] in " \t":
                k -= 1
            prev = code[k] if k >= 0 else "\n"
            if prev in _JS_REGEX_PREV or prev == "\n" or _JS_REGEX_KW_RE.search(
                    "".join(code[max(0, k - 9):k + 1])):
                # a regex literal: skip it whole so a quote or `/*` inside never opens a
                # string or comment. Unsure (no closing `/` on the line) -> division.
                j, cls = i + 1, False
                while j < n and body[j] != "\n":
                    ch = body[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "[":
                        cls = True
                    elif ch == "]":
                        cls = False
                    elif ch == "/" and not cls:
                        break
                    j += 1
                if j < n and body[j] == "/":
                    i = j + 1
                    continue
            i += 1
            continue
        if c in "\"'`" and not (lang == "py" and c == "`"):
            triple = lang == "py" and body.startswith(c * 3, i)
            q = c * 3 if triple else c
            pre = i
            while pre > 0 and body[pre - 1] in "rRbBuUfF" and i - pre < 2:
                pre -= 1
            fmt = lang == "py" and "f" in body[pre:i].lower() or lang == "js" and c == "`"
            j = i + len(q)
            holes: list[tuple[int, int]] = []
            while j < n and not body.startswith(q, j):
                if body[j] == "\\" and lang != "sh" or (lang == "sh" and c == '"' and body[j] == "\\"):
                    j += 2
                    continue
                if body[j] == "\n" and not triple and not (lang == "js" and c == "`") and lang != "sh":
                    break  # unterminated one-line string - stop at the line end
                if fmt and (body.startswith("${", j) or (lang == "py" and body[j] == "{")):
                    if lang == "py" and body.startswith("{{", j):
                        j += 2
                        continue
                    hs = j + (2 if body[j] == "$" else 1)
                    depth, k = 1, hs
                    while k < n and depth and k - hs < SPAN:
                        depth += {"{": 1, "}": -1}.get(body[k], 0)
                        k += 1
                    holes.append((hs, k - 1))
                    j = k
                    continue
                j += 1
            if j >= n and lang == "sh":
                no_closer.add(q)  # none closes later either: no rescan per later quote
                i += 1  # never closed: a literal quote character, keep masking after it
                continue
            end = min(n, j + len(q))
            inner_s, inner_e = i + len(q), min(n, j)
            docstring = False
            if triple:
                ls = body.rfind("\n", 0, i) + 1
                if not body[ls:pre].strip():
                    prev = "".join(code[:ls]).rstrip()
                    docstring = not prev or prev[-1] not in "(,[={+:" or prev.endswith(":")
            if docstring:
                blank(i, end, out, code)
            else:
                blank(inner_s, inner_e, code)
                for hs, he in holes:
                    code[hs:he] = body[hs:he]
            i = end
            continue
        i += 1
    return "".join(out), "".join(code), heredocs


_BRACKET_RE = re.compile(r"[()\[\]{},]")


def bracket_table(code: str) -> dict[int, tuple[int, list[int]]]:
    """One linear pass over the string-blanked *code* view: every opening bracket ->
    (its closing position, the commas at its own depth). An unclosed bracket runs to
    the end of the text."""
    pairs: dict[int, tuple[int, list[int]]] = {}
    stack: list[tuple[int, list[int]]] = []
    for m in _BRACKET_RE.finditer(code):
        c = m.group(0)
        if c == ",":
            if stack:
                stack[-1][1].append(m.start())
        elif c in "([{":
            stack.append((m.start(), []))
        elif stack:
            o, commas = stack.pop()
            pairs[o] = (m.start(), commas)
    for o, commas in stack:
        pairs[o] = (len(code), commas)
    return pairs


def call_args(text: str, pairs, open_idx: int) -> list[tuple[int, int]]:
    """Top-level argument spans of the call/list whose opener is at *open_idx*."""
    if open_idx not in pairs:
        return []
    close, commas = pairs[open_idx]
    bounds = [open_idx, *commas, close]
    return [(bounds[k] + 1, bounds[k + 1]) for k in range(len(bounds) - 1)
            if text[bounds[k] + 1:bounds[k + 1]].strip()]


def stmt_end(text: str, start: int) -> int:
    """End of the statement starting at *start*: a newline or `;` at bracket depth 0
    (strings skipped), bounded by SPAN."""
    depth, i = 0, start
    end = min(len(text), start + SPAN)
    while i < end:
        c = text[i]
        if c in "\"'`":
            j = i + 1
            while j < end and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return i
        elif depth <= 0 and (c == "\n" and text[i - 1:i] != "\\" or c == ";"):
            return i
        i += 1
    return i


def unquote(word: str) -> str:
    return word.strip().strip("\"'`")


def sh_commands(text: str, lo: int, hi: int):
    """Shell commands in text[lo:hi] at command position: a list of (words, redirects,
    heredoc_cmd) where words are (start, end) spans and redirects the spans of `>`
    targets.

    Never gives up on the whole text: one odd line must not hide every write after it.
    A backslash escapes the next character outside single quotes; a quote or `$(`/`${`
    still open at the end of the text is treated as ending at its own line, and parsing
    resumes on the next line (a quote that closes on a later line is a real multi-line
    word, as the shell itself reads it)."""
    cmds = []
    words: list[tuple[int, int]] = []
    redirs: list[tuple[int, int]] = []
    heredoc = False
    want_redirect = False
    skip_next = False
    unclosed = False  # a quote/substitution was proven never to close: words end at lines
    test = False  # inside `[[ ]]`, `[ ]` or `test`: `<`/`>` compare
    i = lo

    def flush():
        nonlocal words, redirs, heredoc, test
        if words or redirs:
            cmds.append((words, redirs, heredoc))
        words, redirs, heredoc, test = [], [], False, False

    while i < hi:
        c = text[i]
        if c in " \t\r":
            i += 1
            continue
        if c == "\\" and text[i + 1:i + 2] == "\n":
            i += 2
            continue
        if c == "#" and (i == lo or text[i - 1] in " \t\n;&|("):
            nl = text.find("\n", i, hi)
            i = hi if nl == -1 else nl
            continue
        if text.startswith("((", i) and all(text[a:b] in _SH_KEYWORDS for a, b in words):
            close = text.find("))", i + 2, hi)
            i = hi if close == -1 else close + 2  # arithmetic: `<`/`>` are operators
            continue
        if c in "\n;()}" or (c == "{" and text[i + 1:i + 2] in (" ", "\t", "\n", "")) or \
                text.startswith("&&", i) or text.startswith("||", i):
            flush()
            i += 2 if text.startswith(("&&", "||"), i) else 1
            continue
        if c == "|":
            flush()
            i += 2 if text.startswith("|&", i) else 1
            continue
        if c == "&" and not text.startswith("&>", i):
            flush()
            i += 1
            continue
        if c in "<>" or c == "&" or (c.isdigit() and text[i + 1:i + 2] in ("<", ">")):
            k = i
            while k < hi and text[k].isdigit():
                k += 1
            op_s = k
            while k < hi and text[k] in "<>&|-":
                k += 1
            op = text[op_s:k]
            if test:
                i = k  # inside [[ ]] / [ ] / test: a comparison, not a redirect
                continue
            if op.startswith("<<<"):
                skip_next = True  # a here-string: the word is data, not a file
            elif op.startswith("<<"):
                heredoc = True
                skip_next = True
            elif ">&" in op and (text[k:k + 1].isdigit() or text[k:k + 1] == "-"):
                k += 1  # fd dup, not a file
            elif ">" in op:
                want_redirect = True
            else:
                skip_next = True  # `<` input file
            i = k
            continue
        # a word
        j, quote, depth = i, None, 0
        while j < hi:
            ch = text[j]
            if unclosed and ch == "\n":
                break  # one linear pass: no rescan to the end of the text per word
            if ch == "\\" and quote != "'":
                j += 2  # an escaped character, inside double quotes or outside quotes
                continue
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "\"'`":
                quote = ch
            elif text.startswith("$(", j) or text.startswith("${", j):
                depth += 1
                j += 2
                continue
            elif ch in ")}" and depth:
                depth -= 1
            elif depth == 0 and (ch in " \t\r\n;&|<>()"):
                break
            j += 1
        if (quote or depth) and not unclosed:
            # Open to the end of the text: the shell would reject it, so read the word
            # as ending at its own line and keep parsing what follows. Proven once -
            # every later word ends at its own line without rescanning.
            unclosed = True
            nl = text.find("\n", i, hi)
            j = hi if nl == -1 else nl
        j = min(j, hi)
        if want_redirect:
            redirs.append((i, j))
            want_redirect = False
        elif skip_next:
            skip_next = False
        elif not words and _SH_ASSIGN_WORD_RE.match(text, i, j):
            pass  # VAR=value prefix assignment
        else:
            wt = text[i:j]
            if wt in ("[[", "[", "test") and all(
                    text[a:b] in _SH_KEYWORDS for a, b in words):
                test = True
            elif wt in ("]]", "]"):
                test = False
            words.append((i, j))
        i = j
    flush()
    return cmds


def _split_opts(text: str, cmd: str, args):
    """(plain words, {option: value span}) - an option that takes a value consumes it,
    so `touch -r REF`, `sed -e SCRIPT`, `rsync --exclude PAT` never read the value as a
    file operand."""
    takes = _OPT_VALUES.get(cmd, frozenset())
    plain, vals = [], {}
    k = 0
    while k < len(args):
        a = args[k]
        t = unquote(text[a[0]:a[1]])
        if t.startswith("-") and t != "-":
            if "=" in t and t.startswith("--"):
                name = t.split("=", 1)[0]
                vals[name] = (a[0] + text[a[0]:a[1]].index("=") + 1, a[1])
            elif t in takes and k + 1 < len(args):
                vals[t] = args[k + 1]
                k += 1
            else:
                vals.setdefault(t, None)
        else:
            plain.append(a)
        k += 1
    return plain, vals


def _cmd_dests(text: str, words: list[tuple[int, int]]):
    """(dest spans, is_dir, data spans) of one command's argv (spans into *text*)."""
    k = 0
    while k < len(words):
        w = unquote(text[words[k][0]:words[k][1]]).rsplit("/", 1)[-1]
        if w in _SH_KEYWORDS:
            k += 1
            continue
        if w in _SH_WRAPPERS:
            k += 1
            while k < len(words) and text[words[k][0]:words[k][1]].startswith("-"):
                k += 1
            continue
        break
    if k >= len(words):
        return [], False, []
    cmd = unquote(text[words[k][0]:words[k][1]]).rsplit("/", 1)[-1]
    plain, vals = _split_opts(text, cmd, words[k + 1:])
    if cmd in _SH_LAST:
        for name in ("-t", "--target-directory"):
            if vals.get(name):
                return [vals[name]], False, plain
        if cmd == "install" and ("-d" in vals or "--directory" in vals):
            return plain, True, []
        if len(plain) >= 2:
            return [plain[-1]], False, plain[:-1]
        return [], False, []
    if cmd in _SH_ALL:
        return plain, cmd == "mkdir", []
    if cmd == "sed" and any(o.startswith("--in-place") or (o.startswith("-i") or (
            not o.startswith("--") and "i" in o[1:])) for o in vals):
        scripted = any(vals.get(o) for o in ("-e", "-f", "--expression", "--file"))
        return (plain if scripted else plain[1:]), False, []
    if cmd == "dd":
        return [(a[0] + 3, a[1]) for a in plain if text[a[0]:a[1]].startswith("of=")], False, []
    return [], False, []


def _sh_dests(text: str, lo: int, hi: int, heredocs, out: list) -> None:
    """Shell destinations in text[lo:hi]; heredoc bodies become the data of a
    redirect on the same command."""
    cmds = sh_commands(text, lo, hi)
    if not cmds:
        return
    for words, redirs, has_heredoc in cmds:
        data: list[tuple[int, int]] = []
        if has_heredoc and redirs:
            ls = text.rfind("\n", 0, redirs[0][0]) + 1
            data = [(s, e) for hl, s, e in heredocs if hl == ls]
        for r in redirs:
            out.append((r[0], r[1], False, data, True))
        dests, is_dir, dsrc = _cmd_dests(text, words)
        for d in dests:
            out.append((d[0], d[1], is_dir, dsrc, True))


def _string_inner(text: str, s: int, e: int) -> tuple[int, int] | None:
    """Inner span of a single string literal argument (prefix letters allowed)."""
    while s < e and text[s] in " \t\n":
        s += 1
    while e > s and text[e - 1] in " \t\n":
        e -= 1
    k = s
    while k < e and text[k] in "rRbBuUfF" and k - s < 2:
        k += 1
    if k < e and text[k] in "\"'`" and text[e - 1] == text[k] and e - 1 > k:
        q = 3 if text.startswith(text[k] * 3, k) and e - k >= 6 else 1
        return k + q, e - q
    return None


def _argv_dests(masked: str, elems: list[tuple[int, int]], out: list) -> None:
    """An argv list handed to subprocess/spawn: `sh -c "<cmd>"` is parsed as shell; else
    the elements are the command's words."""
    lits = [_string_inner(masked, s, e) for s, e in elems]
    for idx, a in enumerate(elems):
        if lits[idx] and masked[lits[idx][0]:lits[idx][1]] == "-c" and idx + 1 < len(elems):
            inner = lits[idx + 1]
            if inner:
                _sh_dests(masked, inner[0], inner[1], (), out)
            return
    words = [(lits[i] if lits[i] else elems[i]) for i in range(len(elems))]
    dests, is_dir, dsrc = _cmd_dests(masked, words)
    for d in dests:
        out.append((d[0], d[1], is_dir, dsrc, d in lits))


def _with_handle_data(masked: str, code: str, pairs, call_end: int) -> list[tuple[int, int]]:
    """`with open(p, 'w') as f:` -> the data of `f.write(X)` / `json.dump(X, f)` in the
    following block (bounded)."""
    m = re.match(r"\s*as\s+([A-Za-z_]\w*)", code[call_end:call_end + 80])
    if not m:
        return []
    h = re.escape(m.group(1))
    lo = call_end + m.end()
    hi = min(len(code), lo + 2000)
    data: list[tuple[int, int]] = []
    for wm in re.finditer(rf"(?<![\w.]){h}\s*\.\s*write\s*\(|\bdump\s*\(", code[lo:hi]):
        op = lo + wm.end() - 1
        args = call_args(masked, pairs, op)
        if wm.group(0).startswith("dump"):
            if len(args) > 1 and re.fullmatch(rf"\s*{h}\s*", masked[args[1][0]:args[1][1]]):
                data.append(args[0])
        elif args:
            data.append(args[0])
    return data


def dest_spans(masked: str, code: str, lang: str, heredocs) -> list:
    """(start, end, is_dir_create, data_spans) of every write destination in a code file
    (see the module docstring for what counts)."""
    out: list = []
    if lang == "sh":
        _sh_dests(masked, 0, len(masked), heredocs, out)
        return out
    pairs = bracket_table(code)
    for cm in _CALL_RE.finditer(code):
        if cm.group("op") and code[cm.start() - 1:cm.start()] == ".":
            continue  # `.open(` is a method - handled below
        args = call_args(masked, pairs, cm.end() - 1)
        if not args:
            continue
        if cm.group("w0"):
            out.append((*args[0], False, args[1:2], False))
        elif cm.group("d0"):
            out.append((*args[0], True, [], False))
        elif cm.group("w1"):
            if len(args) > 1:
                out.append((*args[1], False, args[:1], False))
        elif len(args) > 1 and _WRITE_MODE_RE.match(masked[args[1][0]:args[1][1]]):
            close = args[-1][1]
            data: list[tuple[int, int]] = []
            # open(p, 'w').write(X)
            wm = re.match(r"\)\s*\.\s*write\s*\(", code[close:close + 40])
            if wm:
                data = call_args(masked, pairs, close + wm.end() - 1)[:1]
            # json.dump(X, open(p, 'w'))
            if not data:
                k = code.rfind("dump", max(0, cm.start() - SPAN), cm.start())
                po = code.find("(", k, cm.start()) if k != -1 else -1
                if po != -1 and not code[k + 4:po].strip():
                    dargs = call_args(masked, pairs, po)
                    if len(dargs) > 1 and dargs[1][0] <= cm.start() < dargs[1][1]:
                        data = dargs[:1]
            if not data:
                data = _with_handle_data(masked, code, pairs, close + 1)
            out.append((*args[0], False, data, False))
    for mm in _METHOD_RE.finditer(code):
        args = call_args(masked, pairs, mm.end() - 1)
        if mm.group("op"):
            if not args or not _WRITE_MODE_RE.match(masked[args[0][0]:args[0][1]]):
                continue
        i = mm.start()
        while i > 0 and code[i - 1] in " \t":
            i -= 1
        end = i
        while i > 0:
            c = code[i - 1]
            if c == ")":
                depth, i = 1, i - 1
                while i > 0 and depth and end - i < SPAN:
                    i -= 1
                    depth += {")": 1, "(": -1}.get(code[i], 0)
            elif c.isalnum() or c in "_.$":
                i -= 1
            else:
                break
        data = args[:1] if mm.group("w") in ("write_text", "write_bytes") else []
        out.append((i, end, bool(mm.group("d")), data, False))
    exec_rx = _PY_EXEC_RE if lang == "py" else _JS_EXEC_RE
    for em in exec_rx.finditer(code):
        args = call_args(masked, pairs, em.end() - 1)
        if not args:
            continue
        a0 = args[0]
        lead = masked[a0[0]:a0[1]].lstrip()
        if lead.startswith("["):
            op = a0[0] + masked[a0[0]:a0[1]].index("[")
            _argv_dests(masked, call_args(masked, pairs, op), out)
            continue
        inner = _string_inner(masked, *a0)
        if inner is None:
            continue
        if lang == "js" and len(args) > 1 and masked[args[1][0]:args[1][1]].lstrip().startswith("["):
            op = args[1][0] + masked[args[1][0]:args[1][1]].index("[")
            _argv_dests(masked, [a0] + call_args(masked, pairs, op), out)
            continue
        _sh_dests(masked, inner[0], inner[1], (), out)
    return out
