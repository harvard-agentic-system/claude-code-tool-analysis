#!/usr/bin/env python3
"""Embed template.html into cc_toolstat.py so the tool stays a single file.

    python3 build.py           # embed
    python3 build.py --check   # verify the embedded copy matches (exit 1 if not)
"""
import re
import sys

MARK = 'HTML_TEMPLATE = r"""'


def main():
    tpl = open("template.html").read()
    if '"""' in tpl:
        sys.exit("template.html contains a triple quote; it cannot be embedded verbatim")
    src = open("cc_toolstat.py").read()
    i = src.index(MARK)
    j = src.index('"""\n', i + len(MARK))
    current = src[i + len(MARK):j]
    if "--check" in sys.argv:
        if current == tpl:
            print("in sync")
            return 0
        print("OUT OF SYNC: run `python3 build.py` after editing template.html", file=sys.stderr)
        return 1
    if current == tpl:
        print("already in sync")
        return 0
    open("cc_toolstat.py", "w").write(src[:i + len(MARK)] + tpl + src[j:])
    print("embedded %d KB of template into cc_toolstat.py" % (len(tpl) // 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())
