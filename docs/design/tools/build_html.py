# Converts the canvas mockups (docs/design/*.dc.html) into standalone pages.
# Usage, from the repository root: python3 docs/design/tools/build_html.py docs/design docs/design/html
import re, pathlib, sys
src = pathlib.Path(sys.argv[1]); out = pathlib.Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
runtime = pathlib.Path(__file__).with_name('runtime.js').read_text()
names = {p.stem.replace('.dc', ''): p for p in src.glob('*.dc.html')}
def page_name(stem): return 'index.html' if stem == 'Main' else stem.lower() + '.html'
for stem, p in sorted(names.items()):
    t = p.read_text()
    title = re.search(r'<title>(.*?)</title>', t, re.S).group(1)
    lang = re.search(r'<html lang="([^"]+)"', t).group(1)
    xdc = re.search(r'<x-dc>(.*)</x-dc>', t, re.S).group(1)
    helmet = re.search(r'<helmet>(.*?)</helmet>', xdc, re.S)
    head_extra = helmet.group(1).strip() if helmet else ''
    markup = (xdc[:helmet.start()] + xdc[helmet.end():]) if helmet else xdc
    logic = re.search(r'<script type="text/x-dc"[^>]*>(.*?)</script>', t, re.S).group(1)
    markup = re.sub(r'<sc-for list="\{\{\s*([^}]+?)\s*\}\}" as="([^"]+)"[^>]*>', r'<template data-for="\1" data-as="\2">', markup)
    markup = markup.replace('</sc-for>', '</template>')
    markup = re.sub(r'<sc-if value="\{\{\s*([^}]+?)\s*\}\}"[^>]*>', r'<template data-if="\1">', markup)
    markup = markup.replace('</sc-if>', '</template>')
    def fix_href(m):
        target = m.group(1)
        return 'href="' + page_name(target) + (m.group(2) or '') + '"'
    markup = re.sub(r'href="([A-Za-z0-9_]+)\.dc\.html(#[^"]*)?"', fix_href, markup)
    assert '<sc-' not in markup and '.dc.html' not in markup, stem
    html = f'''<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
{head_extra}
</head>
<body>
<div id="app"></div>
<template id="page-template">{markup}</template>
<script>
{runtime}
</script>
<script>
{logic.strip()}
mountPrototype(Component);
</script>
</body>
</html>
'''
    (out / page_name(stem)).write_text(html)
    print('wrote', page_name(stem))
