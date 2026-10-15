#!/usr/bin/env python3
"""Create a single-file offline HTML app, as in the MPLPB browser distribution."""
from pathlib import Path
root = Path(__file__).resolve().parent.parent
page = (root/'index.html').read_text(encoding='utf-8')
css=(root/'style.css').read_text(encoding='utf-8')
core=(root/'analyzer.js').read_text(encoding='utf-8')
app=(root/'app.js').read_text(encoding='utf-8')
assert '</style' not in css.lower()
assert '</script' not in core.lower()+app.lower()
page=page.replace('<link rel="stylesheet" href="style.css">','<style>'+css+'</style>')
page=page.replace('<script src="analyzer.js"></script>','<script>'+core+'</script>')
page=page.replace('<script src="app.js"></script>','<script>'+app+'</script>')
assert 'src="app.js"' not in page and 'href="style.css"' not in page
path=root/'Ghidra_Browser_Lab.html'
path.write_text(page,encoding='utf-8')
print(f'Built {path.name} ({path.stat().st_size:,} bytes)')
