"""Check a built Pages site's local links and anchors using only the standard library."""

import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links = []
        self.ids = set()
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        for name in ("href", "src"):
            if name in attrs:
                self.links.append(attrs[name])


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
parser.add_argument("--base-path", default="/redhound/")
args = parser.parse_args()
root = args.directory.resolve()
base = "/" + args.base_path.strip("/") + "/"
pages = {path: Page(path.read_text()) for path in root.rglob("*.html")}
if not (root / "index.html").is_file() or not (root / "guide/index.html").is_file():
    parser.error("missing landing page or User Guide")
errors = []
checked = 0
for path, page in pages.items():
    page_url = base + path.relative_to(root).as_posix()
    for link in page.links:
        if urlsplit(link).scheme or link.startswith("//"):
            continue
        url = urlsplit(urljoin(page_url, link))
        local_path = unquote(url.path)
        if not local_path.startswith(base):
            errors.append(f"{path.relative_to(root)}: link escapes base path: {link}")
            continue
        target = (root / local_path[len(base):]).resolve()
        if not target.is_relative_to(root):
            errors.append(f"{path.relative_to(root)}: link escapes site: {link}")
            continue
        if target.is_dir():
            target /= "index.html"
        if not target.is_file():
            errors.append(f"{path.relative_to(root)}: missing target: {link}")
        elif url.fragment and target in pages and unquote(url.fragment) not in pages[target].ids:
            errors.append(f"{path.relative_to(root)}: missing anchor: {link}")
        checked += 1
if errors:
    raise SystemExit("\n".join(errors))
print(f"Checked {checked} internal links and anchors across {len(pages)} pages.")
