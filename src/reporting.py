import csv
import html
import json
import os
from typing import Dict, List


def _member_to_cluster(clusters) -> Dict[str, str]:
    m = {}
    for c in clusters:
        for member in c.members:
            m[member] = c.cluster_id
    return m


def _atomic_write(out_path: str, text: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    tmp = out_path + ".tmp"

    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, out_path)


def write_json_report(result, matches, clusters, out_path: str) -> None:
    sha_cluster = _member_to_cluster(clusters)
    doc = {
        "samples": {
            path: dict(feats.to_dict(), cluster_id=sha_cluster.get(
                feats.sha256, ""), path=path)
            for path, feats in result.features.items()
        },
        "matches": matches,
        "clusters": [{"cluster_id": c.cluster_id,
                      "members": c.members} for c in clusters],
        "errors": result.errors,
    }

    _atomic_write(out_path, json.dumps(doc, indent=2))


def write_csv_report(result, clusters, out_path: str, matches=None) -> None:
    sha_cluster = _member_to_cluster(clusters)
    match_counts = {}

    for m in (matches or []):
        for side in ("a", "b"):
            match_counts[m[side]] = match_counts.get(m[side], 0) + 1

    with open(out_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["path", "sha256", "format", "architecture", "size",
                    "cluster_id", "match_count", "error"])

        for path, f in sorted(result.features.items()):
            w.writerow([path, f.sha256, f.format, f.architecture, f.size,
                        sha_cluster.get(f.sha256, ""),
                        match_counts.get(path, 0), ""])

        for path, err in sorted(result.errors.items()):
            w.writerow([path, "", "", "", "", "", 0, err])


_HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Binartia Triage Report</title>
<style>
 body {{ font-family: monospace; margin: 2em; }}
 .bar {{ background: #4caf50; height: 12px; display: inline-block;
        vertical-align: middle; }}
 table {{ border-collapse: collapse; margin: 1em 0; }}
 td, th {{ border: 1px solid #999; padding: 2px 6px; font-size: 12px; }}
 h2 {{ margin-top: 1.5em; }}
</style></head><body>
<h1>Binartia Triage Report</h1>
{body}
</body></html>
"""


def write_html_report(result, matches, clusters, out_path: str,
                      images: Dict[str, str] = None) -> None:
    images = images or {}
    # members are sha256 values; resolve to paths for display where possible
    sha_to_path = {f.sha256: p for p, f in result.features.items()}
    parts = ['<h2>Clusters (by size)</h2>']
    for c in clusters:
        parts.append('<h2>{0} &mdash; {1} sample(s)</h2>'.format(
            html.escape(c.cluster_id), len(c.members)))
        rows = []
        for m in c.members:
            img = ''
            if m in images:
                img = '<img src="{0}" width="200">'.format(
                    html.escape(os.path.basename(images[m]), quote=True))
            label = sha_to_path.get(m, m)
            rows.append('<tr><td>{0}</td><td>{1}</td></tr>'.format(
                html.escape(label), img))
        if rows:
            parts.append('<table><tr><th>sample</th><th>viz</th></tr>'
                         + ''.join(rows) + '</table>')

    parts.append('<h2>Top matches</h2><table><tr><th>A</th><th>B</th>'
                 '<th>score</th><th></th></tr>')
    for m in matches[:50]:
        bar = ('<span class="bar" style="width:{:.0f}px"></span>'
               .format(m['composite']))
        parts.append('<tr><td>{}</td><td>{}</td><td>{:.1f}</td><td>{}</td>'
                     '</tr>'.format(html.escape(m['a']), html.escape(m['b']),
                                    m['composite'], bar))
    parts.append('</table>')

    if result.errors:
        parts.append('<h2>Errors</h2><ul>')
        for path, err in result.errors.items():
            parts.append('<li>{}: {}</li>'.format(
                html.escape(path), html.escape(err)))
        parts.append('</ul>')

    _atomic_write(out_path, _HTML_TEMPLATE.format(body='\n'.join(parts)))
