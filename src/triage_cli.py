import argparse
import logging
import os
import sys
from typing import List

from batch import BatchRunner, match_all
from clustering import build_clusters
from reporting import (write_json_report, write_csv_report,
                       write_html_report)
from similarity import SimilarityEngine


def _render_representatives(result, clusters, output_dir: str) -> dict:
    images = {}
    try:
        from visualizer import BinaryVisualizer
    except Exception as e:  # pragma: no cover
        print(f"Visualization unavailable ({e}); skipping representatives",
              file=sys.stderr)
        return images
    
    sha_to_path = {f.sha256: p for p, f in result.features.items()}
    viz = BinaryVisualizer()

    for c in clusters:
        rep_sha = c.members[0]
        sample_path = sha_to_path.get(rep_sha)
        if not sample_path:
            continue

        png = os.path.join(output_dir, f"rep_{c.cluster_id}.png")

        try:
            viz.visualize(sample_path, png)
            images[rep_sha] = os.path.abspath(png)
        except Exception as e:
            print(f"Could not render representative for {c.cluster_id} "
                  f"({e}); skipping", file=sys.stderr)
    return images


def _expand_inputs(inputs: List[str]) -> List[str]:
    files = []
    for item in inputs:
        if os.path.isdir(item):
            for root, _, names in os.walk(item):
                files.extend(os.path.join(root, n) for n in names)
        elif os.path.isfile(item):
            files.append(item)
    return sorted(set(files))


def main(argv: List[str] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Binartia triage: similarity clustering over binaries")
    ap.add_argument("inputs", nargs="+",
                    help="Files or directories of samples")
    ap.add_argument("-o", "--output-dir", default="triage_report")
    ap.add_argument("--threshold", type=float, default=40.0)
    ap.add_argument("--weights", default=None,
                    help='JSON object overriding signal weights, '
                         'e.g. \'{"tlsh_file": 60}')
    ap.add_argument("--render-representatives", action="store_true",
                    help="Render a visualization PNG per cluster "
                         "representative into the report directory")
    ap.add_argument("--cache-dir", default=None)
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    ap.add_argument("--strict", action="store_true",
                    help="Fail if any sample could not be fully extracted")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO)

    files = _expand_inputs(args.inputs)
    if not files:
        print("Error: no input files found", file=sys.stderr)
        return 1

    try:
        weights = None
        if args.weights:
            import json as _json
            weights = _json.loads(args.weights)

        engine = (SimilarityEngine(weights=weights)
                  if weights is not None else None)
        runner = BatchRunner(cache_dir=args.cache_dir, jobs=args.jobs,
                             max_bytes=args.max_bytes)
        result = runner.run(files)
        matches, _ = match_all(result, engine=engine,
                               threshold=args.threshold)
        path_to_sha = {p: f.sha256 for p, f in result.features.items()}
        clusters = build_clusters(
            sorted(path_to_sha.values()),
            [(path_to_sha[m["a"]], path_to_sha[m["b"]]) for m in matches])

        os.makedirs(args.output_dir, exist_ok=True)

        images = {}
        if args.render_representatives:
            images = _render_representatives(result, clusters,
                                             args.output_dir)

        write_json_report(result, matches, clusters,
                          os.path.join(args.output_dir, "report.json"))
        write_csv_report(result, clusters,
                         os.path.join(args.output_dir, "samples.csv"),
                         matches=matches)
        write_html_report(result, matches, clusters,
                          os.path.join(args.output_dir, "report.html"),
                          images=images)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Triage complete: {len(result.features)} samples, "
          f"{len(matches)} matches, {len(clusters)} clusters "
          f"(errors: {len(result.errors)})")

    print(f"Report written to {args.output_dir}/")

    if args.strict and result.errors:
        print(f"Strict mode: {len(result.errors)} extraction error(s)",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
