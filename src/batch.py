import hashlib
import json
import logging
import multiprocessing as mp
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BatchResult:
    features: Dict[str, object] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)


def _extract_worker(path: str, max_bytes: int):
    from feature_extractor import FeatureExtractor   # flat import per worker
    return FeatureExtractor(max_bytes=max_bytes).extract(path)


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_cache(cache_dir: str, sha256: str):
    p = os.path.join(cache_dir, sha256 + ".json")

    if not os.path.exists(p):
        return None
    try:
        with open(p) as fh:
            d = json.load(fh)

        from feature_extractor import SampleFeatures
        return SampleFeatures.from_dict(d)
    except Exception:
        return None


def _store_cache(cache_dir: str, features) -> None:
    p = os.path.join(cache_dir, features.sha256 + ".json")
    tmp = p + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(features.to_dict(), fh)
    os.replace(tmp, p)


class BatchRunner:
    def __init__(self, cache_dir: Optional[str] = None,
                 jobs: Optional[int] = None,
                 max_bytes: int = 64 * 1024 * 1024):
        self.cache_dir = cache_dir
        if jobs is not None and jobs < 1:
            raise ValueError(f"jobs must be >= 1, got {jobs}")
        self.jobs = jobs or max(1, mp.cpu_count() - 1)
        self.max_bytes = max_bytes
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    def run(self, paths: List[str]) -> BatchResult:
        result = BatchResult()
        pending = []

        for path in paths:
            if not self.cache_dir:
                pending.append(path)
                continue
            try:
                sha = _file_sha256(path)
            except OSError as e:
                result.errors[path] = f"{type(e).__name__}: {e}"
                continue

            cached = _load_cache(self.cache_dir, sha)
            if cached is not None:
                result.features[path] = cached
            else:
                pending.append(path)

        if pending:
            with mp.get_context("spawn").Pool(self.jobs) as pool:
                async_results = [
                    pool.apply_async(_extract_worker, (p, self.max_bytes))
                    for p in pending]

                for path, ar in zip(pending, async_results):
                    try:
                        feats = ar.get()
                    except Exception as e:
                        result.errors[path] = f"{type(e).__name__}: {e}"
                        continue

                    if self.cache_dir:
                        _store_cache(self.cache_dir, feats)
                    result.features[path] = feats
        return result


def match_all(result: BatchResult, engine=None, threshold: float = 40.0):
    from similarity import SimilarityEngine

    engine = engine or SimilarityEngine()
    paths = sorted(result.features)
    matches = []

    for i in range(len(paths)):
        for j in range(i + 1, len(paths)):
            ps = engine.compare(result.features[paths[i]],
                                result.features[paths[j]])
            if ps.composite >= threshold:
                matches.append({"a": paths[i], "b": paths[j],
                                "composite": ps.composite,
                                "signals": ps.signals})
    matches.sort(key=lambda m: -m["composite"])
    return matches, engine
