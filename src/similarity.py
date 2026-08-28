from typing import Optional, Sequence
import math


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0

    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def cosine(u: Sequence[float], v: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(u, v))
    nu = math.sqrt(sum(x * x for x in u))
    nv = math.sqrt(sum(y * y for y in v))

    if nu == 0.0 or nv == 0.0:
        return 0.0

    return dot / (nu * nv)


def _exec_section_names(f) -> set:
    return {s.name for s in f.sections if s.executable}


def section_overlap(fa, fb) -> float:
    return jaccard(_exec_section_names(fa), _exec_section_names(fb))


def imports_jaccard(fa, fb) -> float:
    return jaccard(set(fa.imports), set(fb.imports))


def histogram_cosine(fa, fb) -> float:
    return cosine(fa.histogram, fb.histogram)


try:
    import tlsh as _tlsh
    TLSH_LIB = True
except ImportError:
    _tlsh = None
    TLSH_LIB = False

DEFAULT_WEIGHTS = {
    "tlsh_file": 40,
    "tlsh_section": 20,
    "ssdeep": 15,
    "imports_jaccard": 15,
    "histogram_cosine": 5,
    "section_overlap": 5,
}

_TLSH_SIMILAR_SPAN = 500.0   # distance ~0 -> 100, >=500 -> 0 (heuristic)


def _dist_to_sim(dist: float) -> float:
    return max(0.0, 1.0 - dist / _TLSH_SIMILAR_SPAN) * 100.0


def _tlsh_dist(h1: str, h2: str) -> Optional[float]:
    if not TLSH_LIB:
        return None
    try:
        return float(_tlsh.diffxlen(h1, h2))
    except Exception:
        return None


def _tlsh_file_similarity(h1, h2) -> Optional[float]:
    if not h1 or not h2:
        return None
    d = _tlsh_dist(h1, h2)
    return None if d is None else _dist_to_sim(d)


def _tlsh_section_similarity(fa, fb) -> Optional[float]:
    ha = [s for s in fa.sections if getattr(s, "tlsh", None)]
    hb = [s for s in fb.sections if getattr(s, "tlsh", None)]
    if not ha or not hb:
        return None

    best = None
    for x in ha:
        for y in hb:
            d = _tlsh_dist(x.tlsh, y.tlsh)
            if d is not None:
                sim = _dist_to_sim(d)
                best = sim if best is None else max(best, sim)
    return best


def _ssdeep_similarity(h1, h2) -> Optional[float]:
    from feature_extractor import SSDEEP_AVAILABLE, _ssdeep
    if not (SSDEEP_AVAILABLE and h1 and h2):
        return None
    try:
        c = _ssdeep.compare(h1, h2)
        return None if c is None or c < 0 else float(c)
    except Exception:
        return None


class PairScore:
    def __init__(self, composite: float, signals: dict):
        self.composite = composite
        self.signals = signals

    def __repr__(self):
        return "PairScore(composite={:.1f}, signals={})".format(
            self.composite, self.signals)


class SimilarityEngine:
    def __init__(self, weights: Optional[dict] = None):
        self.weights = dict(DEFAULT_WEIGHTS)
        if weights:
            unknown = set(weights) - set(self.weights)
            if unknown:
                raise ValueError(
                    f"unknown signal names: {sorted(unknown)}")

            bad = {k: v for k, v in weights.items()
                   if not isinstance(v, (int, float)) or v <= 0}
            if bad:
                raise ValueError(
                    f"signal weights must be positive numbers: {bad}")
            self.weights.update(weights)

    def compare(self, fa, fb) -> PairScore:
        raw = {
            "tlsh_file": _tlsh_file_similarity(fa.tlsh, fb.tlsh),
            "tlsh_section": _tlsh_section_similarity(fa, fb),
            "ssdeep": _ssdeep_similarity(fa.ssdeep, fb.ssdeep),
            "imports_jaccard": imports_jaccard(fa, fb) * 100.0,
            "histogram_cosine": histogram_cosine(fa, fb) * 100.0,
            "section_overlap": section_overlap(fa, fb) * 100.0,
        }
        available = {k: v for k, v in raw.items() if v is not None}
        if not available:
            return PairScore(0.0, {k: None for k in raw})

        total_w = sum(self.weights[k] for k in available)
        composite = sum(raw[k] * self.weights[k] for k in available) / total_w
        return PairScore(round(composite, 2), raw)
