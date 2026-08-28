import dataclasses
import hashlib
import logging
import os
import warnings
import numpy as np
from binary_parser import BinaryParser
from dataclasses import dataclass, field
from typing import List, Optional


logger = logging.getLogger(__name__)

try:
    import tlsh as _tlsh
    TLSH_AVAILABLE = True
except ImportError:
    _tlsh = None
    TLSH_AVAILABLE = False

try:
    import ssdeep as _ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    _ssdeep = None
    SSDEEP_AVAILABLE = False


class TriageDegradationWarning(UserWarning):
    """emitted when an optional triage dependency is missing."""


_warned_missing = set()


def _warn_once(kind: str, detail: str):
    if kind in _warned_missing:
        return
    _warned_missing.add(kind)
    warnings.warn(detail, TriageDegradationWarning, stacklevel=3)


_DEFAULT_MAX_BYTES = 64 * 1024 * 1024


@dataclass
class SectionInfo:
    name: str
    size: int
    entropy: float
    executable: bool
    tlsh: Optional[str] = None


@dataclass
class SampleFeatures:
    sha256: str
    md5: str
    size: int
    format: str
    architecture: str
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    histogram: List[int] = field(default_factory=list)
    tlsh: Optional[str] = None
    ssdeep: Optional[str] = None

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SampleFeatures":
        valid = {f.name for f in dataclasses.fields(cls)}
        d = {k: v for k, v in d.items() if k in valid}

        section_fields = {f.name for f in dataclasses.fields(SectionInfo)}
        sections = []

        for s in d.get("sections", []):
            if isinstance(s, dict):
                s = {k: v for k, v in s.items() if k in section_fields}
                sections.append(SectionInfo(**s))

        d["sections"] = sections
        return cls(**d)


def _read_file(path: str, max_bytes: int) -> bytes:
    parser_probe = BinaryParser(path, max_bytes=max_bytes)  # enforces size gate
    del parser_probe

    with open(path, "rb") as f:
        return f.read()


_ELF_EXEC = 0x4
_PE_EXEC = 0x20000000


def _normalized_entropy(blob: bytes) -> float:
    if not blob:
        return 0.0

    counts = np.bincount(np.frombuffer(blob, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(blob)

    ent = float(-np.sum(p * np.log2(p)))
    return min(1.0, ent / 8.0)


class FeatureExtractor:
    def __init__(self, max_bytes: int = _DEFAULT_MAX_BYTES):
        self.max_bytes = max_bytes

    def extract(self, path: str) -> SampleFeatures:
        raw = _read_file(path, self.max_bytes)
        parser = self._parser_for(path)
        fmt = parser.binary_type if parser is not None else "RAW"
        arch = ""
        sections, imports = [], []

        if parser is not None and fmt != "RAW":
            try:
                meta = parser.get_metadata()
                arch = str(meta.get("architecture", ""))
                sections = self._extract_sections(parser)
                imports = self._extract_imports(parser)
            except Exception as e:
                warnings.warn(
                    f"Structured extraction failed for {path} ({e}); "
                    f"continuing with raw-byte features.",
                    TriageDegradationWarning, stacklevel=2)
                sections, imports = [], []

        hist = [0] * 256
        for b in raw:
            hist[b] += 1

        tlsh_hash = None
        if TLSH_AVAILABLE:
            try:
                tlsh_hash = _tlsh.hash(force=True, data=raw) or None
            except Exception:
                tlsh_hash = None       # too small / low variance inputs
        else:
            _warn_once("tlsh", "tlsh not installed - file-level fuzzy "
                               "matching disabled. pip install tlsh")

        ssd_hash = None
        if SSDEEP_AVAILABLE:
            try:
                ssd_hash = _ssdeep.hash(raw) or None
            except Exception:
                ssd_hash = None
        else:
            _warn_once("ssdeep", "ssdeep not installed - secondary fuzzy "
                                 "matching disabled. pip install ssdeep")

        return SampleFeatures(
            sha256=hashlib.sha256(raw).hexdigest(),
            md5=hashlib.md5(raw).hexdigest(),
            size=len(raw),
            format=fmt, architecture=arch,
            sections=sections, imports=imports, histogram=hist,
            tlsh=tlsh_hash, ssdeep=ssd_hash)

    def _parser_for(self, path: str):
        try:
            parser = BinaryParser(path, max_bytes=self.max_bytes)
            return None if parser.binary_type == "RAW" else parser
        except Exception:
            return None

    def _extract_sections(self, parser) -> list:
        out = []
        for sec in parser.binary.sections:
            try:
                content = bytes(sec.content)
            except Exception:
                content = b""
            if parser.binary_type == "ELF":
                exe = bool(sec.flags & _ELF_EXEC)
            elif parser.binary_type == "PE":
                exe = bool(sec.characteristics & _PE_EXEC)
            else:  # Mach-O: everything under __TEXT segment counts as exec-side
                exe = "__TEXT" in getattr(sec, "segment_name", "")
            out.append(SectionInfo(
                name=str(sec.name).rstrip("\x00"),
                size=len(content),
                entropy=_normalized_entropy(content),
                executable=exe,
                tlsh=self._section_tlsh(content)))
        return out

    @staticmethod
    def _section_tlsh(content: bytes) -> Optional[str]:
        if not (TLSH_AVAILABLE and content):
            return None
        try:
            return _tlsh.hash(force=True, data=content) or None
        except Exception:
            return None  # too small / low-variance sections

    def _extract_imports(self, parser) -> list:
        names = set()
        b = parser.binary
        try:
            if parser.binary_type == "PE":
                for entry in b.imports:
                    for func in entry.entries:
                        if func.name:
                            names.add(str(func.name))
            elif parser.binary_type == "ELF":
                for sym in b.dynamic_symbols:
                    if sym.name and str(sym.type).endswith("FUNC") \
                            and sym.shndx != 0:   # undefined = imported
                        names.add(str(sym.name))
        except Exception as e:
            logger.debug("import extraction failed: %s", e)
        return sorted(names)
