# Binartia

&emsp;Binary Visualizer - A tool for transforming executable binaries into visual representations using space-filling curves and entropy analysis. Binartia extracts bytecode from executable files and generates deterministic visual fingerprints. Each binary produces a distinct pattern based on its internal structure, making it useful for **binary comparison, similarity triage, and reverse engineering research**.

## Installation

```bash
git clone https://github.com/nietzhe/binartia.git
cd binartia

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Rust Extension (Optional, 140x faster)

For maximum performance on large files, build the Rust extension:

```bash
cd core && maturin develop --release
```

This enables:
- **140x faster** entropy calculation
- Parallel processing for multi-core CPUs
- Optimized Hilbert curve generation

## 2. Main workflow — triage a batch of samples

Scenario: an alert dumped 300 suspicious files into `~/cases/case-42/samples/`.

```bash
python src/triage_cli.py ~/cases/case-42/samples/ \
    -o ~/cases/case-42/report \
    --cache-dir ~/.binartia-cache \
    --jobs 8 \
    --render-representatives \
    --strict
```

| Flag | What it does |
|---|---|
| `-o` | Report directory (receives 3 files) |
| `--cache-dir` | Re-runs of the same folder are near-instant (extraction cached by content hash) |
| `--jobs 8` | Parallel workers (default: cores − 1) |
| `--render-representatives` | Renders one Hilbert PNG per family into the report |
| `--strict` | Exit non-zero if any file failed extraction (don't silently skip evidence) |
| `--threshold 50` | Stricter matching (default 40; raise to reduce false groupings) |

### Reading the results

```bash
firefox report/report.html   # clusters ranked by size + match table
```

- **Big cluster at top** → one malware family/campaign. Analyze ONE
  representative (`rep_<id>.png` shows its visual fingerprint); everything in
  that cluster is the same thing.
- **Singletons** → unique samples, need individual attention.
- **Errors section** → corrupt/padded files worth manual review.

Drill into *why* two samples matched:

```bash
python3 - <<'EOF'
import json
doc = json.load(open("report/report.json"))
for m in doc["matches"][:5]:
    print(f"{m['composite']:.1f}  {m['signals']}")
EOF
```

Spreadsheet view for ticketing:

```bash
column -s, -t < report/samples.csv | less -S
```

### Single-sample visualization & comparison

```bash
# Default: Hilbert curve, entropy-shaded HSV
python src/cli.py suspicious.bin -o viz.png

# Instruction-category coloring (needs a valid code section)
python src/cli.py suspicious.exe --color opcode -o opcode.png

# Side-by-side: is variant B related to sample A?
python src/cli.py sample_A.exe sample_B.exe --compare -o compare.png

# Entropy hotspots overlay (packing/encryption regions glow red)
python src/cli.py packed.bin --entropy-overlay -o packed.png

# Stats only
python src/cli.py suspicious.bin --stats
```

### Web Dashboard

(or) launch the interactive dashboard:
```bash
streamlit run src/dashboard.py
```

Access at `http://localhost:8501`

## Triage Workbench (Batch Similarity & Clustering)

Batch-triage hundreds of samples: structural feature extraction (TLSH/ssdeep fuzzy hashes, section tables with entropy, import tables, byte histograms), pairwise similarity scoring, family clustering, and JSON/CSV/HTML reports.

```bash
# Optional but recommended: fuzzy-hash backends
pip install tlsh ssdeep

# Triage a folder of samples into ./triage_report/
python src/triage_cli.py samples/ -o triage_report/
```

Outputs: `report.json` (full features + match pairs), `samples.csv`
(inventory with cluster IDs), `report.html` (standalone summary).

Key flags: `--threshold N` (min composite score, default 40), `--weights` (JSON override of signal weights, e.g. `'{"tlsh_file": 60}`), `--render-representatives` (visualization PNG per cluster representative), `--cache-dir` (re-use extraction results across runs), `--jobs N`, `--max-bytes N`, `--strict` (nonzero exit if any sample failed extraction).

> **Security notice:** Binartia parses untrusted binaries. Run it inside an isolated analysis environment (dedicated VM/container), never on your daily-driver workstation against live malware.


## AI Classifier (Experimental)

> ⚠️ **Status: experimental — do not deploy for operational detection.** Known limitations:
>
> - **Trivially evaded:** appending padding bytes, reordering sections, or packing changes the image completely while preserving functionality.
> - **Resize information loss:** images are squashed to 128×128, discarding the locality that space-filling curves preserve.
> - **Packed ≠ malicious:** high-entropy (packed) benign software scores the same as packed malware.
> - Evaluate only with the stratified, seeded pipeline from `scripts/train_classifier.py` (`split_dataset`); accuracy numbers from ad-hoc splits are not trustworthy.

Train a classifier model:
```python
from ai_classifier import MalwareClassifier, create_training_dataset, three_way_split

# Returns (X, y, groups): groups is not None when labels carry a "group" field.
X, y, groups = create_training_dataset('visualizations/', 'labels.json')

# Three-way split: EarlyStopping monitors the validation set; the test set
# is held out and never seen during training. Groups (families) stay whole.
X_train, X_val, X_test, y_train, y_val, y_test = three_way_split(
    X, y, test_size=0.2, val_size=0.2, seed=42, groups=groups)

classifier = MalwareClassifier()
classifier.model = classifier.build_model()
classifier.train(X_train, y_train,
                 validation_data=(X_val, y_val), epochs=50)
classifier.save_model('models/detector.h5')
```

Run inference:
```python
from ai_classifier import MalwareClassifier

classifier = MalwareClassifier('models/detector.h5')
label, confidence = classifier.predict('binary_viz.png')
print(f"{label}: {confidence:.2%}")
```

**Model integrity:** Always pass `expected_sha256` to `load_model()` — Keras `.h5` files use deserialization that can execute arbitrary code if the file is tampered with. Loading without verification logs a warning.

```python
import hashlib
h = hashlib.sha256(open('models/detector.h5', 'rb').read()).hexdigest()
classifier.load_model('models/detector.h5', expected_sha256=h)
```

## Use Cases

### Triage and Visual Analysis (human-in-the-loop)
Support analyst triage through visual inspection — signals to investigate, not verdicts:
- High concentration of system calls (red in opcode mode)
- Unusual control flow patterns (orange clusters)
- High entropy regions indicating encryption or packing
- Visual similarity between samples suggesting shared code lineage

### Binary Comparison
Compare different versions or variants:
```bash
python src/cli.py version1.exe version2.exe --compare -o diff.png
```

## CLI Options

```
usage: cli.py [-h] [-o OUTPUT] [--curve {hilbert,spiral,grid,random_walk,radial}]
              [--color {hsv,heatmap,grayscale,opcode}] [--scale SCALE]
              [--no-entropy] [--section SECTION] [--entropy-overlay]
              [--compare] [--stats] [--strict] [--max-bytes MAX_BYTES] [-v]
              binary [binary ...]

Options:
  -o, --output          Output PNG file path
  --curve              Curve mapping algorithm
  --color              Color mapping mode
  --scale              Pixel scale factor
  --no-entropy         Disable entropy-based brightness
  --section            Section to visualize (text, all, or section name)
  --entropy-overlay    Show entropy hotspots overlay
   --compare            Create side-by-side comparison
   --stats              Print statistics about the binary
   --strict             Fail instead of silently falling back when rendering degrades
   --max-bytes MAX_BYTES  Reject input files larger than this size in bytes (default: 64 MiB)
   -v, --verbose        Enable verbose output
```

## Testing

Run unit tests:
```bash
pytest tests/ -v
```
