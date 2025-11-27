# Binartia

Binary Decompiler Visualizer - A tool for transforming executable binaries into visual representations using space-filling curves and entropy analysis.

## Overview

Binartia extracts bytecode from executable files and generates unique visual fingerprints. Each binary produces a distinct pattern based on its internal structure, making it useful for malware analysis, binary comparison, and reverse engineering research.

## Installation

```bash
git clone <repository-url>
cd binartia

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## Quick Start

### Command Line

Generate a basic visualization:
```bash
python src/cli.py /path/to/binary -o output.png
```

Use different curve algorithms:
```bash
python src/cli.py binary.exe --curve hilbert -o hilbert.png
python src/cli.py binary.exe --curve spiral -o spiral.png
python src/cli.py binary.exe --curve radial -o radial.png
```

Apply opcode-based coloring:
```bash
python src/cli.py binary.exe --color opcode -o opcode.png
```

Enable entropy overlay:
```bash
python src/cli.py binary.exe --entropy-overlay -o entropy.png
```

Compare multiple binaries:
```bash
python src/cli.py malware.exe benign.exe --compare -o comparison.png
```

### Web Dashboard

Launch the interactive dashboard:
```bash
streamlit run src/dashboard.py
```

Access at `http://localhost:8501`

## Visualization Modes

### Curve Algorithms

- **Hilbert**: Space-filling fractal curve that preserves locality
- **Spiral**: Outward spiral pattern from center
- **Grid**: Simple left-to-right, top-to-bottom layout
- **Random Walk**: Organic path-like visualization
- **Radial**: Circular pattern radiating from center

### Color Modes

- **HSV**: Entropy-aware color mapping with hue based on byte values
- **Heatmap**: Temperature-style gradient (blue to red)
- **Grayscale**: Direct byte value mapping
- **Opcode**: Instruction category-based coloring using Capstone disassembler

### Opcode Color Mapping

- Blue: Data movement instructions
- Green: Arithmetic operations
- Cyan: Logical operations
- Orange: Control flow
- Purple: Stack operations
- Red: System calls
- Magenta: Crypto/SIMD instructions
- Gray: Unknown or data

## AI Classifier

Train a malware detection model:
```python
from ai_classifier import MalwareClassifier, create_training_dataset

X_train, y_train = create_training_dataset('visualizations/', 'labels.json')

classifier = MalwareClassifier()
classifier.model = classifier.build_model()
classifier.train(X_train, y_train, epochs=50)
classifier.save_model('models/detector.h5')
```

Run inference:
```python
from ai_classifier import MalwareClassifier

classifier = MalwareClassifier('models/detector.h5')
label, confidence = classifier.predict('binary_viz.png')
print(f"{label}: {confidence:.2%}")
```

## Use Cases

### Malware Analysis
Identify suspicious patterns through visual inspection:
- High concentration of system calls (red in opcode mode)
- Unusual control flow patterns (orange clusters)
- High entropy regions indicating encryption or packing

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
              [--compare] [--stats] [-v]
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
  -v, --verbose        Enable verbose output
```

## Requirements

- Python 3.8+
- LIEF >= 0.13.0
- Pillow >= 10.0.0
- NumPy >= 1.24.0
- Streamlit >= 1.28.0
- Capstone >= 5.0.0
- TensorFlow >= 2.13.0

## Testing

Run unit tests:
```bash
pytest tests/ -v
```


