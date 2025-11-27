#!/usr/bin/env python3

import os
import sys
import json
import argparse
from pathlib import Path
from src.visualizer import BinaryVisualizer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def main():
    parser = argparse.ArgumentParser(description='Generate training dataset')
    parser.add_argument('--malware-dir', required=True, help='Directory with malware samples')
    parser.add_argument('--benign-dir', required=True, help='Directory with benign samples')
    parser.add_argument('--output-dir', default='training_data', help='Output directory')
    parser.add_argument('--curve', default='hilbert', help='Curve algorithm')
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    labels = {}
    visualizer = BinaryVisualizer(curve_type=args.curve)
    
    print("Generating malware visualizations...")
    malware_files = list(Path(args.malware_dir).glob('*'))
    for i, binary_path in enumerate(malware_files, 1):
        if binary_path.is_file():
            output_name = f"malware_{i:04d}.png"
            output_path = os.path.join(args.output_dir, output_name)
            try:
                visualizer.visualize(str(binary_path), output_path)
                labels[output_name] = 'malware'
                print(f"  [{i}/{len(malware_files)}] {binary_path.name} -> {output_name}")
            except Exception as e:
                print(f"  Error processing {binary_path.name}: {e}")
    
    print("\nGenerating benign visualizations...")
    benign_files = list(Path(args.benign_dir).glob('*'))
    for i, binary_path in enumerate(benign_files, 1):
        if binary_path.is_file():
            output_name = f"benign_{i:04d}.png"
            output_path = os.path.join(args.output_dir, output_name)
            try:
                visualizer.visualize(str(binary_path), output_path)
                labels[output_name] = 'benign'
                print(f"  [{i}/{len(benign_files)}] {binary_path.name} -> {output_name}")
            except Exception as e:
                print(f"  Error processing {binary_path.name}: {e}")
    labels_path = os.path.join(args.output_dir, 'labels.json')
    with open(labels_path, 'w') as f:
        json.dump(labels, f, indent=2)
    
    print(f"\nDataset created:")
    print(f"  Malware samples: {sum(1 for v in labels.values() if v == 'malware')}")
    print(f"  Benign samples:  {sum(1 for v in labels.values() if v == 'benign')}")
    print(f"  Labels saved to: {labels_path}")


if __name__ == '__main__':
    main()
