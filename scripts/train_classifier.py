#!/usr/bin/env python3

import os
import sys
import json
import argparse
import numpy as np
from pathlib import Path
from src.ai_classifier import (
    MalwareClassifier,
    create_training_dataset,
    three_way_split,
    class_distribution,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def main():
    parser = argparse.ArgumentParser(description='Train malware classifier')
    parser.add_argument('--data-dir', required=True, help='Directory containing visualization images')
    parser.add_argument('--labels', required=True, help='JSON file with labels')
    parser.add_argument('--output', default='models/malware_detector.h5', help='Output model path')
    parser.add_argument('--epochs', type=int, default=50, help='Training epochs')
    parser.add_argument('--batch-size', type=int, default=32, help='Batch size')
    parser.add_argument('--test-split', type=float, default=0.2, help='Test split ratio')
    parser.add_argument('--val-split', type=float, default=0.2,
                        help='Validation split ratio (carved from train remainder; '
                             'EarlyStopping monitors this, never the test set)')
    parser.add_argument('--seed', type=int, default=42, help='Random seed for reproducible splits/training')
    parser.add_argument('--strict', action='store_true',
                        help='Fail instead of continuing when labeled files are missing')
    args = parser.parse_args()

    print(f"\nLoading dataset from {args.data_dir}")
    print(f"Using labels from {args.labels}")

    X, y, groups = create_training_dataset(args.data_dir, args.labels)
    if groups is not None:
        print("Group field detected: splits will keep whole groups "
              "(families) on one side to prevent leakage")

    if args.strict and len(X) < len(json.load(open(args.labels))):
        print(f"Error: strict mode: some labeled files were missing from "
              f"{args.data_dir}", file=sys.stderr)
        return 1

    print(f"Loaded {len(X)} samples")
    dist = class_distribution(y)
    for label, count in dist['counts'].items():
        print(f"  Class {label}: {count} ({dist['ratios'][label]:.1%})")

    X_train, X_val, X_test, y_train, y_val, y_test = three_way_split(
        X, y, test_size=args.test_split, val_size=args.val_split,
        seed=args.seed, groups=groups
    )

    print(f"\nTraining set:   {len(X_train)} samples")
    print(f"Validation set: {len(X_val)} samples")
    print(f"Test set:       {len(X_test)} samples (held out; never seen during training)")

    print("\nBuilding model..")
    classifier = MalwareClassifier()
    classifier.model = classifier.build_model()
    classifier.model.summary()

    history = classifier.train(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=args.epochs,
        batch_size=args.batch_size,
        seed=args.seed
    )

    print("\nEvaluating..")
    metrics = classifier.evaluate(X_test, y_test)

    print("\nTest Results:")
    print(f"  Loss:      {metrics['loss']:.4f}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    classifier.save_model(args.output)
    print(f"\nModel saved to {args.output}")

    history_path = args.output.replace('.h5', '_history.json')
    with open(history_path, 'w') as f:
        json.dump({
            'seed': args.seed,
            'class_distribution': dist,
            'history': {k: [float(v) for v in vals] for k, vals in history.history.items()},
            'metrics': {k: float(v) for k, v in metrics.items() if k != 'report'},
            'per_class_report': metrics.get('report', {}),
        }, f, indent=2)
    print(f"Training history and evaluation report saved to {history_path}")
    

if __name__ == '__main__':
    sys.exit(main())
