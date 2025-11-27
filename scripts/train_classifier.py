#!/usr/bin/env python3

import os
import sys
import json
import argparse
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from src.ai_classifier import MalwareClassifier, create_training_dataset

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def main():
    parser = argparse.ArgumentParser(description='Train malware classifier')
    parser.add_argument('--data-dir', required=True, help='Directory containing visualization images')
    parser.add_argument('--labels', required=True, help='JSON file with labels')
    parser.add_argument('--output', default='models/malware_detector.h5', help='Output model path')
    parser.add_argument('--epochs', type=int, default=50, help='Training epochs')
    parser.add_argument('--batch-size', type=int, default=32, help='Batch size')
    parser.add_argument('--test-split', type=float, default=0.2, help='Test split ratio')
    args = parser.parse_args()

    print(f"\nLoading dataset from {args.data_dir}")
    print(f"Using labels from {args.labels}")
    
    X, y = create_training_dataset(args.data_dir, args.labels)
    
    print(f"Loaded {len(X)} samples")
    print(f"  Malware: {np.sum(y == 1)}")
    print(f"  Benign:  {np.sum(y == 0)}")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_split, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set:     {len(X_test)} samples")
    
    print("\nBuilding model..")
    classifier = MalwareClassifier()
    classifier.model = classifier.build_model()
    classifier.model.summary()
    
    history = classifier.train(
        X_train, y_train,
        validation_data=(X_test, y_test),
        epochs=args.epochs,
        batch_size=args.batch_size
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
            'history': {k: [float(v) for v in vals] for k, vals in history.history.items()},
            'metrics': {k: float(v) for k, v in metrics.items()}
        }, f, indent=2)
    print(f"Training history saved to {history_path}")
    

main() if __name__ == '__main__' else exit(1)
