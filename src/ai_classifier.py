# dummy — beta.
import os
import json
import hashlib
import hmac
import logging
import warnings
import numpy as np
from PIL import Image
from typing import Tuple, Dict, Any

logger = logging.getLogger(__name__)

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logger.warning("TensorFlow not available, skipping AI classifier..")


def _require_sklearn():
    try:
        import sklearn
    except ImportError:
        raise ImportError("scikit-learn is required for dataset splitting and metrics. "
                          "Install it with: pip install scikit-learn")
    return sklearn


def split_dataset(X, y, test_size: float = 0.2, seed: int = 42,
                  stratify: bool = True, groups=None):
    sklearn = _require_sklearn()
    from sklearn.model_selection import train_test_split

    y = np.asarray(y)

    if groups is not None:
        from sklearn.model_selection import GroupShuffleSplit

        groups = np.asarray(groups, dtype=object)
        if len(groups) != len(y):
            raise ValueError(
                f"groups length {len(groups)} != labels length {len(y)}")

        gss = GroupShuffleSplit(n_splits=1, test_size=test_size,
                                random_state=seed)
        train_idx, test_idx = next(gss.split(X, y, groups=groups))

        X = np.asarray(X)
        return X[train_idx], X[test_idx], y[train_idx], y[test_idx]

    labels = np.unique(y)
    if stratify:
        if len(labels) < 2:
            raise ValueError(
                f"Stratified split requires at least 2 classes, got {len(labels)}")

        counts = {int(l): int(np.sum(y == l)) for l in labels}
        min_count = min(counts.values())
        if min_count < 2:
            raise ValueError(
                f"Stratified split requires at least 2 samples per class; "
                f"minimum found: {min_count} (counts: {counts})")

    return train_test_split(
        X, y,
        test_size=test_size,
        random_state=seed,
        stratify=y if stratify else None,
    )


def three_way_split(X, y, test_size: float = 0.2, val_size: float = 0.2,
                    seed: int = 42, groups=None):
    X = np.asarray(X)
    y = np.asarray(y)

    if groups is not None:
        from sklearn.model_selection import GroupShuffleSplit

        groups = np.asarray(groups, dtype=object)
        if len(groups) != len(y):
            raise ValueError(
                f"groups length {len(groups)} != labels length {len(y)}")

        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
        trv_idx, te_idx = next(gss.split(X, y, groups=groups))

        gss2 = GroupShuffleSplit(n_splits=1, test_size=val_size, random_state=seed + 1)
        tr_idx, va_idx = next(gss2.split(X[trv_idx], y[trv_idx], groups=groups[trv_idx]))

        return (X[trv_idx][tr_idx], X[trv_idx][va_idx], X[te_idx],
                y[trv_idx][tr_idx], y[trv_idx][va_idx], y[te_idx])

    X_trv, X_te, y_trv, y_te = split_dataset(X, y, test_size=test_size, seed=seed)
    X_tr, X_va, y_tr, y_va = split_dataset(X_trv, y_trv, test_size=val_size, seed=seed + 1)

    return X_tr, X_va, X_te, y_tr, y_va, y_te


def class_distribution(y) -> Dict[str, Dict[int, float]]:
    y = np.asarray(y)
    labels, counts = np.unique(y, return_counts=True)
    total = len(y)

    return {
        'counts': {int(l): int(c) for l, c in zip(labels, counts)},
        'ratios': {int(l): (float(c) / total if total else 0.0)
                   for l, c in zip(labels, counts)},
    }


def compute_metrics(y_true, y_pred) -> Dict[str, Any]:
    sklearn = _require_sklearn()
    from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

    labels = sorted(set(np.asarray(y_true)) | set(np.asarray(y_pred)))
    precisions, recalls, f1s, supports = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0)

    return {
        'per_class': {
            int(l): {
                'precision': float(p),
                'recall': float(r),
                'f1': float(f),
                'support': int(s),
            }
            for l, p, r, f, s in zip(labels, precisions, recalls, f1s, supports)
        },
        'confusion_matrix': confusion_matrix(
            y_true, y_pred, labels=labels).tolist(),
    }


class MalwareClassifier:
    def __init__(self, model_path: str = None):
        self.model = None
        self.model_path = model_path
        self.img_size = (128, 128)
        
        if TENSORFLOW_AVAILABLE and model_path:
            self.load_model(model_path)
    
    def build_model(self) -> keras.Model:
        model = keras.Sequential([
            layers.Input(shape=(*self.img_size, 3)),
            
            layers.Conv2D(32, (3, 3), activation='relu'),
            layers.MaxPooling2D((2, 2)),
            layers.BatchNormalization(),
            
            layers.Conv2D(64, (3, 3), activation='relu'),
            layers.MaxPooling2D((2, 2)),
            layers.BatchNormalization(),
            
            layers.Conv2D(128, (3, 3), activation='relu'),
            layers.MaxPooling2D((2, 2)),
            layers.BatchNormalization(),
            
            layers.Conv2D(256, (3, 3), activation='relu'),
            layers.MaxPooling2D((2, 2)),
            layers.BatchNormalization(),
            
            layers.Flatten(),
            layers.Dropout(0.5),
            layers.Dense(512, activation='relu'),
            layers.Dropout(0.3),
            layers.Dense(256, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        return model
    
    def load_model(self, model_path: str, expected_sha256: str = None):
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is required for AI classifier.")

        if expected_sha256 is not None:
            digest = hashlib.sha256(open(model_path, "rb").read()).hexdigest()
            if not hmac.compare_digest(digest, expected_sha256):
                self.model = None
                raise ValueError(f"Model hash mismatch for {model_path}: "
                                 f"expected {expected_sha256}, got {digest}")
        else:
            logger.warning("Loading model %s WITHOUT integrity verification; "
                           "pass expected_sha256 to prevent tampered-model loading.", model_path)

        try:
            self.model = keras.models.load_model(model_path)
            logger.info(f"Loaded model from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def save_model(self, model_path: str):
        if self.model is None:
            raise ValueError("No model to save")
        self.model.save(model_path)
        # logger.info(f"Saved model to {model_path}")
    
    def preprocess_image(self, image_path: str) -> np.ndarray:
        img = Image.open(image_path)
        img = img.convert('RGB')
        img = img.resize(self.img_size)
        img_array = np.array(img) / 255.0
        img_array = np.expand_dims(img_array, axis=0)
        
        return img_array
    
    def predict(self, image_path: str) -> Tuple[str, float]:
        if self.model is None:
            raise ValueError("Model not loaded. Call load_model() or build_model() first.")
        img_array = self.preprocess_image(image_path)
        
        prediction = self.model.predict(img_array, verbose=0)[0][0]
        label = "Malware" if prediction > 0.5 else "Benign"
        confidence = prediction if prediction > 0.5 else 1 - prediction
        
        logger.info(f"Prediction: {label} (confidence: {confidence:.2%})")
        return label, float(confidence)
    
    def train(self, train_data, train_labels, validation_data=None, epochs=50,
              batch_size=32, seed=None):
        if self.model is None:
            self.model = self.build_model()
        if seed is not None:
            if not TENSORFLOW_AVAILABLE:
                raise ImportError("TensorFlow is required for training.")
            tf.keras.utils.set_random_seed(seed)
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss' if validation_data else 'loss',
                patience=10,
                restore_best_weights=True
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss' if validation_data else 'loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7
            )
        ]
        history = self.model.fit(
            train_data,
            train_labels,
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1
        )
        return history
    
    def evaluate(self, test_data, test_labels, detailed: bool = False):
        if self.model is None:
            raise ValueError("Model not loaded")
        results = self.model.evaluate(test_data, test_labels, verbose=0)
        metrics = {
            'loss': results[0],
            'accuracy': results[1],
            'precision': results[2],
            'recall': results[3]
        }

        if detailed:
            y_pred = (self.model.predict(test_data, verbose=0).ravel() > 0.5).astype(int)
            metrics['report'] = compute_metrics(test_labels, y_pred)
        return metrics


def create_training_dataset(visualization_dir: str, labels_file: str):
    with open(labels_file, 'r') as f:
        labels_data = json.load(f)

    images = []
    labels = []
    raw_groups = []
    missing = []

    for filename, entry in labels_data.items():
        img_path = os.path.join(visualization_dir, filename)
        if not os.path.exists(img_path):
            missing.append(filename)
            continue

        if isinstance(entry, dict):
            label_value = entry.get("label")
            group = entry.get("group")
        else:
            label_value, group = entry, None

        img = Image.open(img_path)
        img = img.convert('RGB')
        img = img.resize((128, 128))
        img_array = np.array(img) / 255.0

        images.append(img_array)
        labels.append(1 if label_value == 'malware' else 0)
        raw_groups.append(group)

    if missing:
        preview = ", ".join(sorted(missing)[:10]) + \
            (" ..." if len(missing) > 10 else "")
        message = (f"Dataset loader skipped {len(missing)}/{len(labels_data)} "
                   f"labeled files missing from '{visualization_dir}': "
                   f"{preview}. This shrinks the dataset and may skew it.")
        logger.warning(message)
        warnings.warn(message, UserWarning, stacklevel=2)

    have_groups = any(g is not None for g in raw_groups)
    groups = None
    if have_groups:
        # ungrouped files become their own group so they never straddle splits
        groups = [g if g is not None else f"__singleton__:{i}"
                  for i, g in enumerate(raw_groups)]

    return np.array(images), np.array(labels), groups
