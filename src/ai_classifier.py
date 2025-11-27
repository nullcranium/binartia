import os
import json
import logging
import numpy as np
from PIL import Image
from typing import Tuple

logger = logging.getLogger(__name__)

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logger.warning("TensorFlow not available, skipping AI classifier..")


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
    
    def load_model(self, model_path: str):
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is required for AI classifier.")
        
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
    
    def train(self, train_data, train_labels, validation_data=None, epochs=50, batch_size=32):
        if self.model is None:
            self.model = self.build_model()
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
    
    def evaluate(self, test_data, test_labels):
        if self.model is None:
            raise ValueError("Model not loaded")
        results = self.model.evaluate(test_data, test_labels, verbose=0)
        metrics = {
            'loss': results[0],
            'accuracy': results[1],
            'precision': results[2],
            'recall': results[3]
        }
        return metrics


def create_training_dataset(visualization_dir: str, labels_file: str):
    with open(labels_file, 'r') as f:
        labels_data = json.load(f)
    
    images = []
    labels = []
    for filename, label in labels_data.items():
        img_path = os.path.join(visualization_dir, filename)
        if os.path.exists(img_path):
            img = Image.open(img_path)
            img = img.convert('RGB')
            img = img.resize((128, 128))
            img_array = np.array(img) / 255.0
            
            images.append(img_array)
            labels.append(1 if label == 'malware' else 0)
    return np.array(images), np.array(labels)
