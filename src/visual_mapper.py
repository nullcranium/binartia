import colorsys
import numpy as np
from typing import List, Tuple


class ByteToColorMapper:    
    def __init__(self, entropy_window: int = 16):
        self.entropy_window = entropy_window
    
    def bytes_to_colors(self, data: bytes, use_entropy: bool = True) -> List[Tuple[int, int, int]]:
        if not data:
            return []
        
        byte_array = np.frombuffer(data, dtype=np.uint8)
        colors = []
        if use_entropy:
            entropy_val = self._calculate_local_entropy(byte_array)
        else:
            entropy_val = np.ones(len(byte_array))
        
        for i, byte_val in enumerate(byte_array):
            hue = byte_val / 255.0
            if use_entropy:
                saturation = 0.6 + (entropy_val[i] * 0.4)  # 0.6-1.0 range
                value = 0.4 + (entropy_val[i] * 0.6)  # 0.4-1.0 range
            else:
                saturation = 0.8
                value = 0.8
            r, g, b = colorsys.hsv_to_rgb(hue, saturation, value)
            rgb = (int(r * 255), int(g * 255), int(b * 255))
            colors.append(rgb)
        
        return colors
    
    def _calculate_local_entropy(self, data: np.ndarray) -> np.ndarray:
        entropy_val = np.zeros(len(data))
        half_window = self.entropy_window // 2
        
        for i in range(len(data)):
            # window boundaries
            start = max(0, i - half_window)
            end = min(len(data), i + half_window + 1)
            window = data[start:end]
            
            entropy = self._shannon_entropy(window)
            entropy_val[i] = entropy
        
        if entropy_val.max() > 0:
            entropy_val = entropy_val / entropy_val.max()
        return entropy_val
    
    def _shannon_entropy(self, data: np.ndarray) -> float:
        if len(data) == 0:
            return 0.0
        # count byte frequencies
        _, counts = np.unique(data, return_counts=True)
        probabilities = counts / len(data)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy
    
    def bytes_to_grayscale(self, data: bytes) -> List[int]:
        return list(data)
    
    def bytes_to_heatmap(self, data: bytes) -> List[Tuple[int, int, int]]:
        colors = []
        
        for byte_val in data:
            normalized = byte_val / 255.0
            if normalized < 0.25:
                t = normalized / 0.25
                r, g, b = 0, int(t * 255), 255 # cyan
            elif normalized < 0.5:
                t = (normalized - 0.25) / 0.25
                r, g, b = 0, 255, int((1 - t) * 255) # green
            elif normalized < 0.75:
                t = (normalized - 0.5) / 0.25
                r, g, b = int(t * 255), 255, 0 # yellow
            else:
                t = (normalized - 0.75) / 0.25
                r, g, b = 255, int((1 - t) * 255), 0 # red
            colors.append((r, g, b))
        return colors
    
    def create_color_palette(self, palette_type: str = 'rainbow') -> List[Tuple[int, int, int]]:
        palette = []
        if palette_type == 'rainbow':
            for i in range(256):
                hue = i / 255.0
                r, g, b = colorsys.hsv_to_rgb(hue, 0.8, 0.9)
                palette.append((int(r * 255), int(g * 255), int(b * 255)))
        elif palette_type == 'viridis':
            for i in range(256):
                t = i / 255.0
                r = int(255 * (0.267 + 0.533 * t))
                g = int(255 * (0.004 + 0.873 * t - 0.333 * t**2))
                b = int(255 * (0.329 + 0.184 * t + 0.487 * t**2))
                palette.append((r, g, b))
        elif palette_type == 'plasma':
            for i in range(256):
                t = i / 255.0
                r = int(255 * (0.050 + 2.5 * t - 2.0 * t**2))
                g = int(255 * (0.030 + 0.5 * t))
                b = int(255 * (0.527 - 0.5 * t))
                palette.append((max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b))))
        else:
            return self.create_color_palette('rainbow')
        return palette
