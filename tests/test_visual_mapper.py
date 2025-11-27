# unit tests for visual mapper

import pytest
import numpy as np
from src.visual_mapper import ByteToColorMapper


class TestByteToColorMapper:
    def test_bytes_to_colors(self):
        mapper = ByteToColorMapper()
        data = bytes([0, 127, 255])
        colors = mapper.bytes_to_colors(data, use_entropy=False)
        
        assert len(colors) == 3
        assert all(len(c) == 3 for c in colors)
        assert all(0 <= v <= 255 for c in colors for v in c)
    
    def test_entropy_calculation(self):
        mapper = ByteToColorMapper(entropy_window=8)
        
        low_entropy = np.array([0] * 100, dtype=np.uint8)
        entropy_low = mapper._shannon_entropy(low_entropy)
        
        high_entropy = np.random.randint(0, 256, 100, dtype=np.uint8)
        entropy_high = mapper._shannon_entropy(high_entropy)
        assert entropy_low < entropy_high
    
    def test_grayscale(self):
        mapper = ByteToColorMapper()
        data = bytes([0, 128, 255])
        gray = mapper.bytes_to_grayscale(data)
        assert gray == [0, 128, 255]
    
    def test_heatmap(self):
        mapper = ByteToColorMapper()
        data = bytes([0, 64, 128, 192, 255])
        colors = mapper.bytes_to_heatmap(data)
        
        assert len(colors) == 5
        # first; blue-ish
        assert colors[0][2] > colors[0][0]
        # last; red-ish
        assert colors[-1][0] > colors[-1][2]
    
    def test_color_palette(self):
        mapper = ByteToColorMapper()
        palette = mapper.create_color_palette('rainbow')
        assert len(palette) == 256
        palette = mapper.create_color_palette('viridis')
        assert len(palette) == 256
