# unit testing for curve algrthm

import pytest
from src.curve_algorithms import HilbertCurve, SpiralMapper, GridMapper, get_mapper


class TestHilbertCurve:
    def test_dimensions(self):
        hilbert = HilbertCurve()
        width, height = hilbert.get_dimensions(16)
        assert width == height
        assert width * height >= 16
        
        width, height = hilbert.get_dimensions(1024)
        assert width * height >= 1024
    
    def test_coordinates(self):
        hilbert = HilbertCurve()
        coords = hilbert.map_to_coordinates(16)
        
        assert len(coords) == 16
        assert all(isinstance(c, tuple) and len(c) == 2 for c in coords)
        assert len(set(coords)) == len(coords)
    
    def test_coordinate_bounds(self):
        hilbert = HilbertCurve()
        data_length = 256
        
        coords = hilbert.map_to_coordinates(data_length)
        width, height = hilbert.get_dimensions(data_length)
        for x, y in coords:
            assert 0 <= x < width
            assert 0 <= y < height


class TestSpiralMapper:
    def test_dimensions(self):
        spiral = SpiralMapper()
        width, height = spiral.get_dimensions(100)
        
        assert width == height  # should be square
        assert width % 2 == 1  # should be odd for center
        assert width * height >= 100
    
    def test_coordinates(self):
        spiral = SpiralMapper()
        coords = spiral.map_to_coordinates(25)
        assert len(coords) == 25
        
        width, height = spiral.get_dimensions(25)
        center = (width // 2, height // 2)
        assert coords[0] == center


class TestGridMapper:
    def test_dimensions(self):
        grid = GridMapper()
        width, height = grid.get_dimensions(100)
        
        assert width * height >= 100
        assert width >= height
    
    def test_coordinates(self):
        grid = GridMapper()
        coords = grid.map_to_coordinates(100)
        
        assert len(coords) == 100
        assert coords[0] == (0, 0)
        
        # coordinates should be in row-major order
        width, height = grid.get_dimensions(100)
        assert coords[1] == (1, 0)


class TestMapperFactory:
    def test_get_mapper(self):
        assert isinstance(get_mapper('hilbert'), HilbertCurve)
        assert isinstance(get_mapper('spiral'), SpiralMapper)
        assert isinstance(get_mapper('grid'), GridMapper)
    
    def test_invalid_mapper(self):
        with pytest.raises(ValueError):
            get_mapper('invalid')
