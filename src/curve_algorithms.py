import math
import random
import numpy as np
from typing import Tuple, List
from abc import ABC, abstractmethod


class CurveMapper(ABC):
    @abstractmethod
    def map_to_coordinates(self, data_length: int) -> List[Tuple[int, int]]:
        pass
    
    @abstractmethod
    def get_dimensions(self, data_length: int) -> Tuple[int, int]:
        pass


class HilbertCurve(CurveMapper):
    def __init__(self):
        self.order = 1
        self.size = 2
        self._cache = {}
    
    def get_dimensions(self, data_length: int) -> Tuple[int, int]:
        # calculate dimensions based on Hilbert curve order and
        # find the minimum order needed to fit all data
        self.order = math.ceil(math.log2(math.sqrt(data_length)))
        self.order = max(1, self.order)
        self.size = 2 ** self.order
        return (self.size, self.size)
    
    def map_to_coordinates(self, data_length: int) -> List[Tuple[int, int]]:
        self.get_dimensions(data_length) # ensure order is set
        
        coords = self._generate_hilbert_curve(self.order)
        if len(coords) > data_length:
            coords = coords[:data_length]
            
        return coords
    
    def _generate_hilbert_curve(self, order: int) -> np.ndarray:
        if order in self._cache:
            return self._cache[order]
            
        if order == 1:
            curve = np.array([[0, 0], [0, 1], [1, 1], [1, 0]], dtype=np.int32)
            self._cache[1] = curve
            return curve
    
        prev_curve = self._generate_hilbert_curve(order - 1)
        N = 2 ** (order - 1)
        
        p0 = prev_curve[:, [1, 0]]
        p1 = prev_curve + [0, N]
        p2 = prev_curve + [N, N]
        p3 = (N - 1) - prev_curve
        p3 = p3[:, [1, 0]]
        p3 = p3 + [N, 0]
        
        curve = np.concatenate([p0, p1, p2, p3])
        self._cache[order] = curve
        return curve


class SpiralMapper(CurveMapper):
    def get_dimensions(self, data_length: int) -> Tuple[int, int]:
        side = math.ceil(math.sqrt(data_length))
        if side % 2 == 0:
            side += 1
        return (side, side)
    
    def map_to_coordinates(self, data_length: int) -> List[Tuple[int, int]]:
        # generate spiral coordinates from center outward
        width, height = self.get_dimensions(data_length)
        coordinates = []
        
        cx = cy = width // 2
        x, y = cx, cy
        coordinates.append((x, y))
        
        dx, dy = 1, 0  # start moving to the right
        segment_length = 1
        segment_passed = 0
        
        for i in range(1, data_length):
            # move in current direction
            x += dx
            y += dy
            coordinates.append((x, y))
            segment_passed += 1
            
            if segment_passed == segment_length:
                segment_passed = 0
                dx, dy = -dy, dx
                if dy == 0:
                    segment_length += 1
        return coordinates


class GridMapper(CurveMapper):
    def get_dimensions(self, data_length: int) -> Tuple[int, int]:
        width = math.ceil(math.sqrt(data_length * 16 / 9))
        height = math.ceil(data_length / width)
        return (width, height)
    
    def map_to_coordinates(self, data_length: int) -> List[Tuple[int, int]]:
        width, height = self.get_dimensions(data_length)
        indices = np.arange(data_length)
        x = indices % width
        y = indices // width
        
        return np.column_stack((x, y))


class RandomWalkMapper(CurveMapper):
    def __init__(self, seed: int = 42):
        self.seed = seed
    
    def get_dimensions(self, data_length: int) -> Tuple[int, int]:
        side = math.ceil(math.sqrt(data_length)) + 10
        return (side, side)
    
    def map_to_coordinates(self, data_length: int) -> List[Tuple[int, int]]:
        random.seed(self.seed)
        width, height = self.get_dimensions(data_length)
        coordinates = []

        x = width // 2
        y = height // 2
        visited = set()
        
        directions = [(0, 1), (1, 0), (0, -1), (-1, 0), (1, 1), (-1, -1), (1, -1), (-1, 1)]
        for i in range(data_length):
            coordinates.append((x, y))
            visited.add((x, y))

            attempts = 0
            while attempts < 20:
                dx, dy = random.choice(directions)
                nx, ny = x + dx, y + dy
                if 0 <= nx < width and 0 <= ny < height and (nx, ny) not in visited:
                    x, y = nx, ny
                    break
                attempts += 1
            else:
                for dx, dy in directions:
                    nx, ny = x + dx, y + dy
                    if 0 <= nx < width and 0 <= ny < height and (nx, ny) not in visited:
                        x, y = nx, ny
                        break
        return coordinates


class RadialMapper(CurveMapper):
    def get_dimensions(self, data_length: int) -> Tuple[int, int]:
        side = math.ceil(math.sqrt(data_length)) * 2
        if side % 2 == 0:
            side += 1
        return (side, side)
    
    def map_to_coordinates(self, data_length: int) -> List[Tuple[int, int]]:
        width, height = self.get_dimensions(data_length)
        coordinates = []
        
        cx = width // 2
        cy = height // 2
        coordinates.append((cx, cy))
        
        radius = 1
        angle = 0
        angle_step = 0.5
        for i in range(1, data_length):
            x = int(cx + radius * math.cos(angle))
            y = int(cy + radius * math.sin(angle))
            
            x = max(0, min(width - 1, x))
            y = max(0, min(height - 1, y))
            coordinates.append((x, y))
            
            angle += angle_step
            if angle >= 2 * math.pi:
                angle = 0
                radius += 1
                angle_step = max(0.1, angle_step * 0.95)
        return coordinates


def get_mapper(curve_type: str) -> CurveMapper:
    mappers = {
        'hilbert': HilbertCurve,
        'spiral': SpiralMapper,
        'grid': GridMapper,
        'random_walk': RandomWalkMapper,
        'radial': RadialMapper
    }  
    curve_type = curve_type.lower()
    if curve_type not in mappers:
        raise ValueError(f"Unknown curve type: {curve_type}. Choose from: {list(mappers.keys())}")
    
    return mappers[curve_type]()
