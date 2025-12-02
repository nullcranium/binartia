
import time
import os
import sys
import numpy as np
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from src.visualizer import BinaryVisualizer

def create_dummy_binary(size_mb, filename):
    size_bytes = size_mb * 1024 * 1024
    data = np.random.bytes(size_bytes)
    with open(filename, 'wb') as f:
        f.write(data)
    return filename

def benchmark():
    filename = 'test_bench.bin'
    output = 'test_bench.png'
    
    try:
        # disable entropy to test pure rendering speed (entropy calc is still O(N))
        create_dummy_binary(1, filename)
        viz = BinaryVisualizer(curve_type='grid', scale=1, use_entropy=False)
        
        start_time = time.time()
        viz.visualize(filename, output, section='all')
        end_time = time.time()
        print(f"Grid (1MB, no entropy): {end_time - start_time:.4f} seconds")
        
        create_dummy_binary(0.1, filename)
        viz = BinaryVisualizer(curve_type='hilbert', scale=1, use_entropy=False)
        
        start_time = time.time()
        viz.visualize(filename, output, section='all')
        end_time = time.time()
        print(f"Hilbert (100KB, no entropy): {end_time - start_time:.4f} seconds")

    finally:
        if os.path.exists(filename):
            os.remove(filename)
        if os.path.exists(output):
            os.remove(output)

if __name__ == '__main__':
    benchmark()
