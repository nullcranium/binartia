#!/usr/bin/env python3
import time
import numpy as np
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.visual_mapper import ByteToColorMapper
from src.curve_algorithms import HilbertCurve


def benchmark_entropy():
    """Benchmark entropy calculation."""
    print("\n" + "="*60)
    print("ENTROPY CALCULATION BENCHMARK")
    print("="*60)
    
    sizes = [10_000, 100_000, 1_000_000, 10_000_000]
    
    for size in sizes:
        data = np.random.randint(0, 256, size, dtype=np.uint8)
        mapper = ByteToColorMapper(entropy_window=16)
        
        # Warm up
        _ = mapper._calculate_local_entropy(data[:1000])
        
        start = time.perf_counter()
        result = mapper._calculate_local_entropy(data)
        elapsed = time.perf_counter() - start
        
        mb = size / (1024 * 1024)
        throughput = mb / elapsed
        
        print(f"  {size:>10,} bytes ({mb:.2f} MB): {elapsed:.4f}s ({throughput:.1f} MB/s)")


def benchmark_hilbert():
    """Benchmark Hilbert curve generation."""
    print("\n" + "="*60)
    print("HILBERT CURVE GENERATION BENCHMARK")
    print("="*60)
    
    orders = [8, 10, 12, 14]
    
    for order in orders:
        hilbert = HilbertCurve()
        hilbert._cache.clear()  # Clear cache to force recomputation
        
        n_points = (2 ** order) ** 2
        
        start = time.perf_counter()
        coords = hilbert._generate_hilbert_curve(order)
        elapsed = time.perf_counter() - start
        
        print(f"  Order {order:>2} ({n_points:>10,} points): {elapsed:.4f}s")


def check_rust_enabled():
    """Check if Rust extensions are being used."""
    from src import visual_mapper, curve_algorithms
    
    print("\n" + "="*60)
    print("RUST EXTENSION STATUS")
    print("="*60)
    
    entropy_rust = getattr(visual_mapper, '_USE_RUST_ENTROPY', False)
    hilbert_rust = getattr(curve_algorithms, '_USE_RUST_HILBERT', False)
    
    print(f"  Entropy (Rust):  {'✓ ENABLED' if entropy_rust else '✗ Disabled (Python fallback)'}")
    print(f"  Hilbert (Rust):  {'✓ ENABLED' if hilbert_rust else '✗ Disabled (Python fallback)'}")
    
    return entropy_rust, hilbert_rust


if __name__ == '__main__':
    print("\n" + "="*60)
    print("BINARTIA PERFORMANCE BENCHMARK")
    print("="*60)
    
    rust_entropy, rust_hilbert = check_rust_enabled()
    
    benchmark_entropy()
    benchmark_hilbert()
    
    print("\n" + "="*60)
    if rust_entropy and rust_hilbert:
        print("Benchmarks ran with RUST acceleration enabled.")
    else:
        print("WARNING: Running with Python fallback (Rust not available)")
    print("="*60 + "\n")
