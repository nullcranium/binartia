import argparse
import sys
import os
from pathlib import Path

from visualizer import BinaryVisualizer


def main():
    parser = argparse.ArgumentParser(
        description='Binartia - Transform executables into visual art',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /bin/ls -o ls_hilbert.png
  %(prog)s /bin/cat --curve spiral --scale 2 -o cat_spiral.png
  %(prog)s malware.exe --color heatmap -o malware_heat.png
  %(prog)s binary1 binary2 binary3 --compare -o comparison.png
        """
    )
    
    parser.add_argument(
        'binary',
        nargs='+',
        help='Path to binary file(s) to visualize'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='output.png',
        help='Output PNG file path (default: output.png)'
    )
    
    parser.add_argument(
        '--curve',
        choices=['hilbert', 'spiral', 'grid', 'random_walk', 'radial'],
        default='hilbert',
        help='Curve mapping algorithm (default: hilbert)'
    )
    
    parser.add_argument(
        '--color',
        choices=['hsv', 'heatmap', 'grayscale', 'opcode'],
        default='hsv',
        help='Color mapping mode (default: hsv)'
    )
    
    parser.add_argument(
        '--scale',
        type=int,
        default=1,
        help='Pixel scale factor (default: 1)'
    )
    
    parser.add_argument(
        '--no-entropy',
        action='store_true',
        help='Disable entropy-based brightness adjustment'
    )
    
    parser.add_argument(
        '--section',
        default='text',
        help='Section to visualize (default: text, options: text, all, or section name)'
    )
    
    parser.add_argument(
        '--entropy-overlay',
        action='store_true',
        help='Show entropy hotspots overlay'
    )
    
    parser.add_argument(
        '--compare',
        action='store_true',
        help='Create side-by-side comparison of multiple binaries'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Print statistics about the binary'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        import logging
        logging.basicConfig(level=logging.INFO)
    
    for binary_path in args.binary:
        if not os.path.exists(binary_path):
            print(f"Error: File not found: {binary_path}", file=sys.stderr)
            sys.exit(1)
    
    visualizer = BinaryVisualizer(
        curve_type=args.curve,
        use_entropy=not args.no_entropy,
        color_mode=args.color,
        scale=args.scale,
        show_entropy_overlay=args.entropy_overlay
    )
    
    try:
        if args.stats:
            for binary_path in args.binary:
                stats = visualizer.get_statistics(binary_path)
                print(f"\n=== Statistics for {binary_path} ===")
                for key, value in stats.items():
                    print(f"{key:15s}: {value}")
            return
        
        if args.compare:
            if len(args.binary) < 2:
                print("Error: Comparison mode requires at least 2 binaries", file=sys.stderr)
                sys.exit(1)
            
            labels = [Path(p).name for p in args.binary]
            visualizer.create_comparison(args.binary, args.output, labels)
            print(f"✓ Created comparison: {args.output}")
            return
        
        if len(args.binary) > 1:
            print("Warning: Multiple binaries provided but not in comparison mode. Using first binary only.")
        
        binary_path = args.binary[0]
        width, height = visualizer.visualize(
            binary_path,
            args.output,
            section=args.section
        )
        
        print(f"✓ Generated visualization: {args.output}")
        print(f"  Dimensions: {width}x{height}")
        print(f"  Curve: {args.curve}")
        print(f"  Color mode: {args.color}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
