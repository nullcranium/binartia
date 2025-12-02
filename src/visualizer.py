import logging
import numpy as np
from PIL import Image, ImageDraw
from typing import Optional, Tuple, List
from disassembler import OpcodeColorMapper, detect_architecture
from binary_parser import BinaryParser
from visual_mapper import ByteToColorMapper
from curve_algorithms import get_mapper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BinaryVisualizer:
    def __init__(self, 
                 curve_type: str = 'hilbert',
                 use_entropy: bool = True,
                 color_mode: str = 'hsv',
                 scale: int = 1,
                 show_entropy_overlay: bool = False):
        self.curve_type = curve_type
        self.use_entropy = use_entropy
        self.color_mode = color_mode
        self.scale = scale
        self.show_entropy_overlay = show_entropy_overlay
        self.mapper = ByteToColorMapper()
    
    def visualize(self, 
                  binary_path: str, 
                  output_path: str,
                  section: str = 'text') -> Tuple[int, int]:
        logger.info(f"Starting visualization of {binary_path}")
        
        parser = BinaryParser(binary_path)
        if section == 'text':
            data = parser.extract_text_section()
        elif section == 'all':
            data = parser.extract_all_code()
        else:
            data = parser.extract_section_by_name(section)
            if data is None:
                raise ValueError(f"Section '{section}' not found in binary")
        logger.info(f"Extracted {len(data)} bytes from binary")
        
        if self.color_mode == 'opcode':
            colors = self._get_opcode_colors(data, parser)
        elif self.color_mode == 'hsv':
            colors = self.mapper.bytes_to_colors(data, use_entropy=self.use_entropy)
        elif self.color_mode == 'heatmap':
            colors = self.mapper.bytes_to_heatmap(data)
        elif self.color_mode == 'grayscale':
            gray_values = self.mapper.bytes_to_grayscale(data)
            colors = [(g, g, g) for g in gray_values]
        else:
            raise ValueError(f"Unknown color mode: {self.color_mode}")
        
        curve_mapper = get_mapper(self.curve_type)
        coordinates = curve_mapper.map_to_coordinates(len(data))
        width, height = curve_mapper.get_dimensions(len(data))
        
        logger.info(f"Canvas size: {width}x{height}")
        
        image = self._create_image(colors, coordinates, width, height)
        if self.show_entropy_overlay:
            image = self._add_entropy_overlay(image, data, coordinates, width, height)
        image.save(output_path, 'PNG')
        logger.info(f"Saved visualization to {output_path}")
        
        return (image.width, image.height)
    
    def _get_opcode_colors(self, data: bytes, parser: BinaryParser) -> List[Tuple[int, int, int]]:
        try:
            metadata = parser.get_metadata()
            arch, mode = detect_architecture(parser.binary_type, metadata)
            
            opcode_mapper = OpcodeColorMapper(arch, mode)
            colors = opcode_mapper.disassemble_and_color(data)
            
            logger.info("Using opcode-based coloring")
            return colors
        except Exception as e:
            logger.warning(f"Opcode coloring failed: {e}, falling back to HSV")
            return self.mapper.bytes_to_colors(data, use_entropy=self.use_entropy)
    
    def _create_image(self, 
                     colors: list, 
                     coordinates: list,
                     width: int, 
                     height: int) -> Image.Image:
        # convert to numpy arrays for vectorization
        coords = np.array(coordinates)
        
        n_points = min(len(colors), len(coords))
        coords = coords[:n_points]
        colors = np.array(colors[:n_points], dtype=np.uint8)
        img_array = np.zeros((height, width, 3), dtype=np.uint8)
        
        # vectorized assignment
        valid_mask = (coords[:, 0] < width) & (coords[:, 1] < height)
        valid_coords = coords[valid_mask]
        valid_colors = colors[valid_mask]
        
        # assign colors to pixels
        img_array[valid_coords[:, 1], valid_coords[:, 0]] = valid_colors
        if self.scale > 1:
            img_array = img_array.repeat(self.scale, axis=0).repeat(self.scale, axis=1)
        return Image.fromarray(img_array, 'RGB')
    
    def _add_entropy_overlay(self, image: Image.Image, data: bytes, 
                            coordinates: list, width: int, height: int) -> Image.Image:
        byte_array = np.frombuffer(data, dtype=np.uint8)
        entropy_values = self.mapper._calculate_local_entropy(byte_array)
        
        coords = np.array(coordinates)
        n_points = min(len(entropy_values), len(coords))
        coords = coords[:n_points]
        entropy = entropy_values[:n_points]
        
        threshold = 0.7
        mask = entropy > threshold
        
        high_entropy_coords = coords[mask]
        high_entropy_vals = entropy[mask]
       
        overlay = Image.new('RGBA', image.size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(overlay)
        
        # iterate only over high entropy points
        for (x, y), val in zip(high_entropy_coords, high_entropy_vals):
            intensity = int((val - threshold) / (1 - threshold) * 255)
            x_scaled = x * self.scale
            y_scaled = y * self.scale
            # draw glowing dot
            draw.ellipse(
                [x_scaled - 2, y_scaled - 2, x_scaled + 2, y_scaled + 2],
                fill=(255, 0, 0, intensity)
            )
            
        base = image.convert('RGBA')
        result = Image.alpha_composite(base, overlay)
        
        return result.convert('RGB')
    
    def create_comparison(self, 
                         binary_paths: list,
                         output_path: str,
                         labels: Optional[list] = None) -> None:
        if not binary_paths:
            raise ValueError("No binary paths provided")
        
        images = []
        max_height = 0
        total_width = 0
        
        for i, binary_path in enumerate(binary_paths):
            temp_output = f"/tmp/binartia_temp_{i}.png"
            width, height = self.visualize(binary_path, temp_output)
            
            img = Image.open(temp_output)
            images.append(img)
            
            max_height = max(max_height, height)
            total_width += width
        spacing = 10
        total_width += spacing * (len(images) - 1)
        
        combined = Image.new('RGB', (total_width, max_height), color='black')
        
        x_offset = 0
        for img in images:
            combined.paste(img, (x_offset, 0))
            x_offset += img.width + spacing
        
        if labels:
            draw = ImageDraw.Draw(combined)
            x_offset = 0
            for i, (img, label) in enumerate(zip(images, labels)):
                draw.text((x_offset + 5, 5), label, fill='white')
                x_offset += img.width + spacing
        combined.save(output_path, 'PNG')
        
    def get_statistics(self, binary_path: str) -> dict:
        parser = BinaryParser(binary_path)
        data = parser.extract_text_section()
        
        byte_array = np.frombuffer(data, dtype=np.uint8)
        entropy = self.mapper._shannon_entropy(byte_array)
        unique_bytes = len(np.unique(byte_array))
        
        curve_mapper = get_mapper(self.curve_type)
        width, height = curve_mapper.get_dimensions(len(data))
        
        return {
            'file': binary_path,
            'bytes': len(data),
            'entropy': float(entropy),
            'unique_bytes': unique_bytes,
            'dimensions': f"{width}x{height}",
            'curve_type': self.curve_type
        }
