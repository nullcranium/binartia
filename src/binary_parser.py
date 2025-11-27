import lief
import logging
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BinaryParser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.binary = None
        self.binary_type = None
        self._parse()
    
    def _parse(self):
        try:
            self.binary = lief.parse(self.filepath)
            
            if self.binary is None:
                logger.warning(f"LIEF could not parse {self.filepath}, treating as raw binary")
                self.binary_type = "RAW"
                return
            
            if isinstance(self.binary, lief.ELF.Binary):
                self.binary_type = "ELF"
            elif isinstance(self.binary, lief.PE.Binary):
                self.binary_type = "PE"
            elif isinstance(self.binary, lief.MachO.Binary):
                self.binary_type = "MachO"
            else:
                self.binary_type = "Unknown"
            
            logger.info(f"Parsed {self.binary_type} binary: {self.filepath}")
        except Exception as e:
            logger.warning(f"Error parsing binary with LIEF: {e}, treating as raw binary")
            self.binary_type = "RAW"
            self.binary = None
    
    def extract_text_section(self) -> bytes:
        if self.binary_type == "RAW":
            return self._extract_raw_binary()
        elif self.binary_type == "ELF":
            return self._extract_elf_text()
        elif self.binary_type == "PE":
            return self._extract_pe_text()
        elif self.binary_type == "MachO":
            return self._extract_macho_text()
        else:
            raise ValueError(f"Unsupported binary type: {self.binary_type}")
    
    def _extract_raw_binary(self) -> bytes:
        with open(self.filepath, 'rb') as f:
            content = f.read()
        logger.info(f"Extracted raw binary: {len(content)} bytes")
        return content
    
    def _extract_elf_text(self) -> bytes:
        text_section = self.binary.get_section(".text")
        if text_section is None:
            raise ValueError("No .text section found in ELF binary.")
        
        content = bytes(text_section.content)
        logger.info(f"Extracted .text section: {len(content)} bytes.")
        return content
    
    def _extract_pe_text(self) -> bytes:
        for section in self.binary.sections:
            if section.name.rstrip('\x00') == ".text":
                content = bytes(section.content)
                logger.info(f"Extracted .text section: {len(content)} bytes")
                return content
        raise ValueError("No .text section found in PE binary.")
    
    def _extract_macho_text(self) -> bytes:
        for section in self.binary.sections:
            if section.name == "__text":
                content = bytes(section.content)
                logger.info(f"Extracted __text section: {len(content)} bytes")
                return content
        raise ValueError("No __text section found in Mach-O binary.")
    
    def extract_all_code(self) -> bytes:
        if self.binary_type == "RAW":
            return self._extract_raw_binary()
        
        all_code = bytearray()
        if self.binary_type == "ELF":
            for section in self.binary.sections:
                # check if section is executable using flags bitmask
                # SHF_EXECINSTR = 0x4
                if section.flags & 0x4:
                    all_code.extend(section.content)
        elif self.binary_type == "PE":
            for section in self.binary.sections:
                # check if section is executable using characteristics bitmask
                # IMAGE_SCN_MEM_EXECUTE = 0x20000000
                if section.characteristics & 0x20000000:
                    all_code.extend(section.content)    
        elif self.binary_type == "MachO":
            for section in self.binary.sections:
                if "__TEXT" in section.segment_name:
                    all_code.extend(section.content)
        
        logger.info(f"Extracted all executable code: {len(all_code)} bytes")
        return bytes(all_code)
    
    def get_metadata(self) -> Dict[str, Any]:
        metadata = {
            'filepath': self.filepath,
            'type': self.binary_type,
        }
        if self.binary_type == "RAW":
            import os
            file_size = os.path.getsize(self.filepath)
            metadata.update({
                'format': 'Raw Binary',
                'size': f"{file_size} bytes",
                'note': 'Treated as raw binary data'
            })
            return metadata
        metadata['format'] = self.binary.format.name if hasattr(self.binary, 'format') else 'Unknown'
        
        if self.binary_type == "ELF":
            metadata.update({
                'architecture': self.binary.header.machine_type.name,
                'entry_point': hex(self.binary.entrypoint),
                'sections': len(list(self.binary.sections))
            })        
        elif self.binary_type == "PE":
            metadata.update({
                'architecture': self.binary.header.machine.name,
                'entry_point': hex(self.binary.optional_header.addressof_entrypoint),
                'sections': len(self.binary.sections)
            })
        return metadata
    
    def extract_section_by_name(self, section_name: str) -> Optional[bytes]:
        try:
            if self.binary_type == "ELF":
                section = self.binary.get_section(section_name)
                if section:
                    return bytes(section.content)
            elif self.binary_type == "PE":
                for section in self.binary.sections:
                    if section.name.rstrip('\x00') == section_name:
                        return bytes(section.content)
            elif self.binary_type == "MachO":
                for section in self.binary.sections:
                    if section.name == section_name:
                        return bytes(section.content)
            logger.warning(f"{section_name} not found")
            return None
        except Exception as e:
            logger.error(f"Error when extracting {section_name}: {e}")
            return None
