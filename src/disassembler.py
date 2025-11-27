import logging
from capstone import *
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class OpcodeColorMapper:
    COLOR_THEMES = {
        'data_move': (100, 150, 255),
        'arithmetic': (100, 255, 150),
        'logic': (150, 255, 200),
        'control_flow': (255, 200, 100),
        'stack': (200, 150, 255),
        'system': (255, 100, 100),
        'crypto': (255, 150, 255),
        'unknown': (128, 128, 128)
    }
    
    def __init__(self, arch=CS_ARCH_X86, mode=CS_MODE_64):
        self.arch = arch
        self.mode = mode
        self.md = Cs(arch, mode)
    
    def disassemble_and_color(self, code: bytes, base_address: int = 0x1000) -> List[Tuple[int, int, int]]:
        colors = []
        byte_index = 0        
        try:
            for instruction in self.md.disasm(code, base_address):
                category = self._categorize_instruction(instruction)
                color = self.COLOR_THEMES.get(category, self.COLOR_THEMES['unknown'])
                for _ in range(instruction.size):
                    if byte_index < len(code):
                        colors.append(color)
                        byte_index += 1
            
            while byte_index < len(code):
                colors.append(self.COLOR_THEMES['unknown'])
                byte_index += 1        
        except CsError as e:
            logger.error(f"Disassembly error: {e}")
            colors = [self.COLOR_THEMES['unknown']] * len(code)
        
        return colors
    
    def _categorize_instruction(self, instruction) -> str:
        mnemonic = instruction.mnemonic.lower()
        if mnemonic in ['mov', 'movabs', 'movsx', 'movzx', 'lea', 'xchg', 
                        'cmov', 'cmova', 'cmovae', 'cmovb', 'cmovbe', 'cmovc',
                        'cmove', 'cmovg', 'cmovge', 'cmovl', 'cmovle', 'cmovna',
                        'cmovnae', 'cmovnb', 'cmovnbe', 'cmovnc', 'cmovne', 'cmovng',
                        'cmovnge', 'cmovnl', 'cmovnle', 'cmovno', 'cmovnp', 'cmovns',
                        'cmovnz', 'cmovo', 'cmovp', 'cmovpe', 'cmovpo', 'cmovs', 'cmovz']:
            return 'data_move'
        elif mnemonic in ['add', 'sub', 'mul', 'imul', 'div', 'idiv', 
                          'inc', 'dec', 'neg', 'adc', 'sbb']:
            return 'arithmetic'
        elif mnemonic in ['and', 'or', 'xor', 'not', 'test', 'cmp',
                          'shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'rcl', 'rcr']:
            return 'logic'
        elif mnemonic in ['jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
                          'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
                          'call', 'ret', 'retn', 'retf', 'loop', 'loope', 'loopne']:
            return 'control_flow'
        elif mnemonic in ['push', 'pop', 'pushf', 'popf', 'pusha', 'popa',
                          'enter', 'leave']:
            return 'stack'
        elif mnemonic in ['syscall', 'sysenter', 'sysexit', 'int', 'iret',
                          'hlt', 'cli', 'sti', 'in', 'out', 'cpuid', 'rdtsc']:
            return 'system'
        elif mnemonic.startswith('aes') or mnemonic.startswith('sha') or \
             mnemonic.startswith('xmm') or mnemonic.startswith('ymm'):
            return 'crypto'
        
        return 'unknown'
    
    def get_instruction_stats(self, code: bytes, base_address: int = 0x1000) -> Dict[str, int]:
        stats = {category: 0 for category in self.COLOR_THEMES.keys()}
        try:
            for instruction in self.md.disasm(code, base_address):
                category = self._categorize_instruction(instruction)
                stats[category] = stats.get(category, 0) + 1
        except CsError as e:
            logger.error(f"Disassembly error: {e}")
        
        return stats


def detect_architecture(binary_type: str, metadata: dict) -> Tuple[int, int]:
    arch_str = metadata.get('architecture', '').lower()
    arch = CS_ARCH_X86
    mode = CS_MODE_64
    
    if 'x86' in arch_str or 'i386' in arch_str or 'i686' in arch_str:
        arch = CS_ARCH_X86
        if '64' in arch_str or 'x86_64' in arch_str or 'amd64' in arch_str:
            mode = CS_MODE_64
        else:
            mode = CS_MODE_32
    elif 'arm' in arch_str:
        arch = CS_ARCH_ARM
        if '64' in arch_str or 'aarch64' in arch_str:
            arch = CS_ARCH_ARM64
            mode = CS_MODE_ARM
        else:
            mode = CS_MODE_ARM
    elif 'mips' in arch_str:
        arch = CS_ARCH_MIPS
        mode = CS_MODE_MIPS64 if '64' in arch_str else CS_MODE_MIPS32
    
    return (arch, mode)
