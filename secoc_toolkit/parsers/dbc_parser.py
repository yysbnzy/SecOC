"""DBC Parser - Parse Vector CAN DBC files for SecOC signal layout."""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DBCSignal:
    """DBC Signal definition."""
    name: str
    start_bit: int
    length: int
    byte_order: str  # 'motorola' (0) or 'intel' (1)
    is_signed: bool
    factor: float
    offset: float
    min_val: float
    max_val: float
    unit: str
    receiver: List[str]
    comment: Optional[str] = None
    
    @classmethod
    def from_dbc_line(cls, line: str) -> Optional['DBCSignal']:
        """Parse DBC signal line."""
        # Example: SG_ FV3BF : 39|4@0+ (1,0) [0|0] ""  VNC
        pattern = r'SG_\s+(\w+)\s*:\s*(\d+)\|(\d+)@(\d+)([+-])\s*\(([^,]+),([^)]+)\)\s*\[([^|]+)\|([^\]]+)\]\s*"([^"]*)"\s*([\w,\s]+)'
        
        match = re.match(pattern, line.strip())
        if not match:
            return None
        
        groups = match.groups()
        return cls(
            name=groups[0],
            start_bit=int(groups[1]),
            length=int(groups[2]),
            byte_order='motorola' if groups[3] == '0' else 'intel',
            is_signed=groups[4] == '-',
            factor=float(groups[5]),
            offset=float(groups[6]),
            min_val=float(groups[7]),
            max_val=float(groups[8]),
            unit=groups[9],
            receiver=[r.strip() for r in groups[10].split(',')]
        )
    
    def extract_from_frame(self, data: bytes) -> int:
        """Extract signal value from CAN frame data."""
        if self.byte_order == 'motorola':
            return self._extract_motorola(data)
        else:
            return self._extract_intel(data)
    
    def _extract_motorola(self, data: bytes) -> int:
        """Extract Motorola format signal."""
        # Motorola: MSB first, big endian within byte
        total_bits = len(data) * 8
        msb = total_bits - 1 - self.start_bit
        lsb = msb - self.length + 1
        
        msb_byte = msb // 8
        msb_bit = msb % 8
        lsb_byte = lsb // 8
        lsb_bit = lsb % 8
        
        value = 0
        for i in range(msb_byte, lsb_byte - 1, -1):
            if i >= len(data):
                continue
            value = (value << 8) | data[i]
        
        # Mask to signal length
        value >>= lsb_bit
        value &= (1 << self.length) - 1
        
        return value
    
    def _extract_intel(self, data: bytes) -> int:
        """Extract Intel format signal."""
        value = 0
        for i in range(self.length):
            bit = self.start_bit + i
            byte_idx = bit // 8
            bit_idx = bit % 8
            
            if byte_idx < len(data) and (data[byte_idx] >> bit_idx) & 1:
                value |= (1 << i)
        
        return value
    
    def pack_into_frame(self, value: int, data: bytearray) -> None:
        """Pack signal value into CAN frame data."""
        if self.byte_order == 'motorola':
            self._pack_motorola(value, data)
        else:
            self._pack_intel(value, data)
    
    def _pack_motorola(self, value: int, data: bytearray) -> None:
        """Pack Motorola format signal."""
        total_bits = len(data) * 8
        msb = total_bits - 1 - self.start_bit
        lsb = msb - self.length + 1
        
        msb_byte = msb // 8
        lsb_byte = lsb // 8
        lsb_bit = lsb % 8
        
        # Clear existing bits
        for i in range(msb_byte, lsb_byte - 1, -1):
            if i < len(data):
                data[i] = 0
        
        # Pack value
        value &= (1 << self.length) - 1
        value <<= lsb_bit
        
        for i in range(msb_byte, lsb_byte - 1, -1):
            if i < len(data):
                data[i] |= (value >> ((msb_byte - i) * 8)) & 0xFF
    
    def _pack_intel(self, value: int, data: bytearray) -> None:
        """Pack Intel format signal."""
        value &= (1 << self.length) - 1
        
        for i in range(self.length):
            bit = self.start_bit + i
            byte_idx = bit // 8
            bit_idx = bit % 8
            
            if byte_idx < len(data):
                if (value >> i) & 1:
                    data[byte_idx] |= (1 << bit_idx)
                else:
                    data[byte_idx] &= ~(1 << bit_idx)


@dataclass
class DBCMessage:
    """DBC Message definition."""
    can_id: int
    name: str
    dlc: int
    sender: str
    signals: Dict[str, DBCSignal]
    comment: Optional[str] = None
    
    @classmethod
    def from_dbc_line(cls, line: str) -> Optional['DBCMessage']:
        """Parse DBC message line."""
        # Example: BO_ 959 ECT1G01: 8 CGW
        pattern = r'BO_\s+(\d+)\s+(\w+)\s*:\s*(\d+)\s+(\w+)'
        
        match = re.match(pattern, line.strip())
        if not match:
            return None
        
        groups = match.groups()
        return cls(
            can_id=int(groups[0]),
            name=groups[1],
            dlc=int(groups[2]),
            sender=groups[3],
            signals={}
        )
    
    def pack_frame(self, signal_values: Dict[str, int]) -> bytes:
        """Pack signal values into CAN frame."""
        data = bytearray(self.dlc)
        
        for sig_name, value in signal_values.items():
            if sig_name in self.signals:
                self.signals[sig_name].pack_into_frame(value, data)
        
        return bytes(data)
    
    def unpack_frame(self, data: bytes) -> Dict[str, int]:
        """Unpack CAN frame into signal values."""
        result = {}
        
        for sig_name, signal in self.signals.items():
            result[sig_name] = signal.extract_from_frame(data)
        
        return result


class DBCParser:
    """Vector CAN DBC file parser."""
    
    def __init__(self):
        self.messages: Dict[int, DBCMessage] = {}  # by CAN ID
        self.messages_by_name: Dict[str, DBCMessage] = {}  # by name
        self.nodes: List[str] = []
        self.version: str = ""
    
    def parse_file(self, filepath: str) -> bool:
        """Parse DBC file."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.parse_content(content)
        except Exception as e:
            logger.error(f"Failed to parse DBC file: {e}")
            return False
    
    def parse_content(self, content: str) -> bool:
        """Parse DBC content string."""
        lines = content.split('\n')
        
        current_msg: Optional[DBCMessage] = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            # Version
            if line.startswith('VERSION'):
                self.version = line.split('"')[1] if '"' in line else ""
            
            # Nodes
            elif line.startswith('BU_:'):
                self.nodes = line.split()[1:]
            
            # Message
            elif line.startswith('BO_'):
                msg = DBCMessage.from_dbc_line(line)
                if msg:
                    current_msg = msg
                    self.messages[msg.can_id] = msg
                    self.messages_by_name[msg.name] = msg
            
            # Signal
            elif line.startswith('SG_') and current_msg:
                sig = DBCSignal.from_dbc_line(line)
                if sig:
                    current_msg.signals[sig.name] = sig
            
            # Comments
            elif line.startswith('CM_ BO_'):
                # Message comment
                match = re.match(r'CM_\s+BO_\s+(\d+)\s+"([^"]+)"', line)
                if match:
                    msg_id = int(match.group(1))
                    if msg_id in self.messages:
                        self.messages[msg_id].comment = match.group(2)
            
            elif line.startswith('CM_ SG_'):
                # Signal comment
                match = re.match(r'CM_\s+SG_\s+(\d+)\s+(\w+)\s+"([^"]+)"', line)
                if match:
                    msg_id = int(match.group(1))
                    sig_name = match.group(2)
                    if msg_id in self.messages and sig_name in self.messages[msg_id].signals:
                        self.messages[msg_id].signals[sig_name].comment = match.group(3)
        
        logger.info(f"Parsed DBC: {len(self.messages)} messages, "
                   f"{sum(len(m.signals) for m in self.messages.values())} signals")
        return True
    
    def get_message(self, can_id: int) -> Optional[DBCMessage]:
        """Get message by CAN ID."""
        return self.messages.get(can_id)
    
    def get_message_by_name(self, name: str) -> Optional[DBCMessage]:
        """Get message by name."""
        return self.messages_by_name.get(name)
    
    def get_signal(self, msg_id: int, sig_name: str) -> Optional[DBCSignal]:
        """Get signal definition."""
        msg = self.messages.get(msg_id)
        if msg:
            return msg.signals.get(sig_name)
        return None
    
    def get_secoc_messages(self) -> Dict[int, DBCMessage]:
        """Get messages with SecOC signals (FV/KZK)."""
        result = {}
        for msg_id, msg in self.messages.items():
            has_secoc = any('FV' in s or 'KZK' in s for s in msg.signals)
            if has_secoc:
                result[msg_id] = msg
        return result
    
    def to_yaml_config(self) -> Dict:
        """Convert to YAML configuration format."""
        config = {
            'vehicle': {
                'name': 'DBC_Imported',
                'network': 'CAN1',
                'baudrate': 500000
            },
            'secoc': {
                'messages': []
            },
            'freshness': {
                'trip_counter_bits': 16,
                'reset_counter_bits': 20,
                'message_counter_bits': 4,
                'sync_period': 0.1,
                'trip_update_factor': 65535
            }
        }
        
        for msg_id, msg in self.messages.items():
            msg_config = {
                'name': msg.name,
                'can_id': msg_id,
                'dlc': msg.dlc,
                'aes_key': '11111111111111111111111111111111',  # Default
                'cmac_bits': 28,
                'freshness_bits': 4,
                'signals': []
            }
            
            for sig_name, sig in msg.signals.items():
                sig_config = {
                    'name': sig_name,
                    'start_bit': sig.start_bit,
                    'length': sig.length,
                    'byte_order': sig.byte_order
                }
                msg_config['signals'].append(sig_config)
            
            config['secoc']['messages'].append(msg_config)
        
        return config
    
    def __repr__(self):
        return f"DBCParser(messages={len(self.messages)}, nodes={self.nodes})"


# SecOC-specific helpers
class SecOCDbcHelper:
    """Helper for SecOC-specific DBC operations."""
    
    def __init__(self, parser: DBCParser):
        self.parser = parser
    
    def get_freshness_signal(self, msg_id: int) -> Optional[DBCSignal]:
        """Get Freshness Value signal."""
        msg = self.parser.get_message(msg_id)
        if not msg:
            return None
        
        for name, sig in msg.signals.items():
            if name.startswith('FV'):
                return sig
        return None
    
    def get_cmac_signal(self, msg_id: int) -> Optional[DBCSignal]:
        """Get CMAC (KZK) signal."""
        msg = self.parser.get_message(msg_id)
        if not msg:
            return None
        
        for name, sig in msg.signals.items():
            if name.startswith('KZK'):
                return sig
        return None
    
    def get_secoc_payload_signals(self, msg_id: int) -> List[DBCSignal]:
        """Get non-SecOC payload signals (for data extraction)."""
        msg = self.parser.get_message(msg_id)
        if not msg:
            return []
        
        return [sig for name, sig in msg.signals.items() 
                if not name.startswith(('FV', 'KZK'))]
    
    def verify_frame(self, msg_id: int, data: bytes, 
                     engine: 'SecOCEngine' = None) -> bool:
        """Verify SecOC frame using DBC layout."""
        msg = self.parser.get_message(msg_id)
        if not msg:
            return False
        
        # Extract FV and KZK
        fv_sig = self.get_freshness_signal(msg_id)
        cmac_sig = self.get_cmac_signal(msg_id)
        
        if not fv_sig or not cmac_sig:
            return False
        
        fv = fv_sig.extract_from_frame(data)
        cmac = cmac_sig.extract_from_frame(data)
        
        if engine:
            # TODO: Verify CMAC using engine
            pass
        
        return True


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Test with Toyota DBC
    dbc_path = r'C:\mnt\agents\Toyota_SecOC_Demo\Database\GlobalCAN_gncanvehcs-891W-1202-a-BITASSIGN(MET)_DSV240521 - liudong.dbc'
    
    parser = DBCParser()
    if parser.parse_file(dbc_path):
        print(f"Parsed {len(parser.messages)} messages")
        
        # Show SecOC messages
        secoc_msgs = parser.get_secoc_messages()
        print(f"\nSecOC messages: {len(secoc_msgs)}")
        for msg_id, msg in secoc_msgs.items():
            print(f"  0x{msg_id:03X} {msg.name}:")
            for sig_name, sig in msg.signals.items():
                print(f"    {sig_name}: bit {sig.start_bit}, len {sig.length}, {sig.byte_order}")
        
        # Test pack/unpack
        if 0x3BF in parser.messages:
            msg = parser.messages[0x3BF]
            test_data = msg.pack_frame({
                'FV3BF': 0x05,
                'KZK3BF': 0x1234567
            })
            print(f"\nPacked ECT1G01: {test_data.hex()}")
            
            unpacked = msg.unpack_frame(test_data)
            print(f"Unpacked: {unpacked}")
    else:
        print("Failed to parse DBC")
