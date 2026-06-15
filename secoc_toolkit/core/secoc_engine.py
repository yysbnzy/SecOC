"""SecOC Engine - Core message authentication module."""

from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from typing import Dict, Optional, Tuple
import struct
import logging

logger = logging.getLogger(__name__)


class SecOCEngine:
    """
    SecOC (Secure Onboard Communication) message authentication engine.
    
    Implements AUTOSAR SecOC standard:
    - Freshness Value (FV) management
    - AES-128-CMAC computation
    - Authenticator truncation (configurable bit-length)
    - PayloadData construction per DBC definition
    
    Compatible with Toyota SecOC Demo and other OEM implementations.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize SecOC engine from configuration.
        
        Args:
            config: Dictionary with keys:
                - aes_key: Hex string of 16-byte AES key
                - data_id: CAN message ID (e.g., 0x3BF)
                - cmac_bits: Authentication tag length (default: 28)
                - freshness_bits: Freshness value length (default: 4)
                - payload_data_length: Payload data length for CMAC (default: 12)
                - protocol_flag: Protocol identifier byte (default: 0x20)
        """
        aes_key_hex = config.get('aes_key', '11111111111111111111111111111111')
        self.aes_key = bytes.fromhex(aes_key_hex)
        
        if len(self.aes_key) != 16:
            raise ValueError(f"AES key must be 16 bytes, got {len(self.aes_key)}")
        
        self.data_id = config.get('data_id', 0x3BF)
        self.cmac_bits = config.get('cmac_bits', 28)
        self.freshness_bits = config.get('freshness_bits', 4)
        self.payload_data_length = config.get('payload_data_length', 12)
        self.protocol_flag = config.get('protocol_flag', 0x20)
        
        # CMAC mask based on bit length
        self.cmac_mask = (1 << self.cmac_bits) - 1
        
        logger.info(f"SecOC Engine initialized: data_id=0x{self.data_id:03X}, "
                    f"cmac_bits={self.cmac_bits}, freshness_bits={self.freshness_bits}")
    
    def build_payload(self, trip_counter: int, reset_counter: int, 
                      message_counter: int) -> bytes:
        """
        Construct PayloadData for CMAC computation.
        
        PayloadData format (12 bytes):
        [0-1]  Data ID (MSG ID) - Big Endian
        [2]    Protocol flag
        [3-4]  Reserved (0x00)
        [5-6]  TripCounter (16-bit, big endian)
        [7-9]  ResetCounter (20-bit) + MessageCounter (high 4-bit)
        [10]   MessageCounter (low 4-bit) + ResetCounter (low 2-bit)
        [11]   Reserved (0x00)
        
        Args:
            trip_counter: 16-bit trip counter
            reset_counter: 20-bit reset counter
            message_counter: 4 or 8-bit message counter
            
        Returns:
            12-byte PayloadData
        """
        payload = bytearray(12)
        
        # [0-1] Data ID (big endian)
        payload[0] = (self.data_id >> 8) & 0xFF
        payload[1] = self.data_id & 0xFF
        
        # [2] Protocol flag
        payload[2] = self.protocol_flag
        
        # [3-4] Reserved
        payload[3] = 0x00
        payload[4] = 0x00
        
        # [5-6] TripCounter (16-bit, big endian)
        payload[5] = (trip_counter >> 8) & 0xFF
        payload[6] = trip_counter & 0xFF
        
        # [7-9] ResetCounter (20-bit) + MessageCounter (high 4-bit)
        payload[7] = (reset_counter >> 12) & 0xFF
        payload[8] = (reset_counter >> 4) & 0xFF
        payload[9] = ((reset_counter & 0x0F) << 4) | ((message_counter >> 4) & 0x0F)
        
        # [10] MessageCounter (low 4-bit) + ResetCounter (low 2-bit)
        payload[10] = ((message_counter & 0x0F) << 4) | ((reset_counter & 0x03) << 2)
        
        # [11] Reserved
        payload[11] = 0x00
        
        return bytes(payload)
    
    def compute_cmac(self, payload: bytes) -> int:
        """
        Compute AES-128-CMAC and truncate to configured bit length.
        
        Args:
            payload: PayloadData bytes (typically 12 bytes)
            
        Returns:
            Truncated CMAC value (integer)
        """
        # Compute full AES-CMAC (16 bytes / 128-bit)
        cobj = CMAC.new(self.aes_key, ciphermod=AES)
        cobj.update(payload)
        full_cmac = cobj.digest()
        
        # Truncate to configured bit length
        # For 28-bit: take high 28 bits of first 4 bytes
        if self.cmac_bits <= 28:
            truncated = (full_cmac[0] << 20) | (full_cmac[1] << 12) | \
                       (full_cmac[2] << 4) | (full_cmac[3] >> 4)
        elif self.cmac_bits <= 32:
            truncated = (full_cmac[0] << 24) | (full_cmac[1] << 16) | \
                       (full_cmac[2] << 8) | full_cmac[3]
        elif self.cmac_bits <= 64:
            truncated = (full_cmac[0] << 56) | (full_cmac[1] << 48) | \
                       (full_cmac[2] << 40) | (full_cmac[3] << 32) | \
                       (full_cmac[4] << 24) | (full_cmac[5] << 16) | \
                       (full_cmac[6] << 8) | full_cmac[7]
        else:
            # Return full 128-bit as two 64-bit integers
            truncated = int.from_bytes(full_cmac[:16], 'big')
        
        return truncated & self.cmac_mask
    
    def build_secoc_frame(self, trip_counter: int, reset_counter: int,
                         message_counter: int, payload_data: bytes) -> Dict:
        """
        Build complete SecOC authenticated frame.
        
        Args:
            trip_counter: Trip counter value
            reset_counter: Reset counter value
            message_counter: Message counter value
            payload_data: Original CAN payload data (before SecOC fields)
            
        Returns:
            Dictionary with:
                - data_id: CAN ID
                - freshness: Freshness value (FV)
                - cmac: Authentication tag (KZK)
                - payload: Auth payload (PayloadData)
                - raw_payload: Original payload data
                - can_data: Final 8-byte CAN frame data
        """
        # Build authentication payload
        auth_payload = self.build_payload(trip_counter, reset_counter, message_counter)
        
        # Compute CMAC
        cmac = self.compute_cmac(auth_payload)
        
        # Build Freshness Value (FV)
        # FV = low 2 bits of MessageCounter + low 2 bits of ResetCounter
        freshness = ((message_counter & 0x03) << 2) | (reset_counter & 0x03)
        
        return {
            'data_id': self.data_id,
            'freshness': freshness,
            'cmac': cmac,
            'payload': auth_payload,
            'raw_payload': payload_data,
            'can_data': None  # To be packed by CAN frame builder
        }
    
    def verify_frame(self, trip_counter: int, reset_counter: int,
                     message_counter: int, received_cmac: int) -> bool:
        """
        Verify received SecOC frame by recomputing CMAC.
        
        Args:
            trip_counter: Expected trip counter
            reset_counter: Expected reset counter
            message_counter: Expected message counter
            received_cmac: Received authentication tag
            
        Returns:
            True if CMAC matches, False otherwise
        """
        payload = self.build_payload(trip_counter, reset_counter, message_counter)
        expected_cmac = self.compute_cmac(payload)
        
        return expected_cmac == received_cmac
    
    def pack_can_frame(self, raw_data: bytes, freshness: int, cmac: int,
                       fv_start_bit: int = 39, cmac_start_bit: int = 35,
                       signal_length: int = 8) -> bytes:
        """
        Pack SecOC fields into CAN frame according to DBC layout.
        
        Default layout (Toyota ECT1G01/ENG1G02):
        - FV: bit 39-42 (4 bits)
        - KZK: bit 35-62 (28 bits)
        
        Args:
            raw_data: Raw payload data
            freshness: Freshness value
            cmac: Truncated CMAC value
            fv_start_bit: Start bit of FV field in CAN frame
            cmac_start_bit: Start bit of KZK/CMAC field
            signal_length: Total CAN frame length (bytes)
            
        Returns:
            Packed CAN frame data (8 bytes)
        """
        frame = bytearray(signal_length)
        
        # Fill raw data (if provided)
        if raw_data:
            data_len = min(len(raw_data), signal_length)
            frame[:data_len] = raw_data[:data_len]
        
        # Pack FV into specified bit position (Motorola format, big endian)
        # FV at bit 39-42 (4 bits)
        byte_pos = (63 - fv_start_bit) // 8
        bit_offset = (63 - fv_start_bit) % 8
        
        if byte_pos < signal_length:
            # Clear FV bits and set new value
            mask = ~(0x0F << (bit_offset - 3)) & 0xFF
            frame[byte_pos] = (frame[byte_pos] & mask) | ((freshness & 0x0F) << (bit_offset - 3))
        
        # Pack CMAC into specified bit position
        # KZK at bit 35-62 (28 bits)
        cmac_bytes = [
            (cmac >> 20) & 0xFF,
            (cmac >> 12) & 0xFF,
            (cmac >> 4) & 0xFF,
            (cmac & 0x0F) << 4
        ]
        
        cmac_byte_pos = (63 - cmac_start_bit) // 8
        if cmac_byte_pos + 3 < signal_length:
            frame[cmac_byte_pos] = cmac_bytes[0]
            frame[cmac_byte_pos + 1] = cmac_bytes[1]
            frame[cmac_byte_pos + 2] = cmac_bytes[2]
            frame[cmac_byte_pos + 3] = (frame[cmac_byte_pos + 3] & 0x0F) | cmac_bytes[3]
        
        return bytes(frame)


def kdf(master_key: bytes, salt: bytes) -> bytes:
    """
    Key Derivation Function (KDF) from Toyota SecOC Demo.
    
    Based on AES-ECB iteration with XOR mixing.
    
    Args:
        master_key: 16-byte master key
        salt: 16-byte salt value
        
    Returns:
        16-byte derived key
    """
    if len(master_key) != 16 or len(salt) != 16:
        raise ValueError("Master key and salt must be 16 bytes each")
    
    # Step 1: AES_ECB(0x00...00, MK)
    tmp_key = bytes(16)
    cipher1 = AES.new(tmp_key, AES.MODE_ECB)
    tmp_key_e = cipher1.encrypt(master_key)
    
    # Step 2: XOR with MK
    tmp_key_e_xor = bytes(a ^ b for a, b in zip(tmp_key_e, master_key))
    
    # Step 3: AES_ECB(TmpKey_e_xor, Salt)
    cipher2 = AES.new(tmp_key_e_xor, AES.MODE_ECB)
    tmp_key_e2 = cipher2.encrypt(salt)
    
    # Step 4: XOR mixing
    xor1 = bytes(a ^ b for a, b in zip(tmp_key_e_xor, tmp_key_e2))
    xor2 = bytes(a ^ b for a, b in zip(salt, xor1))
    
    return xor2


def cmac_cal(secret: bytes, uid: str, challenge: str) -> Tuple[str, str]:
    """
    ICUS (Immobilizer Control Unit Security) verification.
    
    Computes two CMAC variants:
    - ICUSB: CMAC(key, CHALLENGE || UID || 0x80)
    - ICUSC: CMAC(key, CHALLENGE || UID)
    
    Args:
        secret: 16-byte derived key
        uid: 30-character HEX string (15 bytes)
        challenge: 32-character HEX string (16 bytes)
        
    Returns:
        Tuple of (ICUSB, ICUSC) as hex strings
    """
    uid_bytes = bytes.fromhex(uid)
    uid_padded = uid_bytes + b'\x80'
    challenge_bytes = bytes.fromhex(challenge)
    
    # ICUSB: CMAC(key, CHALLENGE || UID || 0x80)
    cobj_b = CMAC.new(secret, ciphermod=AES)
    cobj_b.update(challenge_bytes)
    cobj_b.update(uid_padded)
    icusb = cobj_b.hexdigest()
    
    # ICUSC: CMAC(key, CHALLENGE || UID)
    cobj_c = CMAC.new(secret, ciphermod=AES)
    cobj_c.update(challenge_bytes)
    cobj_c.update(uid_bytes)
    icusc = cobj_c.hexdigest()
    
    return (icusb, icusc)


if __name__ == '__main__':
    # Quick test
    engine = SecOCEngine({
        'aes_key': '11111111111111111111111111111111',
        'data_id': 0x3BF,
        'cmac_bits': 28
    })
    
    payload = engine.build_payload(0x00, 0x01, 0x02)
    cmac = engine.compute_cmac(payload)
    print(f"Payload: {payload.hex()}")
    print(f"CMAC (28-bit): 0x{cmac:07X}")
    
    # KDF test
    mk = bytes.fromhex('11111111111111111111111111111111')
    salt = bytes.fromhex('010153484500800000000000000000b0')
    derived = kdf(mk, salt)
    print(f"Derived Key: {derived.hex()}")
