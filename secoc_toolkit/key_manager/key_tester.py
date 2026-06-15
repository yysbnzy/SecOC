"""KeyTester - KZK Key Distribution and Verification Module."""

import logging
import time
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass

from ..core.secoc_engine import SecOCEngine
from ..can_drivers.can_interface import CANMessage, CANDriverInterface

logger = logging.getLogger(__name__)


@dataclass
class KZKTestResult:
    """KZK test execution result."""
    test_name: str
    success: bool
    kzk_id: int
    kzk_usage: int
    key_data: bytes
    details: Dict
    duration: float


class KeyTester:
    """
    KeyTester - KZK (Key Zum Kommunikation) Key Management.
    
    Equivalent to KeyTester.can from Toyota Demo.
    
    KZK Distribution Messages (0x013-0x01A):
    - KZKSEND1-8: Distribute keys to various ECUs
    
    KZK Verification Messages (0x01B-0x01F):
    - KZKINFO: Key ID + Usage info
    - KZKVERI1-4: Key verification data
    
    KZK Structure:
    - KZKID (1 byte): Key identifier
    - KZKUSAGE (1 byte): Key usage flags
    - Key data (variable): Actual key material
    """
    
    # KZK CAN IDs from Toyota Demo
    KZK_SEND_IDS = [0x013, 0x014, 0x015, 0x016, 0x017, 0x018, 0x019, 0x01A]
    KZK_VERI_IDS = [0x01B, 0x01C, 0x01D, 0x01E, 0x01F]
    KZK_INFO_ID = 0x01B
    
    # Key usage flags (from Demo)
    KZK_USAGE_VERIFY = 0x01
    KZK_USAGE_UPDATE = 0x02
    KZK_USAGE_MASTER = 0x04
    KZK_USAGE_BOOT = 0x08
    
    def __init__(self, can_driver: CANDriverInterface):
        self.can_driver = can_driver
        self._keys: Dict[int, bytes] = {}  # key_id -> key_data
        self._key_usage: Dict[int, int] = {}  # key_id -> usage_flags
        self._verification_results: List[KZKTestResult] = []
    
    def add_key(self, key_id: int, key_data: bytes, usage: int = 0x01) -> None:
        """
        Add a key to the key store.
        
        Args:
            key_id: Key identifier (matches SHE slot)
            key_data: Key material (16 bytes for AES-128)
            usage: Usage flags
        """
        if len(key_data) != 16:
            logger.warning(f"Key data should be 16 bytes, got {len(key_data)}")
        
        self._keys[key_id] = key_data
        self._key_usage[key_id] = usage
        logger.info(f"Added key {key_id}: usage=0x{usage:02X}, len={len(key_data)}")
    
    def distribute_key(self, key_id: int, target_id: int) -> bool:
        """
        Distribute key to target ECU.
        
        Args:
            key_id: Key to distribute
            target_id: Target ECU (0-7 for KZKSEND1-8)
            
        Returns:
            True if sent successfully
        """
        if key_id not in self._keys:
            logger.error(f"Key {key_id} not found")
            return False
        
        if target_id < 0 or target_id >= len(self.KZK_SEND_IDS):
            logger.error(f"Invalid target ID: {target_id}")
            return False
        
        can_id = self.KZK_SEND_IDS[target_id]
        key_data = self._keys[key_id]
        usage = self._key_usage.get(key_id, 0x01)
        
        # Pack KZK data: [KZKID(1B) | KZKUSAGE(1B) | KeyData(16B)] = 18 bytes
        # Split across multiple CAN frames if needed
        frame_data = bytes([key_id, usage]) + key_data[:6]  # First 8 bytes
        
        msg = CANMessage(arbitration_id=can_id, data=frame_data)
        
        if self.can_driver.send(msg):
            logger.info(f"Distributed key {key_id} to target {target_id} (0x{can_id:03X})")
            return True
        
        return False
    
    def distribute_all_keys(self) -> Dict[int, bool]:
        """
        Distribute all stored keys.
        
        Returns:
            Dictionary of key_id -> success
        """
        results = {}
        
        for i, (key_id, key_data) in enumerate(self._keys.items()):
            target_id = i % len(self.KZK_SEND_IDS)
            success = self.distribute_key(key_id, target_id)
            results[key_id] = success
            
            if not success:
                logger.warning(f"Failed to distribute key {key_id}")
        
        return results
    
    def send_key_info(self, key_id: int) -> bool:
        """
        Send KZK information (ID + Usage).
        
        Args:
            key_id: Key identifier
            
        Returns:
            True if sent successfully
        """
        if key_id not in self._keys:
            logger.error(f"Key {key_id} not found")
            return False
        
        usage = self._key_usage.get(key_id, 0x01)
        
        # KZKINFO: [KZKID(1B) | KZKUSAGE(1B) | Reserved(6B)]
        frame_data = bytes([key_id, usage]) + b'\x00' * 6
        
        msg = CANMessage(arbitration_id=self.KZK_INFO_ID, data=frame_data)
        
        if self.can_driver.send(msg):
            logger.info(f"Sent KZK info for key {key_id}")
            return True
        
        return False
    
    def verify_key(self, key_id: int, verification_data: bytes) -> KZKTestResult:
        """
        Verify key by sending verification request.
        
        Args:
            key_id: Key to verify
            verification_data: Verification challenge data
            
        Returns:
            KZKTestResult
        """
        start_time = time.time()
        
        if key_id not in self._keys:
            return KZKTestResult(
                test_name='KeyVerification',
                success=False,
                kzk_id=key_id,
                kzk_usage=0,
                key_data=b'',
                details={'error': 'Key not found'},
                duration=time.time() - start_time
            )
        
        key_data = self._keys[key_id]
        usage = self._key_usage.get(key_id, 0x01)
        
        # Send verification data
        # KZKVERI1-4: [KeyData(16B) | Verification(8B)] = 24 bytes, split across 3 frames
        # Simplified: send hash/key identifier
        import hashlib
        key_hash = hashlib.sha256(key_data).digest()[:8]
        
        frame_data = bytes([key_id, usage]) + key_hash
        
        msg = CANMessage(arbitration_id=self.KZK_VERI_IDS[0], data=frame_data)
        sent = self.can_driver.send(msg)
        
        duration = time.time() - start_time
        
        result = KZKTestResult(
            test_name='KeyVerification',
            success=sent,
            kzk_id=key_id,
            kzk_usage=usage,
            key_data=key_data,
            details={
                'key_hash': key_hash.hex(),
                'verification_sent': sent,
                'frame_data': frame_data.hex()
            },
            duration=duration
        )
        
        self._verification_results.append(result)
        return result
    
    def verify_all_keys(self) -> List[KZKTestResult]:
        """Verify all stored keys."""
        results = []
        
        for key_id in self._keys:
            result = self.verify_key(key_id, b'\x00' * 8)
            results.append(result)
        
        return results
    
    def inject_key(self, target_id: int, forged_key: bytes, 
                   key_id: int = 0x04, usage: int = 0x01) -> bool:
        """
        Test key injection attack.
        
        Args:
            target_id: Target ECU
            forged_key: Forged key data
            key_id: Key ID to claim
            usage: Usage flags
            
        Returns:
            True if injection sent
        """
        logger.warning(f"ATTACK: Injecting forged key {key_id} to target {target_id}")
        
        # Temporarily add forged key
        original_key = self._keys.get(key_id)
        self._keys[key_id] = forged_key
        self._key_usage[key_id] = usage
        
        try:
            return self.distribute_key(key_id, target_id)
        finally:
            # Restore original key
            if original_key:
                self._keys[key_id] = original_key
            else:
                del self._keys[key_id]
    
    def get_key_status(self) -> Dict:
        """Get current key store status."""
        return {
            'total_keys': len(self._keys),
            'keys': {
                kid: {
                    'usage': f"0x{use:02X}",
                    'length': len(self._keys[kid])
                }
                for kid, use in self._key_usage.items()
            },
            'verification_count': len(self._verification_results)
        }
    
    def __repr__(self):
        return f"KeyTester(keys={len(self._keys)}, verifications={len(self._verification_results)})"


class KeyTesterAttacks:
    """Key-related attack vectors."""
    
    def __init__(self, key_tester: KeyTester):
        self.kt = key_tester
    
    def key_injection_test(self, target_id: int) -> Dict:
        """
        Test key injection vulnerability.
        
        Attempts to inject a forged key and observe if target ECU accepts it.
        """
        forged_key = bytes([0xFF] * 16)  # Obvious forged key
        
        logger.info(f"Testing key injection to target {target_id}")
        
        sent = self.kt.inject_key(target_id, forged_key)
        
        return {
            'attack': 'KeyInjection',
            'target': target_id,
            'forged_key': forged_key.hex(),
            'sent': sent,
            'expected': 'REJECTED - Key authentication should fail',
            'risk': 'HIGH'
        }
    
    def key_replay_test(self, key_id: int, target_id: int) -> Dict:
        """
        Test key replay vulnerability.
        
        Attempts to replay a legitimate key update multiple times.
        """
        logger.info(f"Testing key replay for key {key_id}")
        
        results = []
        for i in range(3):
            success = self.kt.distribute_key(key_id, target_id)
            results.append({'attempt': i + 1, 'success': success})
        
        return {
            'attack': 'KeyReplay',
            'key_id': key_id,
            'target': target_id,
            'attempts': results,
            'expected': 'REJECTED after first successful update',
            'risk': 'MEDIUM'
        }
    
    def key_extraction_test(self) -> Dict:
        """
        Test key extraction vulnerability.
        
        Checks if keys are stored securely (not plaintext in memory).
        """
        keys_exposed = {}
        
        for key_id, key_data in self.kt._keys.items():
            # Check for weak/obvious keys
            is_weak = (
                key_data == bytes([0x00] * 16) or
                key_data == bytes([0xFF] * 16) or
                key_data == bytes([0x11] * 16) or
                len(set(key_data)) == 1  # All same byte
            )
            
            keys_exposed[key_id] = {
                'weak': is_weak,
                'pattern': 'repetitive' if len(set(key_data)) == 1 else 'random',
                'exposed': True  # In memory, could be dumped
            }
        
        return {
            'attack': 'KeyExtraction',
            'keys_analyzed': len(self.kt._keys),
            'weak_keys_found': sum(1 for k in keys_exposed.values() if k['weak']),
            'details': keys_exposed,
            'expected': 'Keys should be in HSM/TPM, not software memory',
            'risk': 'CRITICAL'
        }


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("KeyTester Module loaded")
    print("Features:")
    print("  - Key distribution (KZKSEND1-8)")
    print("  - Key verification (KZKVERI1-4)")
    print("  - Key info broadcast (KZKINFO)")
    print("  - Key injection attack test")
    print("  - Key replay attack test")
    print("  - Key extraction vulnerability test")
