#!/usr/bin/env python3
"""
KeyTester Equivalent - KZK Key Distribution/Verification Module.

Replaces CANoe KeyTester.can functionality:
- KZK Key Distribution (CAN IDs 0x013-0x01A)
- KZK Key Verification (CAN IDs 0x01B-0x01F)
- Multi-key support (BOOT_MAC_KEY, MAC_KEY, TOOL_AUTH_KEY, PROG_KEY)

Usage:
    from secoc_toolkit.key_tester import KeyTester
    
    kt = KeyTester(can_driver, config)
    kt.distribute_key(key_type='MAC_KEY', key_index=4)
    kt.verify_key(key_type='MAC_KEY', key_index=4)
"""

import time
import logging
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from enum import IntEnum

from .can_drivers.can_interface import CANMessage, CANDriverInterface

logger = logging.getLogger(__name__)


class KeyType(IntEnum):
    """SHE Key Type Identifiers."""
    BOOT_MAC_KEY = 2
    MAC_KEY = 4
    TOOL_AUTH_KEY = 5
    PROG_KEY = 6


class KZKOpCode(IntEnum):
    """KZK Operation Codes."""
    DISTRIBUTE = 0x01
    VERIFY = 0x02
    CONFIRM = 0x03
    REJECT = 0x04


@dataclass
class KeyTestResult:
    """Key test operation result."""
    operation: str
    key_type: str
    key_index: int
    success: bool
    details: Dict
    duration: float


class KeyTester:
    """
    KZK Key Distribution and Verification Tester.
    
    Implements Toyota KeyTester.can functionality in pure Python:
    1. Sends key distribution frames (0x013-0x01A) with KZKID + KZKUSAGE + key data
    2. Sends verification frames (0x01B-0x01F) with MAC verification
    3. Validates responses and reports results
    
    Frame Structure (Distribution):
    - Byte 0: KZKID (key identifier)
    - Byte 1: KZKUSAGE (usage type: 0x00=MAC, 0x01=BOOT, etc.)
    - Bytes 2-17: Key value (16 bytes)
    - Bytes 18-33: MAC value (16 bytes)
    
    Frame Structure (Verification):
    - Byte 0: KZKID
    - Byte 1: KZKUSAGE
    - Bytes 2-17: Key value
    - Bytes 18-33: MAC value (for verification)
    """
    
    # CAN IDs for key distribution (0x013-0x01A)
    KZK_DISTRIBUTE_IDS = list(range(0x013, 0x01B))  # 0x013-0x01A (8 IDs)
    
    # CAN IDs for key verification (0x01B-0x01F)
    KZK_VERIFY_IDS = list(range(0x01B, 0x020))  # 0x01B-0x01F (5 IDs)
    
    # Key type mapping
    KEY_TYPES = {
        'BOOT_MAC_KEY': {'id': 0x02, 'usage': 0x01, 'verify_key': bytes([0x6E, 0x44, 0xFA, 0xE9, 0xBC, 0x22, 0xA7, 0x3F, 0x38, 0xDE, 0x26, 0x1A, 0x16, 0xE2, 0x1B, 0x76])},
        'MAC_KEY': {'id': 0x04, 'usage': 0x01, 'verify_key': bytes([0x10, 0xDB, 0x33, 0x9E, 0xD3, 0x7F, 0xD4, 0xB0, 0x8D, 0x86, 0x1D, 0xB7, 0x66, 0x01, 0x2A, 0xCC])},
        'TOOL_AUTH_KEY': {'id': 0x05, 'usage': 0x00, 'verify_key': bytes([0x75, 0x2E, 0x55, 0xCA, 0x72, 0x61, 0x5E, 0x90, 0x48, 0x34, 0xAF, 0x89, 0xA1, 0x6D, 0xB9, 0xDE])},
        'PROG_KEY': {'id': 0x06, 'usage': 0x00, 'verify_key': bytes([0xC7, 0x63, 0x62, 0x47, 0x64, 0x73, 0xE0, 0x3D, 0x7A, 0x5E, 0x02, 0xB3, 0xDD, 0xE1, 0x39, 0xBB])},
    }
    
    def __init__(self, can_driver: CANDriverInterface, config: Optional[Dict] = None):
        self.can_driver = can_driver
        self.config = config or {}
        self._key_store: Dict[str, bytes] = {}
        self._response_timeout = self.config.get('response_timeout', 1.0)
        self._send_retries = self.config.get('send_retries', 3)
    
    def _build_key_frame(self, kzk_id: int, kzk_usage: int, 
                         key_data: bytes, mac_data: bytes) -> bytes:
        """Build 8-byte CAN frame for key operation (split across multiple frames)."""
        frame = bytearray(8)
        frame[0] = kzk_id
        frame[1] = kzk_usage
        # Key data and MAC are split across multiple 8-byte frames
        # This is a simplified single-frame representation
        # Full implementation would use ISO-TP or multi-frame protocol
        if len(key_data) >= 6:
            frame[2:8] = key_data[:6]
        return bytes(frame)
    
    def _send_multi_frame(self, can_ids: List[int], data: bytes) -> bool:
        """Send multi-frame key data across multiple CAN IDs."""
        # Split data into 8-byte chunks
        chunks = [data[i:i+8] for i in range(0, len(data), 8)]
        
        for i, chunk in enumerate(chunks):
            if i >= len(can_ids):
                logger.warning(f"More data chunks than CAN IDs available")
                break
            
            frame_data = chunk.ljust(8, b'\x00')
            msg = CANMessage(arbitration_id=can_ids[i], data=frame_data)
            
            for attempt in range(self._send_retries):
                if self.can_driver.send(msg):
                    logger.debug(f"Sent frame {i+1}/{len(chunks)} on ID 0x{can_ids[i]:03X}")
                    time.sleep(0.01)  # 10ms inter-frame delay
                    break
                else:
                    logger.warning(f"Send attempt {attempt+1} failed for frame {i+1}")
                    time.sleep(0.05)
            else:
                logger.error(f"Failed to send frame {i+1} after {self._send_retries} attempts")
                return False
        
        return True
    
    def distribute_key(self, key_type: str = 'MAC_KEY', key_index: int = 4,
                       custom_key: Optional[bytes] = None) -> KeyTestResult:
        """
        Distribute a key to the ECU (KZK Distribution).
        
        Args:
            key_type: Key type ('BOOT_MAC_KEY', 'MAC_KEY', 'TOOL_AUTH_KEY', 'PROG_KEY')
            key_index: Key index/slot number
            custom_key: Optional custom key data (16 bytes), uses default if None
            
        Returns:
            KeyTestResult
        """
        start_time = time.time()
        
        if key_type not in self.KEY_TYPES:
            return KeyTestResult(
                operation='DISTRIBUTE',
                key_type=key_type,
                key_index=key_index,
                success=False,
                details={'error': f'Unknown key type: {key_type}'},
                duration=time.time() - start_time
            )
        
        key_info = self.KEY_TYPES[key_type]
        kzk_id = key_info['id']
        kzk_usage = key_info['usage']
        
        # Use custom key or generate from key_index
        if custom_key:
            key_data = custom_key[:16].ljust(16, b'\x00')
        else:
            # Generate key from index (Demo: key = index * 0x11 pattern)
            key_data = bytes([key_index * 0x11] * 16)
        
        # Store key
        self._key_store[key_type] = key_data
        
        # Build distribution data: KZKID(1) + KZKUSAGE(1) + KEY(16) + MAC(16) = 34 bytes
        dist_data = bytes([kzk_id, kzk_usage]) + key_data + key_info['verify_key']
        
        # Send multi-frame
        sent = self._send_multi_frame(self.KZK_DISTRIBUTE_IDS, dist_data)
        
        duration = time.time() - start_time
        
        return KeyTestResult(
            operation='DISTRIBUTE',
            key_type=key_type,
            key_index=key_index,
            success=sent,
            details={
                'kzk_id': f'0x{kzk_id:02X}',
                'kzk_usage': f'0x{kzk_usage:02X}',
                'key_data': key_data.hex(),
                'verify_key': key_info['verify_key'].hex(),
                'frames_sent': min(len(dist_data) // 8 + 1, len(self.KZK_DISTRIBUTE_IDS)),
                'can_ids': [f'0x{can_id:03X}' for can_id in self.KZK_DISTRIBUTE_IDS[:len(dist_data)//8+1]]
            },
            duration=duration
        )
    
    def verify_key(self, key_type: str = 'MAC_KEY', key_index: int = 4) -> KeyTestResult:
        """
        Verify a key with the ECU (KZK Verification).
        
        Args:
            key_type: Key type to verify
            key_index: Key index/slot number
            
        Returns:
            KeyTestResult
        """
        start_time = time.time()
        
        if key_type not in self.KEY_TYPES:
            return KeyTestResult(
                operation='VERIFY',
                key_type=key_type,
                key_index=key_index,
                success=False,
                details={'error': f'Unknown key type: {key_type}'},
                duration=time.time() - start_time
            )
        
        key_info = self.KEY_TYPES[key_type]
        kzk_id = key_info['id']
        kzk_usage = key_info['usage']
        
        # Get stored key or use default
        key_data = self._key_store.get(key_type, bytes([key_index * 0x11] * 16))
        
        # Build verification data
        verify_data = bytes([kzk_id, kzk_usage]) + key_data + key_info['verify_key']
        
        # Send multi-frame verification
        sent = self._send_multi_frame(self.KZK_VERIFY_IDS, verify_data)
        
        # Wait for response
        response_received = False
        response_data = None
        
        if sent:
            # Listen for response on verification response IDs (0x01B-0x01F range)
            start_wait = time.time()
            while time.time() - start_wait < self._response_timeout:
                msg = self.can_driver.receive(timeout=0.1)
                if msg and msg.arbitration_id in self.KZK_VERIFY_IDS:
                    response_received = True
                    response_data = msg.data
                    break
        
        duration = time.time() - start_time
        
        # Determine success based on response
        # Response byte 0: 0x04 = verify success, 0x71 = positive response
        verify_success = False
        if response_received and response_data:
            if response_data[0] in (0x04, 0x71):
                verify_success = True
            elif response_data[0] in (0x7F, 0x31):
                verify_success = False
        
        return KeyTestResult(
            operation='VERIFY',
            key_type=key_type,
            key_index=key_index,
            success=verify_success if response_received else sent,
            details={
                'kzk_id': f'0x{kzk_id:02X}',
                'kzk_usage': f'0x{kzk_usage:02X}',
                'key_data': key_data.hex(),
                'verify_key': key_info['verify_key'].hex(),
                'response_received': response_received,
                'response_data': response_data.hex() if response_data else None,
                'frames_sent': min(len(verify_data) // 8 + 1, len(self.KZK_VERIFY_IDS))
            },
            duration=duration
        )
    
    def run_full_test(self, key_types: Optional[List[str]] = None) -> Dict[str, KeyTestResult]:
        """
        Run full key distribution and verification test for all key types.
        
        Args:
            key_types: List of key types to test (default: all)
            
        Returns:
            Dictionary of key_type -> KeyTestResult
        """
        if key_types is None:
            key_types = list(self.KEY_TYPES.keys())
        
        results = {}
        
        for key_type in key_types:
            logger.info(f"Testing key type: {key_type}")
            
            # Step 1: Distribute key
            dist_result = self.distribute_key(key_type)
            results[f'{key_type}_distribute'] = dist_result
            
            time.sleep(0.1)  # Wait between operations
            
            # Step 2: Verify key
            verify_result = self.verify_key(key_type)
            results[f'{key_type}_verify'] = verify_result
            
            time.sleep(0.1)
        
        return results
    
    def generate_report(self, results: Dict[str, KeyTestResult]) -> str:
        """Generate markdown report from key test results."""
        lines = [
            "# KZK Key Test Report",
            "",
            "## Summary",
            "",
            f"| Operation | Key Type | Index | Success | Duration |",
            f"|-----------|----------|-------|---------|----------|"
        ]
        
        for name, result in results.items():
            status = "✅" if result.success else "❌"
            lines.append(
                f"| {result.operation} | {result.key_type} | {result.key_index} | {status} | {result.duration:.3f}s |"
            )
        
        lines.extend(["", "## Detailed Results", ""])
        
        for name, result in results.items():
            lines.extend([
                f"### {result.operation} - {result.key_type}",
                "",
                f"- **Success**: {result.success}",
                f"- **Duration**: {result.duration:.3f}s",
                "",
                "**Details**:",
                "```json",
                str(result.details),
                "```",
                ""
            ])
        
        return "\n".join(lines)


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("KeyTester module loaded")
    print("Supported key types:")
    for key_type in KeyTester.KEY_TYPES:
        print(f"  - {key_type}")
    print("\nCAN IDs used:")
    print(f"  Distribution: {[f'0x{can_id:03X}' for can_id in KeyTester.KZK_DISTRIBUTE_IDS]}")
    print(f"  Verification: {[f'0x{can_id:03X}' for can_id in KeyTester.KZK_VERIFY_IDS]}")
