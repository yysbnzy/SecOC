"""FV Verification - Freshness Value bit-level validation."""

import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

from ..core.secoc_engine import SecOCEngine
from ..core.freshness_manager import FreshnessManager

logger = logging.getLogger(__name__)


@dataclass
class FVVerificationResult:
    """FV verification result."""
    test_name: str
    passed: bool
    expected_bits: str
    actual_bits: str
    field: str
    details: Dict


class FVVerifier:
    """
    Freshness Value Bit-Level Verifier.
    
    Validates that FV packing matches Toyota CANoe Demo exactly.
    
    Toyota ECT1G01 FV layout (from DBC):
    - FV3BF at bit 39-42 (4 bits)
    - KZK3BF at bit 35-62 (28 bits)
    
    FV = ((MessageCounter & 0x03) << 2) | (ResetCounter & 0x03)
    
    In CAN frame (Motorola format):
    - Byte 0-4: Regular signals
    - Byte 5: [7:4] = part of KZK, [3:0] = part of KZK
    - Byte 6: [7:4] = part of KZK, [3:0] = part of KZK  
    - Byte 7: [7:4] = FV (4 bits), [3:0] = part of KZK
    
    Wait, that's wrong. Let me recalculate based on DBC:
    
    DBC: SG_ FV3BF : 39|4@0+ (1,0) [0|0] ""  VNC
    
    Motorola format, start bit 39:
    - Total bits = 64 (8 bytes)
    - MSB = 64 - 1 - 39 = 24
    - MSB byte = 24 / 8 = 3, MSB bit = 24 % 8 = 0
    
    Wait, that doesn't match. Let me re-read:
    
    For Motorola (big endian within byte):
    - Start bit 39 means the MSB of the signal is at bit 39
    - Signal length 4 means bits 39, 38, 37, 36
    
    In CAN frame:
    - Bit 39 = Byte 4, bit 7 (since 39 = 4*8 + 7)
    - Bit 38 = Byte 4, bit 6
    - Bit 37 = Byte 4, bit 5
    - Bit 36 = Byte 4, bit 4
    
    Wait, DBC Motorola format is confusing. Let me check:
    
    In DBC Motorola format (@0):
    - Start bit is the MSB position
    - Signal extends to the left (towards lower bit numbers)
    - Start bit 39, length 4: bits 39, 38, 37, 36
    
    Byte mapping:
    - Byte 0: bits 7-0
    - Byte 1: bits 15-8
    - Byte 2: bits 23-16
    - Byte 3: bits 31-24
    - Byte 4: bits 39-32
    - Byte 5: bits 47-40
    - Byte 6: bits 55-48
    - Byte 7: bits 63-56
    
    So bit 39 is in Byte 4, position 7 (MSB of byte 4)
    Bit 36 is in Byte 4, position 4
    
    So FV3BF = Byte[4][7:4]
    
    For KZK3BF at bit 35, length 28:
    - Bits 35, 34, ..., 8 (28 bits)
    - Byte 4: bits 35-32 = positions 3-0
    - Byte 3: bits 31-24 = positions 7-0
    - Byte 2: bits 23-16 = positions 7-0
    - Byte 1: bits 15-8 = positions 7-0
    - Byte 0: bit 8 = position 0 (wait, that's only 1 bit)
    
    Hmm, let me recalculate:
    - Start bit 35, length 28
    - Motorola: extends left from 35
    - Bits: 35, 34, ..., 8 (28 bits total: 35-8+1 = 28)
    
    Byte mapping:
    - Byte 4: bits 35-32 (positions 3, 2, 1, 0) = 4 bits
    - Byte 3: bits 31-24 (positions 7-0) = 8 bits
    - Byte 2: bits 23-16 (positions 7-0) = 8 bits
    - Byte 1: bits 15-8 (positions 7-0) = 8 bits
    
    Total: 4 + 8 + 8 + 8 = 28 bits ✓
    
    So KZK3BF spans:
    - Byte 4 [3:0] = KZK[27:24]
    - Byte 3 [7:0] = KZK[23:16]
    - Byte 2 [7:0] = KZK[15:8]
    - Byte 1 [7:0] = KZK[7:0]
    
    And FV3BF = Byte 4 [7:4]
    
    This is the correct layout!
    """
    
    def __init__(self, engine: SecOCEngine, freshness: FreshnessManager):
        self.engine = engine
        self.freshness = freshness
    
    def verify_fv_packing(self, trip: int, reset: int, 
                          message_counter: int) -> FVVerificationResult:
        """
        Verify FV is packed correctly in CAN frame.
        
        Expected FV = ((MessageCounter & 0x03) << 2) | (ResetCounter & 0x03)
        
        In frame (Byte 4 [7:4]):
        - Bit 7: (MessageCounter & 0x02) >> 1
        - Bit 6: (MessageCounter & 0x01) << 1  (wait, no)
        
        Let me recalculate from CAPL:
        msgECT1G01.FV3BF = (byte)((MessageCounter & 0x00000003) << 2) | (byte)(ResetCounter & 0x00000003);
        
        So FV3BF [3:0] = {MC[1:0], RC[1:0]}
        - Bit 3: MC[1]
        - Bit 2: MC[0]
        - Bit 1: RC[1]
        - Bit 0: RC[0]
        
        In Byte 4 [7:4]:
        - Bit 7 (MSB): MC[1]
        - Bit 6: MC[0]
        - Bit 5: RC[1]
        - Bit 4: RC[0]
        """
        expected_fv = ((message_counter & 0x03) << 2) | (reset & 0x03)
        
        # Build frame
        frame = self.engine.build_secoc_frame(trip, reset, message_counter, b'\x00' * 8)
        can_data = self.engine.pack_can_frame(b'\x00' * 8, frame['freshness'], frame['cmac'])
        
        # Extract FV from packed frame
        # Byte 4 [7:4] = (can_data[4] >> 4) & 0x0F
        actual_fv = (can_data[4] >> 4) & 0x0F
        
        # Verify
        passed = (expected_fv == actual_fv)
        
        return FVVerificationResult(
            test_name='FV_Packing',
            passed=passed,
            expected_bits=f"0x{expected_fv:01X} (MC={message_counter & 0x03}, RC={reset & 0x03})",
            actual_bits=f"0x{actual_fv:01X} (Byte[4][7:4])",
            field='FV3BF',
            details={
                'trip': trip,
                'reset': reset,
                'message_counter': message_counter,
                'expected_fv': expected_fv,
                'actual_fv': actual_fv,
                'can_data': can_data.hex(),
                'byte_4': f"0x{can_data[4]:02X}"
            }
        )
    
    def verify_cmac_packing(self, trip: int, reset: int,
                            message_counter: int) -> FVVerificationResult:
        """
        Verify CMAC is packed correctly in CAN frame.
        
        Expected layout:
        - KZK3BF spans Byte 4 [3:0] + Byte 3 [7:0] + Byte 2 [7:0] + Byte 1 [7:0]
        - Total: 28 bits
        """
        # Build frame
        frame = self.engine.build_secoc_frame(trip, reset, message_counter, b'\x00' * 8)
        can_data = self.engine.pack_can_frame(b'\x00' * 8, frame['freshness'], frame['cmac'])
        
        # Extract CMAC from packed frame
        # Byte 4 [3:0] = KZK[27:24]
        # Byte 3 [7:0] = KZK[23:16]
        # Byte 2 [7:0] = KZK[15:8]
        # Byte 1 [7:0] = KZK[7:0]
        actual_cmac = ((can_data[4] & 0x0F) << 24) | \
                      (can_data[3] << 16) | \
                      (can_data[2] << 8) | \
                      can_data[1]
        
        expected_cmac = frame['cmac']
        
        passed = (expected_cmac == actual_cmac)
        
        return FVVerificationResult(
            test_name='CMAC_Packing',
            passed=passed,
            expected_bits=f"0x{expected_cmac:07X}",
            actual_bits=f"0x{actual_cmac:07X}",
            field='KZK3BF',
            details={
                'trip': trip,
                'reset': reset,
                'message_counter': message_counter,
                'expected_cmac': f"0x{expected_cmac:07X}",
                'actual_cmac': f"0x{actual_cmac:07X}",
                'can_data': can_data.hex(),
                'kzk_bytes': f"[{can_data[1]:02X} {can_data[2]:02X} {can_data[3]:02X} {can_data[4] & 0x0F:01X}]"
            }
        )
    
    def verify_full_frame(self, trip: int, reset: int,
                          message_counter: int) -> Dict[str, FVVerificationResult]:
        """Run all FV verification tests."""
        return {
            'fv': self.verify_fv_packing(trip, reset, message_counter),
            'cmac': self.verify_cmac_packing(trip, reset, message_counter)
        }
    
    def verify_against_canoe_reference(self, canoe_frame_hex: str,
                                       trip: int, reset: int,
                                       message_counter: int) -> FVVerificationResult:
        """
        Verify against actual CANoe captured frame.
        
        Args:
            canoe_frame_hex: CAN frame data from CANoe (hex string, 16 chars)
            trip: Expected trip counter
            reset: Expected reset counter
            message_counter: Expected message counter
        """
        canoe_data = bytes.fromhex(canoe_frame_hex)
        
        # Build our frame
        frame = self.engine.build_secoc_frame(trip, reset, message_counter, b'\x00' * 8)
        our_data = self.engine.pack_can_frame(b'\x00' * 8, frame['freshness'], frame['cmac'])
        
        # Compare byte by byte
        differences = []
        for i in range(min(len(canoe_data), len(our_data))):
            if canoe_data[i] != our_data[i]:
                differences.append({
                    'byte': i,
                    'canoe': f"0x{canoe_data[i]:02X}",
                    'ours': f"0x{our_data[i]:02X}",
                    'xor': f"0x{canoe_data[i] ^ our_data[i]:02X}"
                })
        
        passed = len(differences) == 0
        
        return FVVerificationResult(
            test_name='CANoe_Reference_Match',
            passed=passed,
            expected_bits=canoe_data.hex(),
            actual_bits=our_data.hex(),
            field='Full_Frame',
            details={
                'trip': trip,
                'reset': reset,
                'message_counter': message_counter,
                'differences': differences,
                'difference_count': len(differences)
            }
        )
    
    def run_all_tests(self) -> Dict[str, any]:
        """Run comprehensive FV verification tests."""
        results = {}
        
        # Test 1: Basic FV packing
        logger.info("Test 1: FV packing verification")
        results['basic_fv'] = self.verify_fv_packing(0, 1, 2)
        
        # Test 2: Basic CMAC packing
        logger.info("Test 2: CMAC packing verification")
        results['basic_cmac'] = self.verify_cmac_packing(0, 1, 2)
        
        # Test 3: Edge cases
        logger.info("Test 3: Edge cases")
        results['max_counters'] = self.verify_full_frame(0xFFFF, 0xFFFFF, 0xFF)
        results['zero_counters'] = self.verify_full_frame(0, 0, 0)
        results['mid_counters'] = self.verify_full_frame(0x1234, 0x56789, 0xAB)
        
        # Test 4: FV bit decomposition
        logger.info("Test 4: FV bit decomposition")
        for mc in range(4):
            for rc in range(4):
                result = self.verify_fv_packing(0, rc, mc)
                key = f'fv_mc{mc}_rc{rc}'
                results[key] = result
        
        # Summary
        total = len([r for r in results.values() if isinstance(r, FVVerificationResult)])
        passed = sum(1 for r in results.values() 
                     if isinstance(r, FVVerificationResult) and r.passed)
        
        results['summary'] = {
            'total_tests': total,
            'passed': passed,
            'failed': total - passed,
            'pass_rate': f"{passed / total * 100:.1f}%" if total > 0 else "N/A"
        }
        
        return results
    
    def print_report(self, results: Dict):
        """Print verification report."""
        print("\n" + "=" * 60)
        print("FV Verification Report")
        print("=" * 60)
        
        for name, result in results.items():
            if name == 'summary':
                continue
            
            if isinstance(result, FVVerificationResult):
                status = "PASS" if result.passed else "FAIL"
                print(f"\n{status}: {result.test_name} ({result.field})")
                print(f"  Expected: {result.expected_bits}")
                print(f"  Actual:   {result.actual_bits}")
                if not result.passed:
                    print(f"  Details:  {result.details}")
        
        summary = results.get('summary', {})
        print(f"\n{'=' * 60}")
        print(f"Summary: {summary.get('passed', 0)}/{summary.get('total_tests', 0)} passed")
        print(f"Pass rate: {summary.get('pass_rate', 'N/A')}")
        print(f"{'=' * 60}\n")


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    from secoc_toolkit.core.secoc_engine import SecOCEngine
    from secoc_toolkit.core.freshness_manager import FreshnessManager
    
    engine = SecOCEngine({
        'aes_key': '11111111111111111111111111111111',
        'data_id': 0x3BF,
        'cmac_bits': 28
    })
    
    fm = FreshnessManager()
    fm.activate()
    fm.start_sync()
    
    import time
    time.sleep(0.5)
    
    verifier = FVVerifier(engine, fm)
    results = verifier.run_all_tests()
    verifier.print_report(results)
    
    fm.stop_sync()
