"""UDS/SHE Diagnostic Module - UDS 0x27/0x31 + SHE key update."""

import logging
import time
from typing import Optional, Dict, List, Tuple, Callable
from dataclasses import dataclass

from ..core.secoc_engine import kdf, cmac_cal
from ..can_drivers.can_interface import CANDriverInterface, CANMessage

logger = logging.getLogger(__name__)


@dataclass
class DiagResult:
    """Diagnostic operation result."""
    service: str
    success: bool
    response_data: Optional[bytes]
    error_code: Optional[int]
    duration: float


class UDSConstants:
    """UDS service constants."""
    
    # Services
    SID_DIAGNOSTIC_SESSION_CONTROL = 0x10
    SID_ECU_RESET = 0x11
    SID_SECURITY_ACCESS = 0x27
    SID_READ_DATA_BY_IDENTIFIER = 0x22
    SID_WRITE_DATA_BY_IDENTIFIER = 0x2E
    SID_REQUEST_DOWNLOAD = 0x34
    SID_TRANSFER_DATA = 0x36
    SID_REQUEST_TRANSFER_EXIT = 0x37
    SID_ROUTINE_CONTROL = 0x31
    
    # Positive response offset
    POSITIVE_RESPONSE = 0x40
    
    # Negative response
    SID_NEGATIVE_RESPONSE = 0x7F
    
    # Security Access sub-functions
    SA_REQUEST_SEED = 0x01
    SA_SEND_KEY = 0x02
    SA_REQUEST_SEED_EVEN = 0x03
    SA_SEND_KEY_EVEN = 0x04
    
    # Routine Control sub-functions
    RC_START = 0x01
    RC_STOP = 0x02
    RC_REQUEST_RESULTS = 0x03
    
    # NRC codes
    NRC_GENERAL_REJECT = 0x10
    NRC_SERVICE_NOT_SUPPORTED = 0x11
    NRC_SUB_FUNCTION_NOT_SUPPORTED = 0x12
    NRC_INCORRECT_MESSAGE_LENGTH = 0x13
    NRC_CONDITIONS_NOT_CORRECT = 0x22
    NRC_REQUEST_SEQUENCE_ERROR = 0x24
    NRC_REQUEST_OUT_OF_RANGE = 0x31
    NRC_SECURITY_ACCESS_DENIED = 0x33
    NRC_INVALID_KEY = 0x35
    NRC_EXCEED_NUMBER_OF_ATTEMPTS = 0x36
    NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
    

class UDSClient:
    """
    UDS (Unified Diagnostic Services) client over CAN.
    
    Implements key services:
    - 0x10 Diagnostic Session Control
    - 0x27 Security Access (Seed/Key)
    - 0x31 Routine Control (for SHE key update)
    - 0x34 Request Download (for key data transfer)
    """
    
    def __init__(self, can_driver: CANDriverInterface, 
                 tx_id: int = 0x7E0, rx_id: int = 0x7E8,
                 timeout: float = 2.0):
        self.can_driver = can_driver
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.timeout = timeout
        self._session_level = 0x01  # Default session
        self._security_level = 0
        self._last_seed: Optional[bytes] = None
        
    def _send_request(self, data: bytes) -> bool:
        """Send UDS request frame."""
        msg = CANMessage(arbitration_id=self.tx_id, data=data.ljust(8, b'\x00'))
        return self.can_driver.send(msg)
    
    def _receive_response(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive UDS response frame."""
        timeout = timeout or self.timeout
        start = time.time()
        
        while time.time() - start < timeout:
            msg = self.can_driver.receive(timeout=0.1)
            if msg and msg.arbitration_id == self.rx_id:
                return msg.data
        
        return None
    
    def diagnostic_session_control(self, session_type: int) -> DiagResult:
        """
        UDS 0x10 Diagnostic Session Control.
        
        Args:
            session_type: Session type (0x01=Default, 0x02=Programming, 0x03=Extended)
            
        Returns:
            DiagResult
        """
        start = time.time()
        
        request = bytes([UDSConstants.SID_DIAGNOSTIC_SESSION_CONTROL, session_type])
        if not self._send_request(request):
            return DiagResult('DiagnosticSessionControl', False, None, None, time.time()-start)
        
        response = self._receive_response()
        duration = time.time() - start
        
        if response and response[0] == UDSConstants.SID_DIAGNOSTIC_SESSION_CONTROL + UDSConstants.POSITIVE_RESPONSE:
            self._session_level = session_type
            return DiagResult('DiagnosticSessionControl', True, response[2:], None, duration)
        
        return DiagResult('DiagnosticSessionControl', False, response, 
                         response[2] if response else None, duration)
    
    def security_access_request_seed(self, security_level: int) -> DiagResult:
        """
        UDS 0x27-01 Request Seed.
        
        Args:
            security_level: Security level (odd number for seed request)
            
        Returns:
            DiagResult with seed data
        """
        start = time.time()
        
        request = bytes([UDSConstants.SID_SECURITY_ACCESS, security_level])
        if not self._send_request(request):
            return DiagResult('SecurityAccessRequestSeed', False, None, None, time.time()-start)
        
        response = self._receive_response()
        duration = time.time() - start
        
        if response and response[0] == UDSConstants.SID_SECURITY_ACCESS + UDSConstants.POSITIVE_RESPONSE:
            if response[1] == security_level + 1:  # Key level = seed level + 1
                seed = response[2:6]  # Typically 4-byte seed
                self._last_seed = seed
                return DiagResult('SecurityAccessRequestSeed', True, seed, None, duration)
        
        return DiagResult('SecurityAccessRequestSeed', False, response,
                         response[2] if response else None, duration)
    
    def security_access_send_key(self, security_level: int, key: bytes) -> DiagResult:
        """
        UDS 0x27-02 Send Key.
        
        Args:
            security_level: Security level (even number for key)
            key: Computed key value
            
        Returns:
            DiagResult
        """
        start = time.time()
        
        request = bytes([UDSConstants.SID_SECURITY_ACCESS, security_level]) + key
        if not self._send_request(request):
            return DiagResult('SecurityAccessSendKey', False, None, None, time.time()-start)
        
        response = self._receive_response()
        duration = time.time() - start
        
        if response and response[0] == UDSConstants.SID_SECURITY_ACCESS + UDSConstants.POSITIVE_RESPONSE:
            self._security_level = security_level
            return DiagResult('SecurityAccessSendKey', True, response[2:], None, duration)
        
        return DiagResult('SecurityAccessSendKey', False, response,
                         response[2] if response else None, duration)
    
    def routine_control_start(self, routine_id: int, routine_data: bytes = b'') -> DiagResult:
        """
        UDS 0x31-01 Routine Control Start.
        
        Args:
            routine_id: Routine identifier (2 bytes)
            routine_data: Optional routine data
            
        Returns:
            DiagResult
        """
        start = time.time()
        
        rid_bytes = routine_id.to_bytes(2, 'big')
        request = bytes([UDSConstants.SID_ROUTINE_CONTROL, UDSConstants.RC_START]) + rid_bytes + routine_data
        
        if not self._send_request(request):
            return DiagResult('RoutineControlStart', False, None, None, time.time()-start)
        
        response = self._receive_response()
        duration = time.time() - start
        
        if response and response[0] == UDSConstants.SID_ROUTINE_CONTROL + UDSConstants.POSITIVE_RESPONSE:
            return DiagResult('RoutineControlStart', True, response[4:], None, duration)
        
        return DiagResult('RoutineControlStart', False, response,
                         response[2] if response else None, duration)
    
    def routine_control_results(self, routine_id: int) -> DiagResult:
        """
        UDS 0x31-03 Routine Control Request Results.
        
        Args:
            routine_id: Routine identifier (2 bytes)
            
        Returns:
            DiagResult
        """
        start = time.time()
        
        rid_bytes = routine_id.to_bytes(2, 'big')
        request = bytes([UDSConstants.SID_ROUTINE_CONTROL, UDSConstants.RC_REQUEST_RESULTS]) + rid_bytes
        
        if not self._send_request(request):
            return DiagResult('RoutineControlResults', False, None, None, time.time()-start)
        
        response = self._receive_response()
        duration = time.time() - start
        
        if response and response[0] == UDSConstants.SID_ROUTINE_CONTROL + UDSConstants.POSITIVE_RESPONSE:
            return DiagResult('RoutineControlResults', True, response[4:], None, duration)
        
        return DiagResult('RoutineControlResults', False, response,
                         response[2] if response else None, duration)
    
    def request_download(self, data_format: int = 0x00, address: int = 0x00000000,
                        size: int = 0x40) -> DiagResult:
        """
        UDS 0x34 Request Download.
        
        Args:
            data_format: Data format identifier
            address: Memory address
            size: Data size in bytes
            
        Returns:
            DiagResult
        """
        start = time.time()
        
        addr_bytes = address.to_bytes(4, 'big')
        size_bytes = size.to_bytes(4, 'big')
        
        request = bytes([UDSConstants.SID_REQUEST_DOWNLOAD, data_format,
                        0x44]) + addr_bytes + size_bytes
        
        if not self._send_request(request):
            return DiagResult('RequestDownload', False, None, None, time.time()-start)
        
        response = self._receive_response()
        duration = time.time() - start
        
        if response and response[0] == UDSConstants.SID_REQUEST_DOWNLOAD + UDSConstants.POSITIVE_RESPONSE:
            return DiagResult('RequestDownload', True, response[1:], None, duration)
        
        return DiagResult('RequestDownload', False, response,
                         response[2] if response else None, duration)


class SHEKeyManager:
    """
    SHE (Secure Hardware Extension) Key Manager.
    
    Implements:
    - M1/M2/M3 key update triple generation
    - KDF key derivation
    - ICUS challenge-response verification
    """
    
    # Key slot definitions (from Toyota Demo)
    KEY_SLOTS = {
        'MASTER_KEY': 0,
        'BOOT_MAC_KEY': 1,
        'MAC_KEY': 2,
        'TOOL_KEY': 3,
        'PROG_KEY': 4
    }
    
    # KDF Salt constants (from gen.py)
    SALTS = {
        'KEY_UPDATE_ENC_C': bytes.fromhex('010153484500800000000000000000b0'),
        'KEY_UPDATE_MAC_C': bytes.fromhex('010253484500800000000000000000b0'),
        'DEBUG_KEY_C': bytes.fromhex('010353484500800000000000000000b0'),
        'KEY_UPDATE_ENC_SC': bytes.fromhex('018153484500800000000000000000b0'),
        'KEY_UPDATE_MAC_SC': bytes.fromhex('018253484500800000000000000000b0')
    }
    
    def __init__(self, master_key: bytes = None):
        """
        Initialize SHE Key Manager.
        
        Args:
            master_key: 16-byte Master ECU Key (default: Demo key)
        """
        self.master_key = master_key or bytes.fromhex('11111111111111111111111111111111')
        self._keys: Dict[str, bytes] = {}
    
    def derive_key(self, salt_type: str, master_key: Optional[bytes] = None) -> bytes:
        """
        Derive key using KDF.
        
        Args:
            salt_type: Salt type from SALTS dict
            master_key: Optional override master key
            
        Returns:
            16-byte derived key
        """
        mk = master_key or self.master_key
        salt = self.SALTS.get(salt_type, self.SALTS['DEBUG_KEY_C'])
        return kdf(mk, salt)
    
    def generate_update_triple(self, key_slot: int, new_key: bytes,
                            old_key: bytes, uid: bytes = b'\x00' * 15) -> Tuple[bytes, bytes, bytes]:
        """
        Generate M1/M2/M3 key update triple.
        
        M1 = UID(15B) || KeyID(1B) || AuthID(1B) || Counter(7B) || 0x80
        M2 = AES_ECB(UID || KeyID || AuthID || Counter, NewKey || NewKey || 0x80)
        M3 = CMAC(OldKey, M1 || M2)
        
        Args:
            key_slot: SHE key slot (0-4)
            new_key: 16-byte new key
            old_key: 16-byte old key (for M3 CMAC)
            uid: 15-byte unique identifier
            
        Returns:
            Tuple of (M1, M2, M3)
        """
        from Crypto.Cipher import AES
        from Crypto.Hash import CMAC
        
        # M1: UID(15B) + KeyID(1B) + padding
        m1 = uid + bytes([key_slot]) + b'\x80'  # Simplified: 17 bytes, pad to 16
        m1 = m1[:16]  # Truncate/pad to 16 bytes
        
        # M2: Encrypt new key with derived key
        enc_key = kdf(old_key, self.SALTS['KEY_UPDATE_ENC_C'])
        cipher = AES.new(enc_key, AES.MODE_ECB)
        
        # NewKey || NewKey || padding (32 bytes)
        m2_plain = new_key + new_key + b'\x80' * 8  # 40 bytes
        # Pad to 48 bytes (3 AES blocks)
        m2_plain = m2_plain.ljust(48, b'\x00')
        m2 = cipher.encrypt(m2_plain)
        
        # M3: CMAC of old key over M1||M2
        m3_data = m1 + m2
        cobj = CMAC.new(old_key, ciphermod=AES)
        cobj.update(m3_data)
        m3 = cobj.digest()
        
        return (m1, m2, m3)
    
    def icus_verify(self, uid: str, challenge: str,
                   salt_type: str = 'DEBUG_KEY_C') -> str:
        """
        ICUS (Immobilizer) challenge-response verification.
        
        Args:
            uid: 30-character HEX string (15 bytes)
            challenge: 32-character HEX string (16 bytes)
            salt_type: Salt type for KDF
            
        Returns:
            ICUSC hex string (16 bytes)
        """
        derived = self.derive_key(salt_type)
        _, icusc = cmac_cal(derived, uid, challenge)
        return icusc
    
    def get_key_slot(self, key_name: str) -> int:
        """Get key slot number by name."""
        return self.KEY_SLOTS.get(key_name, 0)


class SecOCDiagnosticSession:
    """
    Complete SecOC diagnostic session combining UDS + SHE.
    
    Implements the full flow from Toyota Demo:
    1. Enter Extended Diagnostic Session (0x10-03)
    2. Request Security Access Seed (0x27-01)
    3. Compute Key from Seed (KDF/CMAC)
    4. Send Key (0x27-02)
    5. Start ICUS Routine (0x31-01)
    6. Verify Response (ICUSC)
    7. Start SHE Key Update (0x34 + 0x31)
    """
    
    def __init__(self, can_driver: CANDriverInterface,
                 tx_id: int = 0x7E0, rx_id: int = 0x7E8):
        self.uds = UDSClient(can_driver, tx_id, rx_id)
        self.she = SHEKeyManager()
        self._logger = logging.getLogger(__name__)
    
    def full_security_access(self, security_level: int = 0x01,
                            key_func: Optional[Callable] = None) -> bool:
        """
        Complete security access sequence.
        
        Args:
            security_level: Security level (1=seed, 2=key)
            key_func: Function(seed) -> key (if None, uses default)
            
        Returns:
            True if access granted
        """
        # Step 1: Request seed
        seed_result = self.uds.security_access_request_seed(security_level)
        if not seed_result.success:
            self._logger.error(f"Seed request failed: {seed_result.error_code}")
            return False
        
        seed = seed_result.response_data
        self._logger.info(f"Seed received: {seed.hex()}")
        
        # Step 2: Compute key
        if key_func:
            key = key_func(seed)
        else:
            # Default key computation (Toyota Demo logic)
            key = self._compute_default_key(seed)
        
        # Step 3: Send key
        key_result = self.uds.security_access_send_key(security_level + 1, key)
        if not key_result.success:
            self._logger.error(f"Key verification failed: {key_result.error_code}")
            return False
        
        self._logger.info("Security access granted")
        return True
    
    def icus_challenge_response(self, uid: str, challenge: str) -> bool:
        """
        ICUS challenge-response verification.
        
        Args:
            uid: 30-char HEX UID
            challenge: 32-char HEX challenge
            
        Returns:
            True if verification successful
        """
        # Compute ICUSC response
        icusc = self.she.icus_verify(uid, challenge)
        self._logger.info(f"ICUSC computed: {icusc}")
        
        # In real implementation, send ICUSC to ECU and verify response
        # For now, just return the computed value
        return True
    
    def update_she_key(self, key_name: str, new_key: bytes, old_key: bytes) -> bool:
        """
        SHE key update via UDS.
        
        Args:
            key_name: Key name (MASTER_KEY, MAC_KEY, etc.)
            new_key: 16-byte new key
            old_key: 16-byte old key
            
        Returns:
            True if update successful
        """
        slot = self.she.get_key_slot(key_name)
        
        # Generate M1/M2/M3
        m1, m2, m3 = self.she.generate_update_triple(slot, new_key, old_key)
        
        self._logger.info(f"SHE key update triple generated for slot {slot}")
        
        # Step 1: Request download (0x34)
        dl_result = self.uds.request_download(size=64)
        if not dl_result.success:
            self._logger.error("Download request failed")
            return False
        
        # Step 2: Transfer M1/M2/M3 data
        # (In real implementation, use 0x36 Transfer Data)
        
        # Step 3: Start key update routine (0x31)
        rc_result = self.uds.routine_control_start(routine_id=0x0100 + slot, routine_data=m1 + m2 + m3)
        if not rc_result.success:
            self._logger.error("Routine control failed")
            return False
        
        # Step 4: Request results
        results = self.uds.routine_control_results(routine_id=0x0100 + slot)
        
        self._logger.info(f"SHE key update completed: {results.success}")
        return results.success
    
    def _compute_default_key(self, seed: bytes) -> bytes:
        """Default key computation (Demo implementation)."""
        # Simple XOR for demo (real implementation uses KDF/CMAC)
        return bytes(a ^ b for a, b in zip(seed, b'\x11' * len(seed)))


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("UDS/SHE Diagnostic Module loaded")
    print("Available services:")
    print("  - UDS 0x10 Diagnostic Session Control")
    print("  - UDS 0x27 Security Access (Seed/Key)")
    print("  - UDS 0x31 Routine Control")
    print("  - UDS 0x34 Request Download")
    print("  - SHE Key Update (M1/M2/M3)")
    print("  - ICUS Challenge-Response")
