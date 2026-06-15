"""Freshness Manager - SecOC freshness value synchronization."""

import threading
import time
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class FreshnessManager:
    """
    SecOC Freshness Value Manager.
    
    Implements three-layer freshness counter architecture:
    - TripCounter: 16-bit, long-term (vehicle lifecycle)
    - ResetCounter: 20-bit, medium-term (sync period based)
    - MessageCounter: 4/8-bit, short-term (per message)
    
    Sync frame (CGW1G01) broadcast:
    - TripCounter + ResetCounter + CMAC
    - Receivers validate and sync their local counters
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize freshness manager.
        
        Args:
            config: Dictionary with optional keys:
                - trip_counter_bits: TripCounter width (default: 16)
                - reset_counter_bits: ResetCounter width (default: 20)
                - message_counter_bits: MessageCounter width (default: 4)
                - sync_period: Sync frame period in seconds (default: 0.1)
                - trip_update_factor: ResetCounter wraps before TripCounter increments (default: 65535)
                - initial_trip: Initial TripCounter value (default: 0)
                - initial_reset: Initial ResetCounter value (default: 0)
        """
        config = config or {}
        
        self.trip_counter_bits = config.get('trip_counter_bits', 16)
        self.reset_counter_bits = config.get('reset_counter_bits', 20)
        self.message_counter_bits = config.get('message_counter_bits', 4)
        
        self.trip_max = (1 << self.trip_counter_bits) - 1
        self.reset_max = (1 << self.reset_counter_bits) - 1
        self.message_max = (1 << self.message_counter_bits) - 1
        
        self.sync_period = config.get('sync_period', 0.1)  # 100ms
        self.trip_update_factor = config.get('trip_update_factor', 65535)
        
        # Counter state
        self.trip_counter = config.get('initial_trip', 0) & self.trip_max
        self.reset_counter = config.get('initial_reset', 0) & self.reset_max
        self.message_counters: Dict[int, int] = {}  # Per-message counters
        
        # Update tracking
        self._update_count = 0
        self._lock = threading.Lock()
        self._running = False
        self._sync_thread: Optional[threading.Thread] = None
        
        # SecOC activation state
        self.enabled = False
        self._activation_triggered = False
        
        logger.info(f"FreshnessManager initialized: trip={self.trip_counter_bits}b, "
                    f"reset={self.reset_counter_bits}b, message={self.message_counter_bits}b")
    
    def activate(self):
        """Activate SecOC (equivalent to receiving MET1N01 in Demo)."""
        if not self._activation_triggered:
            self._activation_triggered = True
            self.enabled = False  # Will be set to True after first sync
            logger.info("SecOC activation triggered")
    
    def start_sync(self):
        """Start freshness synchronization thread."""
        if self._running:
            logger.warning("Sync thread already running")
            return
        
        self._running = True
        self._sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._sync_thread.start()
        logger.info(f"Sync thread started (period={self.sync_period}s)")
    
    def stop_sync(self):
        """Stop freshness synchronization thread."""
        self._running = False
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=1.0)
            logger.info("Sync thread stopped")
    
    def _sync_loop(self):
        """Main synchronization loop (runs in background thread)."""
        while self._running:
            with self._lock:
                # Update counters
                self._update_count += 1
                if self._update_count >= self.trip_update_factor:
                    self.trip_counter = (self.trip_counter + 1) & self.trip_max
                    self.reset_counter = 0
                    self._update_count = 0
                    logger.debug(f"TripCounter incremented: {self.trip_counter}")
                else:
                    self.reset_counter = (self.reset_counter + 1) & self.reset_max
                
                # Reset all message counters on sync boundary
                for msg_id in self.message_counters:
                    self.message_counters[msg_id] = 0
                
                # Enable SecOC after first sync cycle
                if not self.enabled and self._activation_triggered:
                    self.enabled = True
                    logger.info("SecOC enabled")
            
            time.sleep(self.sync_period)
    
    def get_freshness(self, msg_id: int) -> Dict[str, int]:
        """
        Get current freshness values for a message.
        
        Args:
            msg_id: CAN message ID
            
        Returns:
            Dictionary with 'trip', 'reset', 'message' counter values
        """
        with self._lock:
            if not self.enabled:
                raise RuntimeError("SecOC not enabled - sync not active")
            
            # Initialize message counter if needed
            if msg_id not in self.message_counters:
                self.message_counters[msg_id] = 0
            
            msg_counter = self.message_counters[msg_id]
            self.message_counters[msg_id] = (msg_counter + 1) & self.message_max
            
            return {
                'trip': self.trip_counter,
                'reset': self.reset_counter,
                'message': msg_counter
            }
    
    def get_sync_frame_data(self) -> Dict[str, int]:
        """
        Get data for sync frame (CGW1G01 equivalent).
        
        Returns:
            Dictionary with current TripCounter and ResetCounter values
        """
        with self._lock:
            return {
                'trip': self.trip_counter,
                'reset': self.reset_counter
            }
    
    def validate_freshness(self, trip: int, reset: int, message: int,
                         msg_id: int) -> bool:
        """
        Validate received freshness values against local state.
        
        Checks:
        1. TripCounter >= local TripCounter (monotonic)
        2. ResetCounter >= local ResetCounter (if same Trip)
        3. MessageCounter > last seen (if same Trip+Reset)
        
        Args:
            trip: Received TripCounter
            reset: Received ResetCounter
            message: Received MessageCounter
            msg_id: CAN message ID
            
        Returns:
            True if freshness is valid, False otherwise
        """
        with self._lock:
            if msg_id not in self.message_counters:
                self.message_counters[msg_id] = 0
            
            last_message = self.message_counters[msg_id]
            
            # Check TripCounter monotonicity
            if trip < self.trip_counter:
                logger.warning(f"TripCounter rollback detected: {trip} < {self.trip_counter}")
                return False
            
            # Check ResetCounter monotonicity (same Trip)
            if trip == self.trip_counter and reset < self.reset_counter:
                logger.warning(f"ResetCounter rollback detected: {reset} < {self.reset_counter}")
                return False
            
            # Check MessageCounter monotonicity (same Trip+Reset)
            if trip == self.trip_counter and reset == self.reset_counter:
                if message <= last_message:
                    logger.warning(f"MessageCounter not increasing: {message} <= {last_message}")
                    return False
            
            return True
    
    def sync_from_external(self, trip: int, reset: int):
        """
        Sync counters from external sync frame (e.g., received CGW1G01).
        
        Args:
            trip: Received TripCounter
            reset: Received ResetCounter
        """
        with self._lock:
            # Validate: new values must be >= current values
            if trip < self.trip_counter or \
               (trip == self.trip_counter and reset < self.reset_counter):
                logger.warning(f"Rejecting outdated sync: trip={trip}, reset={reset} "
                              f"(current: trip={self.trip_counter}, reset={self.reset_counter})")
                return
            
            self.trip_counter = trip & self.trip_max
            self.reset_counter = reset & self.reset_max
            
            # Reset message counters on sync
            for msg_id in self.message_counters:
                self.message_counters[msg_id] = 0
            
            logger.debug(f"Synced from external: trip={trip}, reset={reset}")
    
    def manual_rollback_test(self, trip_delta: int = -1, reset: int = 1):
        """
        Manually trigger counter rollback (for testing only).
        
        Equivalent to pressing 'd' key in FreshnessManager.can Demo.
        
        Args:
            trip_delta: Amount to change TripCounter (typically negative)
            reset: New ResetCounter value
        """
        with self._lock:
            self.trip_counter = (self.trip_counter + trip_delta) & self.trip_max
            self.reset_counter = reset & self.reset_max
            logger.warning(f"Manual rollback test: trip={self.trip_counter}, "
                          f"reset={self.reset_counter}")
    
    @property
    def is_enabled(self) -> bool:
        """Check if SecOC is enabled."""
        return self.enabled
    
    @property
    def is_running(self) -> bool:
        """Check if sync thread is running."""
        return self._running
    
    def __repr__(self):
        return (f"FreshnessManager(trip={self.trip_counter}, "
                f"reset={self.reset_counter}, enabled={self.enabled})")


if __name__ == '__main__':
    # Quick test
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    fm = FreshnessManager()
    fm.activate()
    fm.start_sync()
    
    time.sleep(0.5)  # Wait for sync
    
    for i in range(5):
        fresh = fm.get_freshness(0x3BF)
        print(f"Msg {i}: trip={fresh['trip']:04X}, reset={fresh['reset']:05X}, "
              f"message={fresh['message']:02X}")
        time.sleep(0.1)
    
    fm.stop_sync()
