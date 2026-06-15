"""CAN Driver Abstraction Layer - Support ZLG and TOSUN hardware."""

import abc
import logging
from typing import Optional, Callable, Dict, Any
import struct

logger = logging.getLogger(__name__)


class CANMessage:
    """Unified CAN message representation."""
    
    def __init__(self, arbitration_id: int, data: bytes, 
                 is_extended_id: bool = False, dlc: Optional[int] = None,
                 timestamp: Optional[float] = None, channel: int = 0):
        self.arbitration_id = arbitration_id
        self.data = data if isinstance(data, bytes) else bytes(data)
        self.is_extended_id = is_extended_id
        self.dlc = dlc or len(data)
        self.timestamp = timestamp
        self.channel = channel
    
    def __repr__(self):
        return f"CANMessage(id=0x{self.arbitration_id:03X}, data={self.data.hex()})")
    
    @classmethod
    def from_dict(cls, msg_dict: Dict) -> 'CANMessage':
        """Create from dictionary (e.g., from JSON)."""
        return cls(
            arbitration_id=msg_dict.get('id', 0),
            data=bytes.fromhex(msg_dict.get('data', '')) if isinstance(msg_dict.get('data'), str) else msg_dict.get('data', b''),
            is_extended_id=msg_dict.get('is_extended', False),
            dlc=msg_dict.get('dlc'),
            channel=msg_dict.get('channel', 0)
        )


class CANDriverInterface(abc.ABC):
    """Abstract base class for CAN hardware drivers."""
    
    @abc.abstractmethod
    def open(self, **kwargs) -> bool:
        """Open CAN channel."""
        pass
    
    @abc.abstractmethod
    def close(self) -> None:
        """Close CAN channel."""
        pass
    
    @abc.abstractmethod
    def send(self, message: CANMessage) -> bool:
        """Send a CAN message."""
        pass
    
    @abc.abstractmethod
    def receive(self, timeout: Optional[float] = None) -> Optional[CANMessage]:
        """Receive a CAN message."""
        pass
    
    @abc.abstractmethod
    def set_filter(self, can_id: int, mask: int, is_extended: bool = False) -> bool:
        """Set CAN filter."""
        pass
    
    @abc.abstractmethod
    def is_open(self) -> bool:
        """Check if channel is open."""
        pass
    
    @abc.abstractmethod
    def get_channel_info(self) -> Dict[str, Any]:
        """Get channel information."""
        pass


class ZLGCANDriver(CANDriverInterface):
    """
    ZLG (Zhou Ligong / 周立功) CAN driver.
    
    Supports devices:
    - CANalyst-II (CAN分析仪-II)
    - USBCAN-E/2E/U
    - USBCAN-I/II
    - CANFD-200U/400U
    
    Uses ZLGCANInterface.dll via ctypes.
    """
    
    # ZLG CAN type constants
    ZCAN_USBCAN1 = 3
    ZCAN_USBCAN2 = 4
    ZCAN_CANETTCP = 6
    ZCAN_CANETUDP = 7
    ZCAN_USBCAN_E_U = 20
    ZCAN_USBCAN_2E_U = 21
    ZCAN_USBCAN_4E_U = 31
    ZCAN_CANFD_200U = 38
    ZCAN_CANFD_400U = 39
    
    # ZLG baud rate constants
    ZCAN_BAUD_125K = 125000
    ZCAN_BAUD_250K = 250000
    ZCAN_BAUD_500K = 500000
    ZCAN_BAUD_1M = 1000000
    
    def __init__(self, device_type: int = ZCAN_USBCAN2, device_index: int = 0,
                 channel: int = 0, baudrate: int = ZCAN_BAUD_500K):
        self.device_type = device_type
        self.device_index = device_index
        self.channel = channel
        self.baudrate = baudrate
        self._handle = None
        self._channel_handle = None
        self._is_open = False
        self._dll = None
    
    def _load_dll(self) -> bool:
        """Load ZLG CAN DLL."""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Try multiple possible paths (Windows + Linux)
            dll_paths = [
                "ZLGCANInterface.dll",
                "zlgcan.dll",
                "C:/Program Files (x86)/ZLG/CANalyst-II/ZLGCANInterface.dll",
                "C:/Program Files/ZLG/CANalyst-II/ZLGCANInterface.dll",
                "/usr/lib/libzlgcan.so",
                "/usr/local/lib/libzlgcan.so",
                "./libzlgcan.so",
            ]
            
            for path in dll_paths:
                try:
                    import sys
                    if sys.platform == 'win32':
                        self._dll = ctypes.windll.LoadLibrary(path)
                    else:
                        self._dll = ctypes.cdll.LoadLibrary(path)
                    logger.info(f"Loaded ZLG DLL: {path}")
                    return True
                except OSError:
                    continue
            
            logger.error("Failed to load ZLG CAN DLL. Please install ZLG driver.")
            return False
            
        except Exception as e:
            logger.error(f"Error loading ZLG DLL: {e}")
            return False
    
    def open(self, **kwargs) -> bool:
        """Open ZLG CAN channel."""
        if self._is_open:
            return True
        
        try:
            import ctypes
            
            if not self._dll and not self._load_dll():
                return False
            
            # Open device
            self._handle = self._dll.VCI_OpenDevice(self.device_type, self.device_index, 0)
            if self._handle == 0:
                logger.error("Failed to open ZLG device")
                return False
            
            # Initialize CAN channel
            class INIT_CONFIG(ctypes.Structure):
                _fields_ = [
                    ("acc_code", ctypes.c_uint32),
                    ("acc_mask", ctypes.c_uint32),
                    ("reserved", ctypes.c_uint32),
                    ("filter", ctypes.c_ubyte),
                    ("timing0", ctypes.c_ubyte),
                    ("timing1", ctypes.c_ubyte),
                    ("mode", ctypes.c_ubyte)
                ]
            
            # Timing for 500Kbps: timing0=0x00, timing1=0x1C
            timing_map = {
                125000: (0x03, 0x1C),
                250000: (0x01, 0x1C),
                500000: (0x00, 0x1C),
                1000000: (0x00, 0x14)
            }
            
            timing = timing_map.get(self.baudrate, (0x00, 0x1C))
            
            config = INIT_CONFIG()
            config.acc_code = 0x00000000
            config.acc_mask = 0xFFFFFFFF
            config.reserved = 0
            config.filter = 0
            config.timing0 = timing[0]
            config.timing1 = timing[1]
            config.mode = 0  # Normal mode
            
            result = self._dll.VCI_InitCAN(self.device_type, self.device_index, 
                                          self.channel, ctypes.byref(config))
            if result == 0:
                logger.error("Failed to initialize ZLG CAN channel")
                self._dll.VCI_CloseDevice(self.device_type, self.device_index)
                return False
            
            # Start CAN channel
            result = self._dll.VCI_StartCAN(self.device_type, self.device_index, self.channel)
            if result == 0:
                logger.error("Failed to start ZLG CAN channel")
                self._dll.VCI_CloseDevice(self.device_type, self.device_index)
                return False
            
            self._is_open = True
            logger.info(f"ZLG CAN channel opened: type={self.device_type}, "
                       f"channel={self.channel}, baudrate={self.baudrate}")
            return True
            
        except Exception as e:
            logger.error(f"Error opening ZLG CAN: {e}")
            return False
    
    def close(self) -> None:
        """Close ZLG CAN channel."""
        if not self._is_open or not self._dll:
            return
        
        try:
            self._dll.VCI_ResetCAN(self.device_type, self.device_index, self.channel)
            self._dll.VCI_CloseDevice(self.device_type, self.device_index)
            self._is_open = False
            logger.info("ZLG CAN channel closed")
        except Exception as e:
            logger.error(f"Error closing ZLG CAN: {e}")
    
    def send(self, message: CANMessage) -> bool:
        """Send CAN message via ZLG."""
        if not self._is_open or not self._dll:
            return False
        
        try:
            import ctypes
            
            class ZCAN_MSG(ctypes.Structure):
                _fields_ = [
                    ("ID", ctypes.c_uint32),
                    ("TimeStamp", ctypes.c_uint32),
                    ("TimeFlag", ctypes.c_ubyte),
                    ("SendType", ctypes.c_ubyte),
                    ("RemoteFlag", ctypes.c_ubyte),
                    ("ExternFlag", ctypes.c_ubyte),
                    ("DataLen", ctypes.c_ubyte),
                    ("Data", ctypes.c_ubyte * 8),
                    ("Reserved", ctypes.c_ubyte * 3)
                ]
            
            msg = ZCAN_MSG()
            msg.ID = message.arbitration_id
            msg.TimeStamp = 0
            msg.TimeFlag = 0
            msg.SendType = 0
            msg.RemoteFlag = 0
            msg.ExternFlag = 1 if message.is_extended_id else 0
            msg.DataLen = min(len(message.data), 8)
            
            for i in range(msg.DataLen):
                msg.Data[i] = message.data[i]
            
            result = self._dll.VCI_Transmit(self.device_type, self.device_index, 
                                           self.channel, ctypes.byref(msg), 1)
            return result == 1
            
        except Exception as e:
            logger.error(f"Error sending ZLG CAN message: {e}")
            return False
    
    def receive(self, timeout: Optional[float] = None) -> Optional[CANMessage]:
        """Receive CAN message from ZLG."""
        if not self._is_open or not self._dll:
            return None
        
        try:
            import ctypes
            
            class ZCAN_MSG(ctypes.Structure):
                _fields_ = [
                    ("ID", ctypes.c_uint32),
                    ("TimeStamp", ctypes.c_uint32),
                    ("TimeFlag", ctypes.c_ubyte),
                    ("SendType", ctypes.c_ubyte),
                    ("RemoteFlag", ctypes.c_ubyte),
                    ("ExternFlag", ctypes.c_ubyte),
                    ("DataLen", ctypes.c_ubyte),
                    ("Data", ctypes.c_ubyte * 8),
                    ("Reserved", ctypes.c_ubyte * 3)
                ]
            
            msg = ZCAN_MSG()
            recv_num = self._dll.VCI_Receive(self.device_type, self.device_index,
                                             self.channel, ctypes.byref(msg), 1,
                                             int((timeout or 100) * 1000))  # ms
            
            if recv_num > 0:
                data = bytes(msg.Data[:msg.DataLen])
                return CANMessage(
                    arbitration_id=msg.ID,
                    data=data,
                    is_extended_id=bool(msg.ExternFlag),
                    dlc=msg.DataLen,
                    channel=self.channel
                )
            return None
            
        except Exception as e:
            logger.error(f"Error receiving ZLG CAN message: {e}")
            return None
    
    def set_filter(self, can_id: int, mask: int, is_extended: bool = False) -> bool:
        """Set ZLG CAN filter."""
        if not self._is_open or not self._dll:
            return False
        
        try:
            import ctypes
            
            class FILTER_RECORD(ctypes.Structure):
                _fields_ = [
                    ("ExtFrame", ctypes.c_ubyte),
                    ("Start", ctypes.c_uint32),
                    ("End", ctypes.c_uint32)
                ]
            
            filter_record = FILTER_RECORD()
            filter_record.ExtFrame = 1 if is_extended else 0
            filter_record.Start = can_id
            filter_record.End = can_id | mask
            
            result = self._dll.VCI_SetReference(self.device_type, self.device_index,
                                                self.channel, 0, ctypes.byref(filter_record))
            return result == 1
            
        except Exception as e:
            logger.error(f"Error setting ZLG filter: {e}")
            return False
    
    def is_open(self) -> bool:
        return self._is_open
    
    def get_channel_info(self) -> Dict[str, Any]:
        return {
            'driver': 'ZLG',
            'device_type': self.device_type,
            'device_index': self.device_index,
            'channel': self.channel,
            'baudrate': self.baudrate,
            'is_open': self._is_open
        }


class TOSUNCANDriver(CANDriverInterface):
    """
    TOSUN (同星) CAN driver.
    
    Supports devices:
    - TSMaster series (同星总线主站)
    - TC1016/TC1017
    - TC1026/TC1027
    
    Uses TOSUN CAN library (TOSUNlib.dll) via ctypes.
    """
    
    # TOSUN device types
    TS_DEVICE_USB = 1
    TS_DEVICE_TCP = 2
    
    # TOSUN baud rates
    TS_BAUD_125K = 125000
    TS_BAUD_250K = 250000
    TS_BAUD_500K = 500000
    TS_BAUD_1M = 1000000
    
    def __init__(self, device_type: int = TS_DEVICE_USB, device_index: int = 0,
                 channel: int = 0, baudrate: int = TS_BAUD_500K,
                 app_name: str = "SecOC_Toolkit"):
        self.device_type = device_type
        self.device_index = device_index
        self.channel = channel
        self.baudrate = baudrate
        self.app_name = app_name
        self._handle = None
        self._is_open = False
        self._dll = None
    
    def _load_dll(self) -> bool:
        """Load TOSUN CAN DLL."""
        try:
            import ctypes
            import sys
            
            dll_paths = [
                "TOSUNlib.dll",
                "libTOSUN.so",
                "C:/Program Files/TOSUN/TSMaster/TOSUNlib.dll",
                "C:/Program Files (x86)/TOSUN/TSMaster/TOSUNlib.dll",
                "/usr/lib/libTOSUN.so",
                "/usr/local/lib/libTOSUN.so",
                "./libTOSUN.so",
            ]
            
            for path in dll_paths:
                try:
                    if sys.platform == 'win32':
                        self._dll = ctypes.windll.LoadLibrary(path)
                    else:
                        self._dll = ctypes.cdll.LoadLibrary(path)
                    logger.info(f"Loaded TOSUN DLL: {path}")
                    return True
                except (OSError, AttributeError):
                    continue
            
            logger.error("Failed to load TOSUN CAN DLL. Please install TOSUN driver.")
            return False
            
        except Exception as e:
            logger.error(f"Error loading TOSUN DLL: {e}")
            return False
    
    def open(self, **kwargs) -> bool:
        """Open TOSUN CAN channel."""
        if self._is_open:
            return True
        
        try:
            import ctypes
            
            if not self._dll and not self._load_dll():
                return False
            
            # Connect to device
            handle = ctypes.c_int32(0)
            result = self._dll.tsapp_connect(self.app_name.encode(), ctypes.byref(handle))
            if result != 0:
                logger.error(f"Failed to connect to TOSUN device: {result}")
                return False
            self._handle = handle.value
            
            # Set CAN baud rate
            # TOSUN uses different API structure
            # This is a simplified implementation
            
            # Enable CAN channel
            result = self._dll.tscan_set_can_channel(self._handle, self.channel, 0)
            if result != 0:
                logger.error(f"Failed to set TOSUN CAN channel: {result}")
                return False
            
            # Start bus
            result = self._dll.tscan_start_bus(self._handle, self.channel)
            if result != 0:
                logger.error(f"Failed to start TOSUN bus: {result}")
                return False
            
            self._is_open = True
            logger.info(f"TOSUN CAN channel opened: channel={self.channel}, "
                       f"baudrate={self.baudrate}")
            return True
            
        except Exception as e:
            logger.error(f"Error opening TOSUN CAN: {e}")
            return False
    
    def close(self) -> None:
        """Close TOSUN CAN channel."""
        if not self._is_open or not self._dll:
            return
        
        try:
            self._dll.tscan_stop_bus(self._handle, self.channel)
            self._dll.tsapp_disconnect(self._handle)
            self._is_open = False
            logger.info("TOSUN CAN channel closed")
        except Exception as e:
            logger.error(f"Error closing TOSUN CAN: {e}")
    
    def send(self, message: CANMessage) -> bool:
        """Send CAN message via TOSUN."""
        if not self._is_open or not self._dll:
            return False
        
        try:
            import ctypes
            
            # TOSUN CAN message structure
            class TSCAN_MSG(ctypes.Structure):
                _fields_ = [
                    ("FIdxChn", ctypes.c_ubyte),
                    ("FProperties", ctypes.c_ubyte),
                    ("FDC", ctypes.c_ubyte),
                    ("FReserved", ctypes.c_ubyte),
                    ("FIdxFrame", ctypes.c_uint32),
                    ("FIdentifier", ctypes.c_uint32),
                    ("FTimeUs", ctypes.c_uint64),
                    ("FDLC", ctypes.c_ubyte),
                    ("FData", ctypes.c_ubyte * 64)
                ]
            
            msg = TSCAN_MSG()
            msg.FIdxChn = self.channel
            msg.FProperties = 0x80 if message.is_extended_id else 0x00
            msg.FDC = 0
            msg.FReserved = 0
            msg.FIdxFrame = 0
            msg.FIdentifier = message.arbitration_id
            msg.FTimeUs = 0
            msg.FDLC = min(len(message.data), 8)
            
            for i in range(msg.FDLC):
                msg.FData[i] = message.data[i]
            
            result = self._dll.tscan_transmit_can_sync(self._handle, 
                                                         ctypes.byref(msg), 1, 100)
            return result == 0
            
        except Exception as e:
            logger.error(f"Error sending TOSUN CAN message: {e}")
            return False
    
    def receive(self, timeout: Optional[float] = None) -> Optional[CANMessage]:
        """Receive CAN message from TOSUN."""
        if not self._is_open or not self._dll:
            return None
        
        try:
            import ctypes
            
            class TSCAN_MSG(ctypes.Structure):
                _fields_ = [
                    ("FIdxChn", ctypes.c_ubyte),
                    ("FProperties", ctypes.c_ubyte),
                    ("FDC", ctypes.c_ubyte),
                    ("FReserved", ctypes.c_ubyte),
                    ("FIdxFrame", ctypes.c_uint32),
                    ("FIdentifier", ctypes.c_uint32),
                    ("FTimeUs", ctypes.c_uint64),
                    ("FDLC", ctypes.c_ubyte),
                    ("FData", ctypes.c_ubyte * 64)
                ]
            
            msg = TSCAN_MSG()
            result = self._dll.tscan_read_can_message(self._handle, self.channel,
                                                       ctypes.byref(msg), 1,
                                                       int((timeout or 100) * 1000))
            
            if result > 0:
                data = bytes(msg.FData[:msg.FDLC])
                return CANMessage(
                    arbitration_id=msg.FIdentifier,
                    data=data,
                    is_extended_id=bool(msg.FProperties & 0x80),
                    dlc=msg.FDLC,
                    channel=msg.FIdxChn
                )
            return None
            
        except Exception as e:
            logger.error(f"Error receiving TOSUN CAN message: {e}")
            return None
    
    def set_filter(self, can_id: int, mask: int, is_extended: bool = False) -> bool:
        """Set TOSUN CAN filter."""
        if not self._is_open or not self._dll:
            return False
        
        try:
            result = self._dll.tscan_config_can_filter(self._handle, self.channel,
                                                        1 if is_extended else 0,
                                                        can_id, mask)
            return result == 0
            
        except Exception as e:
            logger.error(f"Error setting TOSUN filter: {e}")
            return False
    
    def is_open(self) -> bool:
        return self._is_open
    
    def get_channel_info(self) -> Dict[str, Any]:
        return {
            'driver': 'TOSUN',
            'device_type': self.device_type,
            'device_index': self.device_index,
            'channel': self.channel,
            'baudrate': self.baudrate,
            'is_open': self._is_open
        }


class PythonCANDriver(CANDriverInterface):
    """
    Generic CAN driver using python-can library.
    
    Supports:
    - PCAN (PCAN-USB)
    - Kvaser
    - Vector (VN series)
    - SocketCAN (Linux)
    - Serial (SLCAN)
    """
    
    def __init__(self, interface: str = 'pcan', channel: str = 'PCAN_USBBUS1',
                 bitrate: int = 500000, **kwargs):
        self.interface = interface
        self.channel = channel
        self.bitrate = bitrate
        self._kwargs = kwargs
        self._bus = None
        self._is_open = False
    
    def open(self, **kwargs) -> bool:
        """Open python-can bus."""
        if self._is_open:
            return True
        
        try:
            import can
            
            config = {
                'interface': self.interface,
                'channel': self.channel,
                'bitrate': self.bitrate,
                **self._kwargs
            }
            config.update(kwargs)
            
            self._bus = can.Bus(**config)
            self._is_open = True
            logger.info(f"python-can bus opened: interface={self.interface}, "
                       f"channel={self.channel}, bitrate={self.bitrate}")
            return True
            
        except ImportError:
            logger.error("python-can not installed. Run: pip install python-can")
            return False
        except Exception as e:
            logger.error(f"Error opening python-can: {e}")
            return False
    
    def close(self) -> None:
        """Close python-can bus."""
        if self._bus:
            self._bus.shutdown()
            self._bus = None
        self._is_open = False
        logger.info("python-can bus closed")
    
    def send(self, message: CANMessage) -> bool:
        """Send via python-can."""
        if not self._bus:
            return False
        
        try:
            import can
            
            msg = can.Message(
                arbitration_id=message.arbitration_id,
                data=message.data,
                is_extended_id=message.is_extended_id
            )
            self._bus.send(msg)
            return True
            
        except Exception as e:
            logger.error(f"Error sending python-can message: {e}")
            return False
    
    def receive(self, timeout: Optional[float] = None) -> Optional[CANMessage]:
        """Receive via python-can."""
        if not self._bus:
            return None
        
        try:
            import can
            
            msg = self._bus.recv(timeout=timeout)
            if msg:
                return CANMessage(
                    arbitration_id=msg.arbitration_id,
                    data=msg.data,
                    is_extended_id=msg.is_extended_id,
                    dlc=msg.dlc,
                    timestamp=msg.timestamp
                )
            return None
            
        except Exception as e:
            logger.error(f"Error receiving python-can message: {e}")
            return None
    
    def set_filter(self, can_id: int, mask: int, is_extended: bool = False) -> bool:
        """Set python-can filter."""
        if not self._bus:
            return False
        
        try:
            import can
            
            self._bus.set_filters([{
                'can_id': can_id,
                'can_mask': mask,
                'extended': is_extended
            }])
            return True
            
        except Exception as e:
            logger.error(f"Error setting python-can filter: {e}")
            return False
    
    def is_open(self) -> bool:
        return self._is_open
    
    def get_channel_info(self) -> Dict[str, Any]:
        return {
            'driver': 'python-can',
            'interface': self.interface,
            'channel': self.channel,
            'bitrate': self.bitrate,
            'is_open': self._is_open
        }


def create_driver(driver_type: str, **kwargs) -> CANDriverInterface:
    """
    Factory function to create CAN driver instances.
    
    Args:
        driver_type: Driver type ('zlg', 'tosun', 'python-can', 'pcan', 'kvaser', 'vector', 'socketcan')
        **kwargs: Driver-specific configuration
        
    Returns:
        CANDriverInterface instance
    """
    driver_type = driver_type.lower()
    
    if driver_type == 'zlg':
        return ZLGCANDriver(**kwargs)
    elif driver_type == 'tosun':
        return TOSUNCANDriver(**kwargs)
    elif driver_type in ('python-can', 'pcan', 'kvaser', 'vector', 'socketcan', 'serial'):
        if driver_type != 'python-can':
            kwargs['interface'] = driver_type
        return PythonCANDriver(**kwargs)
    else:
        raise ValueError(f"Unknown driver type: {driver_type}. "
                        f"Supported: zlg, tosun, python-can, pcan, kvaser, vector, socketcan")


if __name__ == '__main__':
    # Quick test with mock
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Test driver factory
    try:
        driver = create_driver('python-can', channel='PCAN_USBBUS1', bitrate=500000)
        print(f"Driver created: {driver.get_channel_info()}")
    except Exception as e:
        print(f"Driver creation test: {e}")
    
    # Test CAN message
    msg = CANMessage(0x3BF, b'\x00\x0f\x00\x00\x00\x00\x00\x00')
    print(f"CAN Message: {msg}")
