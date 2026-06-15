# SecOC Toolkit

Generic SecOC (Secure Onboard Communication) testing tool based on Toyota SecOC Demo.

## Features

- **Cross-platform**: Python + Scapy, no Vector CANoe dependency
- **Multi-hardware support**: ZLG (周立功), TOSUN (同星), PCAN, Kvaser, Vector, SocketCAN
- **9 attack modules**: Replay, CMAC Forgery, Freshness Rollback, DoS Flood, Sync Disruption, CPU Load, Key Interception, KDF Collision, Key Injection
- **SHE key management**: KDF, M1/M2/M3 update, ICUS verification, KeyTester (KZK distribution)
- **DBC import**: Parse Vector CAN DBC files for automatic signal layout
- **FV verification**: Bit-level validation against CANoe reference frames
- **UDS diagnostic**: 0x10/0x27/0x31/0x34 services
- **Configurable**: YAML configuration for different OEMs

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Normal SecOC Communication
```bash
python -m secoc_toolkit.main --config secoc_toolkit/config/toyota_secoc.yaml \
  --driver zlg --channel 0 --mode normal --duration 10
```

### 2. Attack Testing
```bash
# Replay attack
python -m secoc_toolkit.main --config secoc_toolkit/config/toyota_secoc.yaml \
  --driver zlg --mode attack --attack replay --msg-id 0x3BF

# DoS flood attack
python -m secoc_toolkit.main --config secoc_toolkit/config/toyota_secoc.yaml \
  --driver zlg --mode attack --attack dos_flood --duration 5

# Run all attacks
python -m secoc_toolkit.main --config secoc_toolkit/config/toyota_secoc.yaml \
  --driver zlg --mode attack --attack all
```

### 3. DBC Import
```python
from secoc_toolkit.parsers.dbc_parser import DBCParser

parser = DBCParser()
parser.parse_file('path/to/your.dbc')

# Get SecOC messages
secoc_msgs = parser.get_secoc_messages()
for msg_id, msg in secoc_msgs.items():
    print(f"0x{msg_id:03X}: {msg.name}")
    for sig_name, sig in msg.signals.items():
        print(f"  {sig_name}: bit {sig.start_bit}, len {sig.length}")

# Convert to YAML config
config = parser.to_yaml_config()
```

### 4. FV Verification
```python
from secoc_toolkit.core.secoc_engine import SecOCEngine
from secoc_toolkit.core.freshness_manager import FreshnessManager
from secoc_toolkit.verification.fv_verifier import FVVerifier

engine = SecOCEngine({'aes_key': '111111...', 'data_id': 0x3BF, 'cmac_bits': 28})
fm = FreshnessManager()
fm.activate()
fm.start_sync()

verifier = FVVerifier(engine, fm)
results = verifier.run_all_tests()
verifier.print_report(results)
```

### 5. KeyTester (KZK Management)
```python
from secoc_toolkit.can_drivers.can_interface import create_driver
from secoc_toolkit.key_manager.key_tester import KeyTester

can_driver = create_driver('zlg', channel=0, baudrate=500000)
can_driver.open()

kt = KeyTester(can_driver)
kt.add_key(0x02, bytes.fromhex('C1B15650...'), usage=0x01)  # MAC_KEY

# Distribute to target ECU
kt.distribute_key(key_id=0x02, target_id=0)

# Verify key
result = kt.verify_key(0x02, verification_data=b'\x00' * 8)
print(f"Verification: {result.success}")
```

### 6. Diagnostic Mode (ICUS)
```bash
python -m secoc_toolkit.main --config secoc_toolkit/config/toyota_secoc.yaml \
  --mode diag --uid <30-hex-UID> --challenge <32-hex-challenge>
```

## Supported CAN Hardware

| Vendor | Driver | Device Examples |
|--------|--------|-----------------|
| ZLG (周立功) | `zlg` | CANalyst-II, USBCAN-E/2E/U |
| TOSUN (同星) | `tosun` | TSMaster, TC1016/TC1017 |
| PCAN | `pcan` | PCAN-USB |
| Kvaser | `kvaser` | Leaf Light, Leaf Pro |
| Vector | `vector` | VN1630, VN1640 |
| Linux | `socketcan` | Any SocketCAN device |

## Attack Modules

| Attack | Description | Risk |
|--------|-------------|------|
| **Replay** | Resend old frames to test freshness validation | Medium |
| **CMAC Forgery** | Forge valid auth with known key | Critical |
| **Freshness Rollback** | Use old counter values | High |
| **DoS Flood** | High-rate valid frame flood | High |
| **Sync Disruption** | Block CGW1G01 sync frames | High |
| **CPU Load** | Force CMAC verification waste | Medium |
| **Key Interception** | Tamper with SHE key update | Critical |
| **KDF Collision** | Find KDF input collisions | Medium |
| **Key Injection** | Inject forged keys | High |

## Project Structure

```
SecOC_Toolkit/
├── secoc_toolkit/
│   ├── core/              # SecOC Engine + Freshness Manager
│   │   ├── secoc_engine.py        # AES-CMAC, KDF, Payload construction
│   │   └── freshness_manager.py   # Trip/Reset/Message counters
│   ├── can_drivers/       # CAN hardware abstraction (ZLG, TOSUN, python-can)
│   │   └── can_interface.py
│   ├── attacks/           # Penetration testing modules
│   │   └── attack_modules.py
│   ├── diag/              # UDS/SHE diagnostic tools
│   │   └── uds_she_diag.py
│   ├── key_manager/       # KZK key distribution/verification
│   │   └── key_tester.py
│   ├── parsers/           # DBC/CDD file parsers
│   │   └── dbc_parser.py
│   ├── verification/      # FV bit-level validation
│   │   └── fv_verifier.py
│   ├── config/            # YAML configurations
│   │   └── toyota_secoc.yaml
│   └── main.py            # CLI entry point
├── tests/                 # Test scripts
├── requirements.txt
├── build_exe.py           # PyInstaller build script
└── README.md
```

## Build EXE

```bash
# Install PyInstaller
pip install pyinstaller

# Build
python build_exe.py

# Or manually
pyinstaller --name=SecOCToolkit --onefile --console \
  --add-data="secoc_toolkit/config;secoc_toolkit/config" \
  secoc_toolkit\main.py
```

## License

MIT
