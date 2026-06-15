# SecOC Toolkit

Generic SecOC (Secure Onboard Communication) testing tool based on Toyota SecOC Demo.

## Features

- **Cross-platform**: Python + Scapy, no Vector CANoe dependency
- **Multi-hardware support**: ZLG (周立功), TOSUN (同星), PCAN, Kvaser, Vector, SocketCAN
- **6 attack modules**: Replay, CMAC Forgery, Freshness Rollback, Bus-Off, Key Interception, KDF Collision
- **SHE key management**: KDF, M1/M2/M3 update, ICUS verification
- **Configurable**: YAML configuration for different OEMs

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Normal Mode (SecOC communication)
```bash
python -m secoc_toolkit.main --config secoc_toolkit/config/toyota_secoc.yaml \
  --driver zlg --channel 0 --mode normal --duration 10
```

### Attack Mode
```bash
# Replay attack
python -m secoc_toolkit.main --config secoc_toolkit/config/toyota_secoc.yaml \
  --driver zlg --mode attack --attack replay --msg-id 0x3BF

# Run all attacks
python -m secoc_toolkit.main --config secoc_toolkit/config/toyota_secoc.yaml \
  --driver zlg --mode attack --attack all
```

### Diagnostic Mode (ICUS verification)
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

## Project Structure

```
SecOC_Toolkit/
├── secoc_toolkit/
│   ├── core/              # SecOC Engine + Freshness Manager
│   ├── can_drivers/       # CAN hardware abstraction (ZLG, TOSUN, python-can)
│   ├── attacks/           # Penetration testing modules
│   ├── diag/              # UDS/SHE diagnostic tools
│   ├── config/            # YAML configurations
│   └── main.py            # CLI entry point
├── tests/                 # Test scripts
├── requirements.txt
└── README.md
```

## License

MIT
