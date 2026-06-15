#!/usr/bin/env python3
"""
SecOC Toolkit - Generic SecOC Testing Tool

Usage:
    python main.py --config config/toyota_secoc.yaml --driver zlg --attack replay
    python main.py --config config/toyota_secoc.yaml --driver tosun --test all
    python main.py --config config/toyota_secoc.yaml --mode normal --duration 10
"""

import argparse
import sys
import time
import logging
import yaml
from pathlib import Path

from secoc_toolkit.core.secoc_engine import SecOCEngine, kdf, cmac_cal
from secoc_toolkit.core.freshness_manager import FreshnessManager
from secoc_toolkit.can_drivers.can_interface import create_driver, CANMessage
from secoc_toolkit.attacks.attack_modules import SecOCAttacks
from secoc_toolkit.key_manager.key_tester import KeyTester
from secoc_toolkit.parsers.dbc_parser import DBCParser
from secoc_toolkit.verification.fv_verifier import FVVerifier


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def load_config(config_path: str) -> dict:
    """Load YAML configuration."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def run_normal_mode(config, can_driver, duration):
    """Run normal SecOC communication mode."""
    logger = logging.getLogger(__name__)
    logger.info("Starting normal SecOC communication mode")
    
    # Initialize engine and freshness manager
    secoc_config = config['secoc']['messages'][1]  # ECT1G01
    engine = SecOCEngine(secoc_config)
    
    freshness_config = config.get('freshness', {})
    fm = FreshnessManager(freshness_config)
    fm.activate()
    fm.start_sync()
    
    # Wait for sync
    time.sleep(0.5)
    
    start_time = time.time()
    count = 0
    
    try:
        while time.time() - start_time < duration:
            fresh = fm.get_freshness(secoc_config['can_id'])
            raw_data = b'\x00' * 8
            
            frame = engine.build_secoc_frame(
                fresh['trip'], fresh['reset'], fresh['message'], raw_data
            )
            
            can_data = engine.pack_can_frame(raw_data, frame['freshness'], frame['cmac'])
            msg = CANMessage(arbitration_id=secoc_config['can_id'], data=can_data)
            
            if can_driver.send(msg):
                count += 1
                if count % 10 == 0:
                    logger.info(f"Sent {count} frames")
            
            time.sleep(secoc_config['period'])
            
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        fm.stop_sync()
        can_driver.close()
    
    logger.info(f"Normal mode completed: {count} frames sent")


def run_attack_mode(config, can_driver, attack_name, msg_id):
    """Run attack mode."""
    logger = logging.getLogger(__name__)
    logger.info(f"Starting attack mode: {attack_name}")
    
    secoc_config = None
    for msg in config['secoc']['messages']:
        if msg['can_id'] == msg_id:
            secoc_config = msg
            break
    
    if not secoc_config:
        secoc_config = config['secoc']['messages'][1]
        msg_id = secoc_config['can_id']
    
    engine = SecOCEngine(secoc_config)
    
    freshness_config = config.get('freshness', {})
    fm = FreshnessManager(freshness_config)
    fm.activate()
    fm.start_sync()
    
    time.sleep(0.5)
    
    attacks = SecOCAttacks(engine, fm, can_driver)
    
    try:
        if attack_name == 'replay':
            result = attacks.replay_attack(msg_id)
        elif attack_name == 'cmac_forgery':
            result = attacks.cmac_forgery(msg_id)
        elif attack_name == 'freshness_rollback':
            result = attacks.freshness_rollback(msg_id)
        elif attack_name == 'dos_flood':
            result = attacks.dos_flood_attack(msg_id, duration=args.duration)
        elif attack_name == 'sync_disruption':
            result = attacks.sync_disruption_attack(msg_id)
        elif attack_name == 'cpu_load':
            result = attacks.cpu_load_attack(msg_id, duration=args.duration)
        elif attack_name == 'key_interception':
            result = attacks.key_update_interception()
        elif attack_name == 'kdf_collision':
            result = attacks.kdf_collision_test(iterations=1000)
        elif attack_name == 'all':
            results = attacks.run_all_attacks(msg_id)
            report = attacks.generate_report(results)
            print(report)
            return
        else:
            logger.error(f"Unknown attack: {attack_name}")
            return
        
        print(f"\n{'='*60}")
        print(f"Attack: {result.attack_name}")
        print(f"Risk Level: {result.risk_level}")
        print(f"Success: {result.success}")
        print(f"Duration: {result.duration:.3f}s")
        print(f"Details: {result.details}")
        print(f"Recommendations:")
        for rec in result.recommendations:
            print(f"  - {rec}")
        print(f"{'='*60}\n")
        
    finally:
        fm.stop_sync()
        can_driver.close()


def run_diagnostic_mode(config, can_driver, uid, challenge):
    """Run diagnostic mode (ICUS verification)."""
    logger = logging.getLogger(__name__)
    logger.info("Starting diagnostic mode")
    
    master_key = bytes.fromhex(config['diagnostic']['kdf_constants']['MASTER_ECU_KEY'])
    salt = bytes.fromhex(config['diagnostic']['kdf_constants']['DEBUG_KEY_C'])
    
    derived_key = kdf(master_key, salt)
    icusb, icusc = cmac_cal(derived_key, uid, challenge)
    
    print(f"\n{'='*60}")
    print(f"ICUS Verification")
    print(f"UID: {uid}")
    print(f"Challenge: {challenge}")
    print(f"Derived Key: {derived_key.hex()}")
    print(f"ICUSB: {icusb}")
    print(f"ICUSC: {icusc}")
    print(f"{'='*60}\n")
    
    can_driver.close()


def main():
    parser = argparse.ArgumentParser(description='SecOC Toolkit - Generic SecOC Testing Tool')
    parser.add_argument('--config', default='secoc_toolkit/config/toyota_secoc.yaml',
                        help='Configuration file path')
    parser.add_argument('--driver', default='python-can',
                        choices=['zlg', 'tosun', 'python-can', 'pcan', 'kvaser', 'vector', 'socketcan'],
                        help='CAN driver type')
    parser.add_argument('--channel', default='0', help='CAN channel (0, 1, PCAN_USBBUS1, etc.)')
    parser.add_argument('--baudrate', type=int, default=500000, help='CAN baudrate')
    
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--mode', choices=['normal', 'attack', 'diag'],
                          help='Operation mode')
    
    parser.add_argument('--attack', choices=['replay', 'cmac_forgery', 'freshness_rollback',
                                              'dos_flood', 'sync_disruption', 'cpu_load',
                                              'key_interception', 'kdf_collision', 'all'],
                        help='Attack type (for attack mode)')
    parser.add_argument('--msg-id', type=lambda x: int(x, 0), default=0x3BF,
                        help='Target CAN message ID (hex)')
    parser.add_argument('--duration', type=int, default=10, help='Duration in seconds')
    
    parser.add_argument('--uid', help='UID for ICUS verification (diag mode)')
    parser.add_argument('--challenge', help='Challenge for ICUS verification (diag mode)')
    
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    # Load config
    config = load_config(args.config)
    
    # Create CAN driver
    driver_kwargs = {
        'channel': args.channel,
        'baudrate': args.baudrate
    }
    
    if args.driver == 'zlg':
        driver_kwargs['channel'] = int(args.channel)
    elif args.driver == 'tosun':
        driver_kwargs['channel'] = int(args.channel)
    
    can_driver = create_driver(args.driver, **driver_kwargs)
    
    if not can_driver.open():
        logging.error("Failed to open CAN driver")
        sys.exit(1)
    
    # Run mode
    if args.mode == 'normal':
        run_normal_mode(config, can_driver, args.duration)
    elif args.mode == 'attack':
        if not args.attack:
            print("Error: --attack required for attack mode")
            sys.exit(1)
        run_attack_mode(config, can_driver, args.attack, args.msg_id)
    elif args.mode == 'diag':
        if not args.uid or not args.challenge:
            print("Error: --uid and --challenge required for diag mode")
            sys.exit(1)
        run_diagnostic_mode(config, can_driver, args.uid, args.challenge)
    
    logging.info("SecOC Toolkit completed")


if __name__ == '__main__':
    main()
