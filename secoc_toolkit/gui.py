#!/usr/bin/env python3
"""
SecOC Toolkit GUI - Tkinter GUI wrapper for SecOC Toolkit
Handles PyInstaller bundled resources via get_resource_path().
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
import os
import logging
from queue import Queue, Empty
from pathlib import Path

# Import toolkit modules
from core.secoc_engine import SecOCEngine, kdf, cmac_cal, SyncFrameEngine
from core.freshness_manager import FreshnessManager
from can_drivers.can_interface import create_driver, CANMessage
from attacks.attack_modules import SecOCAttacks
import yaml
import time


def get_resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller."""
    try:
        base_path = sys._MEIPASS  # PyInstaller temp folder
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


class QueueHandler(logging.Handler):
    """Logging handler that puts records into a queue for GUI thread."""
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)


class StdoutRedirector:
    """Redirect stdout/stderr to GUI text widget."""
    def __init__(self, log_queue):
        self.log_queue = log_queue

    def write(self, text):
        if text:
            self.log_queue.put(text)

    def flush(self):
        pass


class SecOCGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecOC Toolkit GUI")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # Style
        style = ttk.Style()
        style.configure("TNotebook.Tab", padding=[10, 5])

        # Execution state
        self.running = False
        self.worker_thread = None
        self.stop_event = threading.Event()
        self.can_driver = None

        # Sync frame state
        self.sync_thread = None
        self.sync_running = False

        # Log queue
        self.log_queue = Queue()

        # Setup logging
        self.setup_logging()

        # Build UI
        self.build_ui()

        # Start log polling
        self.poll_log_queue()

    def setup_logging(self):
        """Configure logging to GUI."""
        self.logger = logging.getLogger("SecOC")
        self.logger.setLevel(logging.DEBUG)

        # Clear existing handlers
        for h in list(self.logger.handlers):
            self.logger.removeHandler(h)

        # Queue handler for GUI
        queue_handler = QueueHandler(self.log_queue)
        queue_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        queue_handler.setFormatter(formatter)
        self.logger.addHandler(queue_handler)

        # Also log to root logger for imported modules
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        for h in list(root_logger.handlers):
            root_logger.removeHandler(h)
        root_logger.addHandler(queue_handler)

    def build_ui(self):
        """Build the GUI layout."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=2)
        main_frame.rowconfigure(1, weight=1)

        # ===== Left Panel: Configuration =====
        left_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        left_frame.grid(row=0, column=0, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        left_frame.columnconfigure(1, weight=1)

        # Config File
        ttk.Label(left_frame, text="Config File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        config_frame = ttk.Frame(left_frame)
        config_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        config_frame.columnconfigure(0, weight=1)

        self.config_path = tk.StringVar(value="config/toyota_secoc.yaml")
        # Default to bundled config when packaged
        bundled = get_resource_path("config/toyota_secoc.yaml")
        if os.path.exists(bundled):
            self.config_path.set(bundled)
        self.config_entry = ttk.Entry(config_frame, textvariable=self.config_path)
        self.config_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))
        ttk.Button(config_frame, text="Browse", command=self.browse_config).grid(row=0, column=1, padx=5)

        # CAN Driver
        ttk.Label(left_frame, text="CAN Driver:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.driver_map = {
            "virtual (无需硬件)": "virtual",
            "zlg (周立功CAN - 需硬件)": "zlg",
            "tosun (同星CAN - 需硬件)": "tosun",
            "vector (Vector - 需硬件)": "vector",
            "pcan (PEAK CAN - 需硬件)": "pcan",
            "kvaser (Kvaser - 需硬件)": "kvaser",
            "socketcan (Linux - 需硬件)": "socketcan",
        }
        self.driver_var = tk.StringVar(value="virtual (无需硬件)")
        driver_combo = ttk.Combobox(
            left_frame, textvariable=self.driver_var,
            values=list(self.driver_map.keys()),
            state="readonly", width=28
        )
        driver_combo.grid(row=1, column=1, sticky=tk.W, pady=5)

        # Channel
        ttk.Label(left_frame, text="Channel:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.channel_var = tk.StringVar(value="0")
        ttk.Entry(left_frame, textvariable=self.channel_var, width=20).grid(row=2, column=1, sticky=tk.W, pady=5)

        # Baudrate
        ttk.Label(left_frame, text="Baudrate:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.baudrate_var = tk.StringVar(value="500000")
        ttk.Entry(left_frame, textvariable=self.baudrate_var, width=20).grid(row=3, column=1, sticky=tk.W, pady=5)

        # ===== Mode Selection (Notebook) =====
        ttk.Label(left_frame, text="Mode:").grid(row=4, column=0, sticky=tk.W, pady=(15, 5))
        self.mode_notebook = ttk.Notebook(left_frame)
        self.mode_notebook.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        # --- Normal Mode Tab ---
        self.normal_frame = ttk.Frame(self.mode_notebook, padding="10")
        self.mode_notebook.add(self.normal_frame, text="Normal")

        ttk.Label(self.normal_frame, text="Duration (sec):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.normal_duration = tk.StringVar(value="10")
        ttk.Entry(self.normal_frame, textvariable=self.normal_duration, width=15).grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(self.normal_frame, text="Message ID (hex):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.normal_msg_id = tk.StringVar(value="0x3BF")
        ttk.Entry(self.normal_frame, textvariable=self.normal_msg_id, width=15).grid(row=1, column=1, sticky=tk.W, pady=5)

        # --- Sync frame checkbox ---
        self.sync_cgw_var = tk.BooleanVar(value=True)
        sync_chk = ttk.Checkbutton(
            self.normal_frame,
            text="发送同步报文 CGW1G01（0x00F）",
            variable=self.sync_cgw_var
        )
        sync_chk.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(10, 5))

        # --- Attack Mode Tab ---
        self.attack_frame = ttk.Frame(self.mode_notebook, padding="10")
        self.mode_notebook.add(self.attack_frame, text="Attack")

        ttk.Label(self.attack_frame, text="Attack Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.attack_type = tk.StringVar(value="replay")
        ttk.Combobox(
            self.attack_frame, textvariable=self.attack_type,
            values=["replay", "cmac_forgery", "freshness_rollback", "busoff",
                    "key_interception", "kdf_collision", "all"],
            state="readonly", width=20
        ).grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(self.attack_frame, text="Message ID (hex):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.attack_msg_id = tk.StringVar(value="0x3BF")
        ttk.Entry(self.attack_frame, textvariable=self.attack_msg_id, width=15).grid(row=1, column=1, sticky=tk.W, pady=5)

        ttk.Label(self.attack_frame, text="Duration (sec):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.attack_duration = tk.StringVar(value="10")
        ttk.Entry(self.attack_frame, textvariable=self.attack_duration, width=15).grid(row=2, column=1, sticky=tk.W, pady=5)

        # --- Diagnostic Mode Tab ---
        self.diag_frame = ttk.Frame(self.mode_notebook, padding="10")
        self.mode_notebook.add(self.diag_frame, text="Diagnostic")

        ttk.Label(self.diag_frame, text="UID (hex):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.diag_uid = tk.StringVar(value="1234567890ABCDEF")
        ttk.Entry(self.diag_frame, textvariable=self.diag_uid, width=25).grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(self.diag_frame, text="Challenge (hex):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.diag_challenge = tk.StringVar(value="ABCDEF1234567890")
        ttk.Entry(self.diag_frame, textvariable=self.diag_challenge, width=25).grid(row=1, column=1, sticky=tk.W, pady=5)

        # ===== Control Buttons =====
        btn_frame = ttk.Frame(left_frame)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=(15, 5))

        self.run_btn = ttk.Button(btn_frame, text="Run Test", command=self.start_run, width=12)
        self.run_btn.grid(row=0, column=0, padx=5)

        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_run, width=12, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=5)

        ttk.Button(btn_frame, text="Clear Log", command=self.clear_log, width=12).grid(row=0, column=2, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(left_frame, mode='indeterminate', length=200)
        self.progress.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 5))
        self.progress.grid_remove()

        # Status label
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(left_frame, textvariable=self.status_var, foreground="gray").grid(
            row=8, column=0, columnspan=2, sticky=tk.W, pady=5)

        # ===== Right Panel: Log Output =====
        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding="5")
        log_frame.grid(row=0, column=1, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, state="disabled",
            font=("Consolas", 10), bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="white"
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Log tags for colors
        self.log_text.tag_configure("INFO", foreground="#4ec9b0")
        self.log_text.tag_configure("DEBUG", foreground="#569cd6")
        self.log_text.tag_configure("WARNING", foreground="#dcdcaa")
        self.log_text.tag_configure("ERROR", foreground="#f44747")
        self.log_text.tag_configure("CRITICAL", foreground="#ff0000")

        # Help text at bottom
        help_frame = ttk.Frame(main_frame)
        help_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        ttk.Label(
            help_frame,
            text="Tip: Select a mode tab (Normal/Attack/Diagnostic), configure parameters, then click 'Run Test'. "
                 "Output will appear in the log panel. Use 'Stop' to interrupt.",
            foreground="gray", font=("Arial", 9)
        ).pack(anchor=tk.W)

    def browse_config(self):
        """Open file dialog to select config file."""
        path = filedialog.askopenfilename(
            title="Select Config File",
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")],
            initialdir="config"
        )
        if path:
            self.config_path.set(path)

    def log(self, text, level="INFO"):
        """Append text to log area."""
        self.log_text.config(state="normal")
        tag = level if level in ("INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL") else "INFO"
        self.log_text.insert(tk.END, f"{text}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def poll_log_queue(self):
        """Poll log queue from worker thread and update GUI."""
        from datetime import datetime
        try:
            while True:
                item = self.log_queue.get_nowait()
                if isinstance(item, logging.LogRecord):
                    ts = datetime.fromtimestamp(item.created).strftime('%H:%M:%S')
                    text = f"{ts} - {item.levelname} - {item.getMessage()}"
                    self.log(text, item.levelname)
                else:
                    self.log(str(item), "INFO")
        except Empty:
            pass
        finally:
            self.root.after(100, self.poll_log_queue)

    def start_run(self):
        """Start the test in a worker thread."""
        if self.running:
            return

        self.running = True
        self.stop_event.clear()
        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.grid()
        self.progress.start()
        self.status_var.set("Running...")
        self.clear_log()

        tab = self.mode_notebook.index(self.mode_notebook.select())
        modes = ["normal", "attack", "diag"]
        mode = modes[tab]

        self.worker_thread = threading.Thread(
            target=self.run_test,
            args=(mode,),
            daemon=True
        )
        self.worker_thread.start()

    def stop_run(self):
        """Signal the worker thread to stop."""
        if not self.running:
            return
        self.stop_event.set()
        self.status_var.set("Stopping...")

        # Try to close CAN driver if open
        if self.can_driver:
            try:
                self.can_driver.close()
            except Exception:
                pass

    def on_run_finished(self):
        """Called when worker thread finishes."""
        self.running = False
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress.stop()
        self.progress.grid_remove()
        self.status_var.set("Ready")
        self.can_driver = None

    def clear_log(self):
        """Clear log text area."""
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state="disabled")

    def load_config(self, path):
        """Load YAML config, handle nested top-level key."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw = yaml.safe_load(f)
            # Handle nested structure like {Toyota_SecOC_Demo: {secoc: ...}}
            if isinstance(raw, dict) and len(raw) == 1:
                first_key = next(iter(raw))
                if isinstance(raw[first_key], dict) and 'secoc' in raw[first_key]:
                    return raw[first_key]
            return raw
        except Exception as e:
            self.log(f"Failed to load config: {e}", "ERROR")
            raise

    def create_driver(self):
        """Create and open CAN driver."""
        driver_display = self.driver_var.get()
        driver = self.driver_map.get(driver_display, driver_display)
        channel = self.channel_var.get()
        baudrate = int(self.baudrate_var.get())

        kwargs = {'channel': channel, 'baudrate': baudrate}
        if driver in ('zlg', 'tosun'):
            try:
                kwargs['channel'] = int(channel)
            except ValueError:
                kwargs['channel'] = 0

        try:
            can_drv = create_driver(driver, **kwargs)
            if can_drv is None:
                # Vector driver not installed
                if driver == 'vector':
                    error_msg = (
                        "Vector 驱动未检测到。请安装 Vector XL Driver Library（免费）后重试。\n"
                        "下载地址：https://www.vector.com/int/en/download/"
                    )
                    self.root.after(0, lambda: messagebox.showwarning("驱动未安装", error_msg))
                else:
                    self.root.after(0, lambda: messagebox.showerror(
                        "驱动错误", f"无法创建驱动: {driver_display}"))
                return None
            if not can_drv.open():
                raise RuntimeError(f"Failed to open CAN driver: {driver}")
            self.can_driver = can_drv
            self.log(f"CAN driver opened: {driver}", "INFO")
            return can_drv
        except Exception as e:
            error_msg = f"驱动打开失败: {driver_display}\n\n"
            error_msg += f"错误信息: {e}\n\n"
            error_msg += "请检查:\n"
            error_msg += "1. 硬件已连接并通电\n"
            error_msg += "2. 驱动软件已正确安装\n"
            error_msg += "3. 通道号设置正确\n"
            error_msg += "\n提示: 选择 'virtual (无需硬件)' 可在无硬件环境下测试。"
            # Show messagebox on main thread
            self.root.after(0, lambda: messagebox.showerror("驱动错误", error_msg))
            return None

    def run_test(self, mode):
        """Worker thread: execute test based on mode."""
        try:
            # Redirect stdout/stderr to log queue
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = StdoutRedirector(self.log_queue)
            sys.stderr = StdoutRedirector(self.log_queue)

            config_path = self.config_path.get()
            # Resolve path: user path -> bundled resource -> dev relative
            if not os.path.isabs(config_path):
                bundled = get_resource_path(config_path)
                if os.path.exists(bundled):
                    config_path = bundled
                elif not os.path.exists(config_path):
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    alt = os.path.join(script_dir, config_path)
                    if os.path.exists(alt):
                        config_path = alt
            if not os.path.exists(config_path):
                error_msg = f"配置文件加载失败\n\n路径不存在: {config_path}\n\n"
                error_msg += "请确认以下位置存在配置文件:\n"
                error_msg += f"  • 内嵌资源: {get_resource_path('config/toyota_secoc.yaml')}\n"
                error_msg += f"  • 当前目录: {os.path.join(os.getcwd(), 'config/toyota_secoc.yaml')}\n"
                error_msg += "\n可点击 'Browse' 手动选择配置文件。"
                self.root.after(0, lambda: messagebox.showerror("配置文件错误", error_msg))
                return

            config = self.load_config(config_path)
            can_driver = self.create_driver()
            if can_driver is None:
                return

            if mode == "normal":
                self.run_normal(config, can_driver)
            elif mode == "attack":
                self.run_attack(config, can_driver)
            elif mode == "diag":
                self.run_diagnostic(config, can_driver)

        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
        finally:
            # Restore stdout/stderr
            sys.stdout = old_stdout
            sys.stderr = old_stderr

            # Stop sync thread if running
            if self.sync_running and self.sync_thread:
                self.stop_event.set()
                self.sync_thread.join(timeout=2.0)
                self.sync_running = False
                self.sync_thread = None

            if self.can_driver:
                try:
                    self.can_driver.close()
                except Exception:
                    pass
                self.can_driver = None

            # Schedule GUI update on main thread
            self.root.after(0, self.on_run_finished)

    def run_normal(self, config, can_driver):
        """Run normal mode with optional sync frame."""
        try:
            self.log("Starting Normal SecOC communication mode", "INFO")
            if 'secoc' not in config:
                error_msg = "配置文件缺少 'secoc' 字段\n\n"
                error_msg += "请确认配置文件格式正确，包含 secoc / freshness / diagnostic 等顶层键。"
                self.root.after(0, lambda: messagebox.showerror("配置格式错误", error_msg))
                return
            duration = int(self.normal_duration.get())
            msg_id = int(self.normal_msg_id.get(), 0)
            messages = config.get('secoc', {}).get('messages', [])
            if not messages:
                self.log("配置中未找到 secoc.messages，使用默认配置", "WARNING")
                return
            secoc_config = None
            for msg in messages:
                if msg.get('can_id') == msg_id:
                    secoc_config = msg
                    break
            if not secoc_config:
                for msg in messages:
                    if msg.get('protocol_flag', 0x00) != 0x00:
                        secoc_config = msg
                        break
            if not secoc_config:
                secoc_config = messages[0]
                msg_id = secoc_config['can_id']
            engine = SecOCEngine(secoc_config)
            freshness_config = config.get('freshness', {})
            fm = FreshnessManager(freshness_config)
            fm.activate()
            fm.start_sync()
            time.sleep(0.5)

            # Start sync frame thread if enabled
            if self.sync_cgw_var.get():
                self.log("启动 CGW1G01 同步报文发送 (0x00F, 100ms)", "INFO")
                sync_engine = SyncFrameEngine({
                    'aes_key': secoc_config.get('aes_key', '11111111111111111111111111111111'),
                    'data_id': 0x00F,
                    'cmac_bits': secoc_config.get('cmac_bits', 28)
                })
                self.sync_running = True
                self.sync_thread = threading.Thread(
                    target=self._sync_frame_worker,
                    args=(sync_engine, fm, can_driver, duration),
                    daemon=True
                )
                self.sync_thread.start()

            start_time = time.time()
            count = 0
            try:
                while time.time() - start_time < duration:
                    if self.stop_event.is_set():
                        self.log("Interrupted by user", "WARNING")
                        break
                    fresh = fm.get_freshness(msg_id)
                    raw_data = b'\x00' * 8
                    frame = engine.build_secoc_frame(
                        fresh['trip'], fresh['reset'], fresh['message'], raw_data
                    )
                    can_data = engine.pack_can_frame(raw_data, frame['freshness'], frame['cmac'])
                    msg = CANMessage(arbitration_id=msg_id, data=can_data)
                    if can_driver.send(msg):
                        count += 1
                        if count % 10 == 0:
                            self.log(f"Sent {count} frames", "INFO")
                    time.sleep(secoc_config.get('period', 0.1))
            finally:
                fm.stop_sync()
                self.log(f"Normal mode completed: {count} frames sent", "INFO")
        except Exception as e:
            self.log(f"Normal mode error: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
            self.root.after(0, lambda: messagebox.showerror("运行错误", f"Normal模式运行出错:\n{e}"))

    def _sync_frame_worker(self, sync_engine, fm, can_driver, duration):
        """Background thread: send CGW1G01 sync frames at 100ms interval."""
        sync_count = 0
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                if self.stop_event.is_set():
                    break
                fresh = fm.get_freshness(0x00F)
                sync_frame = sync_engine.build_sync_frame(
                    fresh['trip'], fresh['reset']
                )
                msg = CANMessage(arbitration_id=0x00F, data=sync_frame['can_data'])
                if can_driver.send(msg):
                    sync_count += 1
                    if sync_count % 10 == 0:
                        self.log(f"Sync frame sent: {sync_count}", "INFO")
                time.sleep(0.1)  # 100ms period
        except Exception as e:
            self.log(f"Sync frame error: {e}", "ERROR")
        finally:
            self.sync_running = False
            self.log(f"Sync frame completed: {sync_count} frames sent", "INFO")

    def run_attack(self, config, can_driver):
        """Run attack mode."""
        try:
            attack_name = self.attack_type.get()
            msg_id = int(self.attack_msg_id.get(), 0)
            self.log(f"Starting attack mode: {attack_name}", "INFO")
            messages = config.get('secoc', {}).get('messages', [])
            if not messages:
                self.log("配置中未找到 secoc.messages", "ERROR")
                return
            secoc_config = None
            for msg in messages:
                if msg['can_id'] == msg_id:
                    secoc_config = msg
                    break
            if not secoc_config:
                secoc_config = messages[1] if len(messages) > 1 else messages[0]
                msg_id = secoc_config['can_id']
            engine = SecOCEngine(secoc_config)
            freshness_config = config.get('freshness', {})
            fm = FreshnessManager(freshness_config)
            fm.activate()
            fm.start_sync()
            time.sleep(0.5)
            attacks = SecOCAttacks(engine, fm, can_driver)
            try:
                if attack_name == 'all':
                    results = attacks.run_all_attacks(msg_id)
                    report = attacks.generate_report(results)
                    self.log(report, "INFO")
                else:
                    if attack_name == 'replay':
                        result = attacks.replay_attack(msg_id)
                    elif attack_name == 'cmac_forgery':
                        result = attacks.cmac_forgery(msg_id)
                    elif attack_name == 'freshness_rollback':
                        result = attacks.freshness_rollback(msg_id)
                    elif attack_name == 'busoff':
                        result = attacks.busoff_induction(msg_id, duration=2.0)
                    elif attack_name == 'key_interception':
                        result = attacks.key_update_interception()
                    elif attack_name == 'kdf_collision':
                        result = attacks.kdf_collision_test(iterations=1000)
                    else:
                        self.log(f"Unknown attack: {attack_name}", "ERROR")
                        return
                    self.log(f"\n{'='*60}", "INFO")
                    self.log(f"Attack: {result.attack_name}", "INFO")
                    self.log(f"Risk Level: {result.risk_level}", "INFO")
                    self.log(f"Success: {result.success}", "INFO")
                    self.log(f"Duration: {result.duration:.3f}s", "INFO")
                    self.log(f"Details: {result.details}", "INFO")
                    self.log(f"Recommendations:", "INFO")
                    for rec in result.recommendations:
                        self.log(f"  - {rec}", "INFO")
                    self.log(f"{'='*60}\n", "INFO")
            finally:
                fm.stop_sync()
                if self.stop_event.is_set():
                    self.log("Attack interrupted", "WARNING")
        except Exception as e:
            self.log(f"Attack mode error: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
            self.root.after(0, lambda: messagebox.showerror("运行错误", f"Attack模式运行出错:\n{e}"))

    def run_diagnostic(self, config, can_driver):
        """Run diagnostic (ICUS) mode."""
        try:
            self.log("Starting diagnostic mode", "INFO")
            uid = self.diag_uid.get()
            challenge = self.diag_challenge.get()
            diag_cfg = config.get('diagnostic', {})
            kdf_const = diag_cfg.get('kdf_constants', {})
            master_key = bytes.fromhex(kdf_const.get('MASTER_ECU_KEY', '00000000000000000000000000000000'))
            salt = bytes.fromhex(kdf_const.get('DEBUG_KEY_C', '00000000000000000000000000000000'))
            derived_key = kdf(master_key, salt)
            icusb, icusc = cmac_cal(derived_key, uid, challenge)
            self.log(f"\n{'='*60}", "INFO")
            self.log("ICUS Verification", "INFO")
            self.log(f"UID: {uid}", "INFO")
            self.log(f"Challenge: {challenge}", "INFO")
            self.log(f"Derived Key: {derived_key.hex()}", "INFO")
            self.log(f"ICUSB: {icusb}", "INFO")
            self.log(f"ICUSC: {icusc}", "INFO")
            self.log(f"{'='*60}\n", "INFO")
        except Exception as e:
            self.log(f"Diagnostic mode error: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
            self.root.after(0, lambda: messagebox.showerror("运行错误", f"Diagnostic模式运行出错:\n{e}"))
        finally:
            can_driver.close()


def main():
    root = tk.Tk()
    app = SecOCGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
