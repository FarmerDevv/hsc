#!/usr/bin/env python3
import sys
import argparse
import hashlib
import threading
import time
import os

try:
    from colorama import init
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("Gerekli kütüphaneler eksik: pip install colorama rich")
    sys.exit(1)

console = Console()

def _md5(x): return hashlib.md5(x.encode('utf-8', errors='ignore')).hexdigest()
def _sha1(x): return hashlib.sha1(x.encode('utf-8', errors='ignore')).hexdigest()
def _sha224(x): return hashlib.sha224(x.encode('utf-8', errors='ignore')).hexdigest()
def _sha256(x): return hashlib.sha256(x.encode('utf-8', errors='ignore')).hexdigest()
def _sha384(x): return hashlib.sha384(x.encode('utf-8', errors='ignore')).hexdigest()
def _sha512(x): return hashlib.sha512(x.encode('utf-8', errors='ignore')).hexdigest()
def _sha3_224(x): return hashlib.sha3_224(x.encode('utf-8', errors='ignore')).hexdigest()
def _sha3_256(x): return hashlib.sha3_256(x.encode('utf-8', errors='ignore')).hexdigest()
def _sha3_384(x): return hashlib.sha3_384(x.encode('utf-8', errors='ignore')).hexdigest()
def _sha3_512(x): return hashlib.sha3_512(x.encode('utf-8', errors='ignore')).hexdigest()
def _blake2b(x): return hashlib.blake2b(x.encode('utf-8', errors='ignore')).hexdigest()
def _blake2s(x): return hashlib.blake2s(x.encode('utf-8', errors='ignore')).hexdigest()
def _ripemd160(x): return hashlib.new('ripemd160', x.encode('utf-8', errors='ignore')).hexdigest()
def _whirlpool(x): return hashlib.new('whirlpool', x.encode('utf-8', errors='ignore')).hexdigest()
def _md4(x): return hashlib.new('md4', x.encode('utf-8', errors='ignore')).hexdigest()
def _ntlm(x): return hashlib.new('md4', x.encode('utf-16le', errors='ignore')).hexdigest()
def _lm_hash(x):
    x = x.upper()[:14].ljust(14, '\x00')
    magic = b"KGS!@#$%"
    part1 = hashlib.new('des', bytes([((ord(x[0]) << 1) & 0xfe)]))
    part1.update(magic)
    part2 = hashlib.new('des', bytes([((ord(x[1]) << 1) & 0xfe)]))
    part2.update(magic)
    return (part1.digest()[:8] + part2.digest()[:8]).hex()
def _shake128_hash(x): return hashlib.shake_128(x.encode('utf-8', errors='ignore')).hexdigest(32)
def _shake256_hash(x): return hashlib.shake_256(x.encode('utf-8', errors='ignore')).hexdigest(64)

HASH_FUNCTIONS = {
    'md5': _md5, 'sha1': _sha1, 'sha224': _sha224, 'sha256': _sha256, 'sha384': _sha384, 'sha512': _sha512,
    'sha3_224': _sha3_224, 'sha3_256': _sha3_256, 'sha3_384': _sha3_384, 'sha3_512': _sha3_512,
    'shake_128': _shake128_hash, 'shake_256': _shake256_hash,
    'blake2b': _blake2b, 'blake2s': _blake2s,
    'ripemd160': _ripemd160, 'whirlpool': _whirlpool, 'md4': _md4, 'ntlm': _ntlm, 'lm': _lm_hash
}

def launch_gui():
    try:
        from PyQt5.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
            QLabel, QLineEdit, QComboBox, QPushButton, QFileDialog, QTextEdit,
            QTabWidget, QStatusBar, QMessageBox
        )
        from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
        from PyQt5.QtGui import QFont, QColor, QPalette, QDesktopServices

        class CrackerWorker(QThread):
            found = pyqtSignal(str, float)
            log_message = pyqtSignal(str, str)
            finished_signal = pyqtSignal()
            status_update = pyqtSignal(str)

            def __init__(self, target_hash, wordlist, hash_type):
                super().__init__()
                self.target_hash = target_hash.lower().strip()
                self.wordlist = wordlist
                self.hash_type = hash_type
                self._stop = False

            def run(self):
                start_time = time.time()
                hf = HASH_FUNCTIONS.get(self.hash_type)
                if not hf:
                    self.log_message.emit("ERROR", f"Unsupported hash type: {self.hash_type}")
                    self.finished_signal.emit()
                    return

                self.log_message.emit("INFO", f"Cracking started for hash type: {self.hash_type}")
                self.log_message.emit("INFO", f"Target hash: {self.target_hash}")
                self.log_message.emit("INFO", f"Wordlist: {self.wordlist}")

                if not os.path.isfile(self.wordlist):
                    self.log_message.emit("ERROR", f"Wordlist not found: {self.wordlist}")
                    self.finished_signal.emit()
                    return

                total_lines = 0
                try:
                    with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                        total_lines = sum(1 for _ in f)
                    self.log_message.emit("INFO", f"Wordlist loaded. Total entries: {total_lines}")
                except Exception as e:
                    self.log_message.emit("ERROR", f"Failed to read wordlist: {str(e)}")
                    self.finished_signal.emit()
                    return

                line_num = 0
                try:
                    with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                        for word in f:
                            if self._stop:
                                self.log_message.emit("INFO", "Cracking stopped by user.")
                                return
                            line_num += 1
                            word = word.rstrip('\r\n')
                            if not word:
                                continue
                            try:
                                computed = hf(word)
                                self.log_message.emit("TRY", f"Line {line_num}: '{word}' → {computed}")
                                if computed == self.target_hash:
                                    elapsed = time.time() - start_time
                                    self.found.emit(word, elapsed)
                                    return
                            except Exception as e:
                                self.log_message.emit("WARN", f"Hashing failed at line {line_num}: {str(e)}")
                except Exception as e:
                    self.log_message.emit("FATAL", f"Unexpected error: {str(e)}")

                if not self._stop:
                    self.finished_signal.emit()

            def stop(self):
                self._stop = True

        class HSCMainWindow(QMainWindow):
            def __init__(self):
                super().__init__()
                self.worker = None
                self.init_ui()

            def init_ui(self):
                self.setWindowTitle("HSC")
                self.resize(940, 720)

                palette = QPalette()
                palette.setColor(QPalette.Window, QColor(22, 22, 22))
                palette.setColor(QPalette.WindowText, QColor(240, 240, 240))
                palette.setColor(QPalette.Base, QColor(30, 30, 30))
                palette.setColor(QPalette.AlternateBase, QColor(40, 40, 40))
                palette.setColor(QPalette.ToolTipBase, Qt.white)
                palette.setColor(QPalette.ToolTipText, Qt.white)
                palette.setColor(QPalette.Text, QColor(240, 240, 240))
                palette.setColor(QPalette.Button, QColor(50, 50, 50))
                palette.setColor(QPalette.ButtonText, QColor(240, 240, 240))
                palette.setColor(QPalette.BrightText, Qt.red)
                palette.setColor(QPalette.Highlight, QColor(0, 120, 212))
                palette.setColor(QPalette.HighlightedText, Qt.black)
                self.setPalette(palette)

                font = QFont("Segoe UI", 10)
                self.setFont(font)

                central_widget = QWidget()
                self.setCentralWidget(central_widget)
                main_layout = QVBoxLayout(central_widget)
                main_layout.setContentsMargins(0, 0, 0, 0)

                title_label = QLabel("HSC — Hash Security Cracker")
                title_label.setAlignment(Qt.AlignCenter)
                title_label.setFont(QFont("Segoe UI", 16, QFont.Bold))
                title_label.setStyleSheet("color: #0078D4; padding: 12px 0; background-color: #1a1a1a; margin: 0;")
                main_layout.addWidget(title_label)

                self.tabs = QTabWidget()
                self.tabs.setStyleSheet("""
                    QTabWidget::pane { border: 1px solid #3a3a3a; top: -1px; }
                    QTabBar::tab {
                        background: #2a2a2a;
                        color: #cccccc;
                        padding: 10px 20px;
                        margin-right: 2px;
                        border-top-left-radius: 4px;
                        border-top-right-radius: 4px;
                    }
                    QTabBar::tab:selected {
                        background: #0078D4;
                        color: white;
                    }
                    QTabBar::tab:hover:!selected {
                        background: #3a3a3a;
                    }
                """)
                main_layout.addWidget(self.tabs)

                self.create_hsc_tab()
                self.create_about_tab()

                self.status_bar = QStatusBar()
                self.status_bar.setStyleSheet("background: #1a1a1a; color: #aaaaaa; font-size: 9pt;")
                self.setStatusBar(self.status_bar)
                self.status_bar.showMessage("Ready")

            def create_hsc_tab(self):
                tab = QWidget()
                layout = QVBoxLayout(tab)
                layout.setContentsMargins(20, 20, 20, 20)
                layout.setSpacing(16)

                input_widget = QWidget()
                input_layout = QGridLayout(input_widget)
                input_layout.setSpacing(12)
                input_layout.setContentsMargins(0, 0, 0, 0)

                input_layout.addWidget(QLabel("Target Hash:"), 0, 0)
                self.hash_input = QLineEdit()
                self.hash_input.setPlaceholderText("Enter hash value")
                input_layout.addWidget(self.hash_input, 0, 1)

                input_layout.addWidget(QLabel("Hash Type:"), 1, 0)
                self.hash_type_combo = QComboBox()
                self.hash_type_combo.addItems(sorted(HASH_FUNCTIONS.keys()))
                input_layout.addWidget(self.hash_type_combo, 1, 1)

                input_layout.addWidget(QLabel("Wordlist:"), 2, 0)
                wl_layout = QHBoxLayout()
                self.wordlist_input = QLineEdit()
                self.wordlist_input.setPlaceholderText("Path to wordlist file")
                browse_btn = QPushButton("Browse")
                browse_btn.setFixedWidth(90)
                browse_btn.clicked.connect(self.select_wordlist)
                wl_layout.addWidget(self.wordlist_input)
                wl_layout.addWidget(browse_btn)
                input_layout.addLayout(wl_layout, 2, 1)

                layout.addWidget(input_widget)

                button_layout = QHBoxLayout()
                self.start_btn = QPushButton("Start Cracking")
                self.start_btn.setFixedHeight(38)
                self.start_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #0078D4;
                        color: white;
                        font-weight: bold;
                        border: none;
                        border-radius: 4px;
                        padding: 0 20px;
                    }
                    QPushButton:hover {
                        background-color: #106EBE;
                    }
                    QPushButton:pressed {
                        background-color: #005A9E;
                    }
                """)
                self.start_btn.clicked.connect(self.toggle_cracking)
                button_layout.addStretch()
                button_layout.addWidget(self.start_btn)
                button_layout.addStretch()
                layout.addLayout(button_layout)

                log_label = QLabel("Output Log")
                log_label.setStyleSheet("font-weight: bold; color: #0078D4; font-size: 10pt;")
                layout.addWidget(log_label)

                self.output_log = QTextEdit()
                self.output_log.setReadOnly(True)
                self.output_log.setFont(QFont("Consolas", 9))
                self.output_log.setStyleSheet("""
                    QTextEdit {
                        background-color: #1e1e1e;
                        color: #d4d4d4;
                        border: 1px solid #3a3a3a;
                        padding: 10px;
                        line-height: 1.4;
                    }
                """)
                layout.addWidget(self.output_log)

                self.tabs.addTab(tab, "HSC")
            def create_about_tab(self):
                tab = QWidget()
                layout = QVBoxLayout(tab)
                layout.setAlignment(Qt.AlignTop)
                layout.setSpacing(18)
                layout.setContentsMargins(40, 40, 40, 40)

                title = QLabel("About HSC")
                title.setFont(QFont("Segoe UI", 16, QFont.Bold))
                title.setStyleSheet("color: #0078D4;")
                title.setAlignment(Qt.AlignCenter)
                layout.addWidget(title)

                desc = QLabel(
                    "HSC (Hash Security Cracker) is indie hash cracker\n"
                    "Designed for Farmerdevv.\n\n"
                    "Features include multi-threaded cracking, 20+ supported hash algorithms, detailed logging,\n"
                    "and an enterprise-ready graphical interface."
                )
                desc.setWordWrap(True)
                desc.setAlignment(Qt.AlignCenter)
                desc.setStyleSheet("color: #cccccc; font-size: 10pt; line-height: 1.5;")
                layout.addWidget(desc)

                github_label = QLabel('<a href="#" style="color: #0078D4; text-decoration: none; font-weight: bold;">● GitHub Repository</a>')
                github_label.setAlignment(Qt.AlignCenter)
                github_label.setOpenExternalLinks(False)
                github_label.linkActivated.connect(self.open_github)
                layout.addWidget(github_label)

                layout.addStretch()
                self.tabs.addTab(tab, "About")

            def open_github(self):
                QDesktopServices.openUrl(QUrl("https://github.com/FarmerDevv"))

            def select_wordlist(self):
                path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
                if path:
                    self.wordlist_input.setText(path)

            def toggle_cracking(self):
                if self.worker and self.worker.isRunning():
                    self.worker.stop()
                    self.start_btn.setText("Start Cracking")
                    self.start_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #0078D4;
                            color: white;
                            font-weight: bold;
                            border: none;
                            border-radius: 4px;
                            padding: 0 20px;
                        }
                    """)
                    self.status_bar.showMessage("Stopped by user")
                    return

                target_hash = self.hash_input.text().strip()
                wordlist = self.wordlist_input.text().strip()
                hash_type = self.hash_type_combo.currentText().strip()

                if not target_hash or not wordlist or not hash_type:
                    QMessageBox.warning(self, "Input Error", "All fields are required.")
                    return

                if hash_type not in HASH_FUNCTIONS:
                    QMessageBox.warning(self, "Hash Error", f"Unsupported hash type: {hash_type}")
                    return

                self.worker = CrackerWorker(target_hash, wordlist, hash_type)
                self.worker.found.connect(self.on_found)
                self.worker.log_message.connect(self.on_log_message)
                self.worker.finished_signal.connect(self.on_finished)
                self.worker.status_update.connect(self.status_bar.showMessage)
                self.worker.start()

                self.start_btn.setText("Stop Cracking")
                self.start_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #D73B3B;
                        color: white;
                        font-weight: bold;
                        border: none;
                        border-radius: 4px;
                        padding: 0 20px;
                    }
                    QPushButton:hover {
                        background-color: #B53232;
                    }
                    QPushButton:pressed {
                        background-color: #9A2A2A;
                    }
                """)
                self.output_log.clear()
                self.status_bar.showMessage(f"Cracking started... (Hash: {hash_type})")

            def on_found(self, password, elapsed):
                self.output_log.append(f"\n<span style='color:#4CAF50; font-weight:bold;'>[SUCCESS] HASH CRACKED!</span>")
                self.output_log.append(f"<span style='color:#4CAF50;'>Password: {password}</span>")
                self.output_log.append(f"<span style='color:#4CAF50;'>Time: {elapsed:.2f} seconds</span>")
                self.start_btn.setText("Start Cracking")
                self.start_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #0078D4;
                        color: white;
                        font-weight: bold;
                        border: none;
                        border-radius: 4px;
                        padding: 0 20px;
                    }
                """)
                self.status_bar.showMessage("Cracking completed — Password found")

            def on_log_message(self, level, message):
                timestamp = time.strftime("%H:%M:%S")
                color = {
                    "INFO": "#0078D4",
                    "WARN": "#FFAA00",
                    "ERROR": "#D73B3B",
                    "FATAL": "#B53232",
                    "TRY": "#888888"
                }.get(level, "#888888")
                formatted = f"<span style='color:{color};'>[{timestamp}] [{level}] {message}</span>"
                self.output_log.append(formatted)

            def on_finished(self):
                if self.start_btn.text() == "Stop Cracking":
                    self.output_log.append("\n<span style='color:#D73B3B;'>[RESULT] Password not found.</span>")
                    self.start_btn.setText("Start Cracking")
                    self.start_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #0078D4;
                            color: white;
                            font-weight: bold;
                            border: none;
                            border-radius: 4px;
                            padding: 0 20px;
                        }
                    """)
                    self.status_bar.showMessage("Cracking completed — Password not found")

        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        window = HSCMainWindow()
        window.show()
        sys.exit(app.exec_())

    except ImportError:
        print("GUI requires PyQt5. Install with: pip install pyqt5")
        sys.exit(1)

def crack_hash(target_hash, wordlist, hash_type, verbose=False, max_threads=4):
    hf = HASH_FUNCTIONS.get(hash_type.lower())
    if not hf:
        raise ValueError(f"Unsupported hash type: {hash_type}. Supported: {list(HASH_FUNCTIONS.keys())}")

    found = threading.Event()
    result = [None]
    lock = threading.Lock()

    def worker(words):
        for word in words:
            if found.is_set():
                return
            word = word.rstrip('\r\n')
            if not word:
                continue
            try:
                computed = hf(word)
                if verbose:
                    with lock:
                        console.print(f"[dim][TRY] '{word}' → {computed}[/dim]")
                if computed == target_hash.lower():
                    result[0] = word
                    found.set()
                    return
            except Exception as e:
                if verbose:
                    with lock:
                        console.print(f"[red][ERROR] Hashing failed for '{word}': {e}[/red]")

    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            words = f.read().splitlines()
    except FileNotFoundError:
        console.print(f"[bold red]Wordlist not found: {wordlist}[/bold red]")
        return None

    chunk_size = max(1, len(words) // max_threads)
    threads = []
    start_time = time.time()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task("Cracking...", total=None)
        for i in range(0, len(words), chunk_size):
            chunk = words[i:i + chunk_size]
            t = threading.Thread(target=worker, args=(chunk,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    elapsed = time.time() - start_time
    return {"password": result[0], "time": elapsed} if result[0] else None

def main():
    if "--gui" in sys.argv or "-gui" in sys.argv:
        launch_gui()
        return

    parser = argparse.ArgumentParser(
        prog="HSC",
        description="HSC — Hash Security Cracker (Enterprise-Grade)",
        epilog="Example: hsc -H 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt -t sha256"
    )
    parser.add_argument("-H", "--hash", required=True, help="Target hash value")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-t", "--type", default="md5", choices=list(HASH_FUNCTIONS.keys()), help="Hash algorithm")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (logs every attempt)")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads")
    parser.add_argument("--gui", action="store_true", help="Launch GUI mode")

    args = parser.parse_args()

    init(autoreset=True)
    table = Table(show_header=False, box=None)
    table.add_row("[bold cyan]HSC — Hash Security Cracker[/bold cyan]")
    table.add_row(f"[green]Target Hash:[/green] {args.hash}")
    table.add_row(f"[green]Hash Type:[/green] {args.type}")
    table.add_row(f"[green]Wordlist:[/green] {args.wordlist}")
    console.print(Panel(table, title="Configuration", border_style="blue"))

    result = crack_hash(
        target_hash=args.hash,
        wordlist=args.wordlist,
        hash_type=args.type,
        verbose=args.verbose,
        max_threads=args.threads
    )

    if result:
        console.print("\n" + "="*50, style="bold green")
        console.print("[bold green]✅ HASH CRACKED![/bold green]")
        console.print(f"[bold]Password:[/bold] [cyan]{result['password']}[/cyan]")
        console.print(f"[bold]Time:[/bold] [magenta]{result['time']:.2f} seconds[/magenta]")
        console.print("="*50, style="bold green")
    else:
        console.print("\n[bold red]❌ Password not found.[/bold red]")

if __name__ == "__main__":
    main()