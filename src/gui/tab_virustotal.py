"""
VirusTotal & Organization Tab - Scan APKs and organize dataset
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QGroupBox, QProgressBar, QTextEdit,
                             QMessageBox, QLineEdit, QFileDialog, QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from pathlib import Path
from typing import Dict, List
import json


class VirusTotalScannerWorker(QThread):
    """Worker thread for VirusTotal scanning"""

    progress = pyqtSignal(int, int, str, str)  # current, total, filename, status
    scan_result = pyqtSignal(dict)  # scan result for single APK
    finished = pyqtSignal(list)  # all results
    error = pyqtSignal(str)

    def __init__(self, apk_table, api_key: str):
        super().__init__()
        self.apk_table = apk_table
        self.api_key = api_key
        self.is_running = True
        self.results = []

    def run(self):
        """Scan all APKs with VirusTotal"""
        try:
            from core.virustotal_scanner import VirusTotalScanner

            scanner = VirusTotalScanner(self.api_key)
            total = self.apk_table.rowCount()

            for row in range(total):
                if not self.is_running:
                    break

                # Get APK info
                filename_item = self.apk_table.item(row, 1)
                path_item = self.apk_table.item(row, 4)

                if not (filename_item and path_item):
                    continue

                filename = filename_item.text()
                apk_path = path_item.text()

                self.progress.emit(row + 1, total, filename, "Scanning...")

                try:
                    # Scan with VirusTotal
                    scan_data = scanner.scan_file(apk_path)

                    if scan_data:
                        label, family, detections, total_engines = scanner.parse_scan_results(scan_data)

                        result = {
                            'filename': filename,
                            'path': apk_path,
                            'label': label,
                            'family': family,
                            'detections': detections,
                            'total_engines': total_engines
                        }

                        self.results.append(result)
                        self.scan_result.emit(result)

                        # Update table label
                        label_item = self.apk_table.item(row, 2)
                        if label_item:
                            label_item.setText(f"{label} ({family})" if label == "MALWARE" else label)
                            if label == "MALWARE":
                                label_item.setBackground(Qt.red)
                            elif label == "BENIGN":
                                label_item.setBackground(Qt.green)
                            elif label == "SUSPICIOUS":
                                label_item.setBackground(Qt.yellow)

                        self.progress.emit(row + 1, total, filename,
                                         f"✓ {label} - {detections}/{total_engines}")
                    else:
                        self.error.emit(f"Failed to scan: {filename}")
                        self.progress.emit(row + 1, total, filename, "✗ Failed")

                except Exception as e:
                    self.error.emit(f"Error scanning {filename}: {str(e)}")
                    continue

            self.finished.emit(self.results)

        except Exception as e:
            self.error.emit(f"Fatal error: {str(e)}")

    def stop(self):
        """Stop the worker"""
        self.is_running = False


class VirusTotalTab(QWidget):
    """VirusTotal scanning and dataset organization tab"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.apk_table = None
        self.worker = None
        self.scan_results = []
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Title
        title = QLabel("VirusTotal Scanner & Dataset Organizer")
        title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(title)

        # API Key configuration
        api_group = self.create_api_group()
        layout.addWidget(api_group)

        # Scan controls
        scan_group = self.create_scan_group()
        layout.addWidget(scan_group)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Scan log
        log_group = QGroupBox("Scan Log")
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        # Organization controls
        org_group = self.create_organization_group()
        layout.addWidget(org_group)

        # Status
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet("padding: 10px; background-color: #e3f2fd;")
        layout.addWidget(self.status_label)

        layout.addStretch()
        self.setLayout(layout)

    def create_api_group(self) -> QGroupBox:
        """Create API key configuration group"""
        group = QGroupBox("VirusTotal API Configuration")
        layout = QVBoxLayout()

        # API Key input
        key_layout = QHBoxLayout()
        key_label = QLabel("API Key:")
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setText("100849ae80b6a59a79aab3e988a5493f1fd0eb45268e7bd59d82036cc34f6d44")
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.api_key_input)

        show_key_btn = QPushButton("Show/Hide")
        show_key_btn.clicked.connect(self.toggle_api_key_visibility)
        key_layout.addWidget(show_key_btn)

        layout.addLayout(key_layout)

        # Rate limit info
        info = QLabel("ℹ️ Free API: 4 requests/minute, 500 requests/day\n"
                     "Scanning will automatically respect rate limits (15 sec between requests)")
        info.setStyleSheet("color: #ff9800; font-size: 11px; padding: 5px;")
        layout.addWidget(info)

        group.setLayout(layout)
        return group

    def create_scan_group(self) -> QGroupBox:
        """Create scan controls group"""
        group = QGroupBox("VirusTotal Scanning")
        layout = QVBoxLayout()

        # Buttons
        button_layout = QHBoxLayout()

        self.start_scan_btn = QPushButton("🔍 Start Scanning")
        self.start_scan_btn.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; font-weight: bold;")
        self.start_scan_btn.clicked.connect(self.start_scanning)
        button_layout.addWidget(self.start_scan_btn)

        self.stop_scan_btn = QPushButton("Stop")
        self.stop_scan_btn.setStyleSheet("background-color: #f44336; color: white; padding: 10px;")
        self.stop_scan_btn.clicked.connect(self.stop_scanning)
        self.stop_scan_btn.setEnabled(False)
        button_layout.addWidget(self.stop_scan_btn)

        layout.addLayout(button_layout)

        # Options
        self.save_results_checkbox = QCheckBox("Save scan results to JSON")
        self.save_results_checkbox.setChecked(True)
        layout.addWidget(self.save_results_checkbox)

        group.setLayout(layout)
        return group

    def create_organization_group(self) -> QGroupBox:
        """Create organization controls group"""
        group = QGroupBox("Dataset Organization")
        layout = QVBoxLayout()

        # Output path
        path_layout = QHBoxLayout()
        path_label = QLabel("Output Folder:")
        self.org_path_input = QLineEdit()
        self.org_path_input.setPlaceholderText("Select output folder for organized dataset...")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_organization_path)
        path_layout.addWidget(path_label)
        path_layout.addWidget(self.org_path_input)
        path_layout.addWidget(browse_btn)
        layout.addLayout(path_layout)

        # Organize button
        self.organize_btn = QPushButton("📁 Organize Dataset by Classification")
        self.organize_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px; font-weight: bold;")
        self.organize_btn.clicked.connect(self.organize_dataset)
        self.organize_btn.setEnabled(False)
        layout.addWidget(self.organize_btn)

        # Info
        info = QLabel("Organizes APKs into folders:\n"
                     "  benign/ - Benign applications\n"
                     "  malware/[family]/ - Malware by family (trojan, adware, etc.)\n"
                     "  suspicious/ - Suspicious files\n"
                     "  unknown/ - Unknown classification")
        info.setStyleSheet("font-size: 11px; padding: 5px;")
        layout.addWidget(info)

        group.setLayout(layout)
        return group

    def set_apk_table(self, apk_table):
        """Set reference to APK table"""
        self.apk_table = apk_table

    def toggle_api_key_visibility(self):
        """Toggle API key visibility"""
        if self.api_key_input.echoMode() == QLineEdit.Password:
            self.api_key_input.setEchoMode(QLineEdit.Normal)
        else:
            self.api_key_input.setEchoMode(QLineEdit.Password)

    def browse_organization_path(self):
        """Browse for organization output folder"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Folder for Organized Dataset",
            str(Path.home())
        )
        if directory:
            self.org_path_input.setText(directory)

    def start_scanning(self):
        """Start VirusTotal scanning"""
        if not self.apk_table or self.apk_table.rowCount() == 0:
            QMessageBox.warning(self, "No APKs", "Please load APK files first")
            return

        api_key = self.api_key_input.text().strip()
        if not api_key:
            QMessageBox.warning(self, "No API Key", "Please enter your VirusTotal API key")
            return

        # Confirm action
        reply = QMessageBox.question(
            self,
            "Start Scanning",
            f"This will scan {self.apk_table.rowCount()} APKs with VirusTotal.\n\n"
            f"⚠️ Important:\n"
            f"- Rate limit: 15 seconds between requests\n"
            f"- Estimated time: {self.apk_table.rowCount() * 15 / 60:.1f} minutes\n"
            f"- Daily limit: 500 requests\n\n"
            f"Continue?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.No:
            return

        # Start scanning
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.log_text.clear()
        self.scan_results = []

        self.log_text.append("=" * 60)
        self.log_text.append("Starting VirusTotal scanning...")
        self.log_text.append(f"Total APKs: {self.apk_table.rowCount()}")
        self.log_text.append("=" * 60)

        # Create and start worker
        self.worker = VirusTotalScannerWorker(self.apk_table, api_key)
        self.worker.progress.connect(self.on_scan_progress)
        self.worker.scan_result.connect(self.on_scan_result)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()

    def stop_scanning(self):
        """Stop scanning"""
        if self.worker:
            self.worker.stop()
            self.log_text.append("\nStopping scan...")

    def on_scan_progress(self, current: int, total: int, filename: str, status: str):
        """Handle scan progress"""
        percentage = int((current / total) * 100)
        self.progress_bar.setValue(percentage)
        self.status_label.setText(f"Scanning {current}/{total}: {filename}")
        self.log_text.append(f"[{current}/{total}] {filename}: {status}")

    def on_scan_result(self, result: dict):
        """Handle single scan result"""
        self.scan_results.append(result)

    def on_scan_finished(self, results: list):
        """Handle scan completion"""
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.organize_btn.setEnabled(True)

        # Statistics
        malware_count = sum(1 for r in results if r['label'] == 'MALWARE')
        benign_count = sum(1 for r in results if r['label'] == 'BENIGN')
        suspicious_count = sum(1 for r in results if r['label'] == 'SUSPICIOUS')

        self.log_text.append("\n" + "=" * 60)
        self.log_text.append("Scanning completed!")
        self.log_text.append(f"Total scanned: {len(results)}")
        self.log_text.append(f"  Malware: {malware_count}")
        self.log_text.append(f"  Benign: {benign_count}")
        self.log_text.append(f"  Suspicious: {suspicious_count}")
        self.log_text.append("=" * 60)

        self.status_label.setText(f"Scan completed: {len(results)} APKs scanned")

        # Save results if requested
        if self.save_results_checkbox.isChecked():
            self.save_scan_results(results)

        QMessageBox.information(
            self,
            "Scan Complete",
            f"VirusTotal scanning completed!\n\n"
            f"Total: {len(results)}\n"
            f"Malware: {malware_count}\n"
            f"Benign: {benign_count}\n"
            f"Suspicious: {suspicious_count}"
        )

    def on_scan_error(self, error_msg: str):
        """Handle scan error"""
        self.log_text.append(f"⚠️ ERROR: {error_msg}")

    def save_scan_results(self, results: list):
        """Save scan results to JSON"""
        try:
            output_file = Path("virustotal_scan_results.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            self.log_text.append(f"\n✓ Scan results saved to: {output_file.absolute()}")
        except Exception as e:
            self.log_text.append(f"\n✗ Failed to save results: {str(e)}")

    def organize_dataset(self):
        """Organize dataset by classification"""
        if not self.scan_results:
            QMessageBox.warning(self, "No Results", "Please scan APKs first")
            return

        output_path = self.org_path_input.text().strip()
        if not output_path:
            QMessageBox.warning(self, "No Path", "Please select an output folder")
            return

        try:
            from core.dataset_organizer import DatasetOrganizer

            organizer = DatasetOrganizer(output_path)
            organizer.create_folder_structure()

            self.log_text.append("\n" + "=" * 60)
            self.log_text.append("Organizing dataset...")

            metadata = []
            for result in self.scan_results:
                dest_path = organizer.organize_apk(
                    result['path'],
                    result['label'],
                    result['family']
                )

                metadata.append({
                    'original_path': result['path'],
                    'new_path': str(dest_path),
                    'label': result['label'],
                    'family': result['family'],
                    'detections': f"{result['detections']}/{result['total_engines']}"
                })

                self.log_text.append(f"✓ {result['filename']} → {result['label']}/{result['family']}")

            # Save metadata
            organizer.save_metadata(metadata)

            # Generate report
            report = organizer.generate_report()
            self.log_text.append("\n" + report)

            QMessageBox.information(
                self,
                "Organization Complete",
                f"Dataset organized successfully!\n\n{report}"
            )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to organize dataset:\n{str(e)}")
            self.log_text.append(f"\n✗ Organization failed: {str(e)}")
