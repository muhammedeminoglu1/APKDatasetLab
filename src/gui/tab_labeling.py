"""
Labeling Tab - Unified labeling with VirusTotal, Hash DB, Folder-based, and Manual
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QGroupBox, QPushButton,
                             QLabel, QLineEdit, QSpinBox, QHBoxLayout,
                             QProgressBar, QTextEdit, QMessageBox, QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from pathlib import Path

from core.workspace_manager import WorkspaceManager
from core.virustotal_scanner import VirusTotalScanner
from core.androzoo_client import AndroZooClient
from utils.translator import tr


class VirusTotalThread(QThread):
    """Thread for VirusTotal scanning"""
    progress = pyqtSignal(int, int)  # current, total
    result = pyqtSignal(str, str, str)  # filename, label, family
    finished_scan = pyqtSignal()

    def __init__(self, api_key, threshold, apk_list):
        super().__init__()
        self.api_key = api_key
        self.threshold = threshold
        self.apk_list = apk_list
        self.scanner = VirusTotalScanner(api_key)

    def run(self):
        workspace = WorkspaceManager()

        for i, apk_file in enumerate(self.apk_list):
            try:
                # Calculate file hash
                file_hash = self.scanner.calculate_file_hash(apk_file)

                # Check if file exists in VirusTotal
                report = self.scanner.get_file_report(file_hash)

                if not report:
                    # File not found, scan it
                    report = self.scanner.scan_file(apk_file)

                # Parse results
                if report:
                    label, family, detections, total = self.scanner.parse_scan_results(report)

                    # Apply threshold
                    if detections < self.threshold:
                        label = 'BENIGN'
                        family = None
                else:
                    label = 'UNKNOWN'
                    family = 'unknown'
                    detections = 0

                # Organize
                if label != 'UNKNOWN':
                    try:
                        workspace.organize_apk(
                            Path(apk_file).name,
                            label,
                            family
                        )
                    except Exception as e:
                        print(f"Error organizing {apk_file}: {e}")

                # Emit result
                self.result.emit(
                    Path(apk_file).name,
                    label,
                    family or '-'
                )

            except Exception as e:
                print(f"Error scanning {apk_file}: {e}")
                self.result.emit(
                    Path(apk_file).name,
                    'ERROR',
                    str(e)
                )

            self.progress.emit(i + 1, len(self.apk_list))

        self.finished_scan.emit()


class AndroZooThread(QThread):
    """Thread for AndroZoo hash database lookup"""
    progress = pyqtSignal(int, int)  # current, total
    result = pyqtSignal(str, str, str, int, str)  # filename, suggested_label, confidence, vt_detections, reasoning
    status = pyqtSignal(str)  # status message
    finished_scan = pyqtSignal(int, int)  # found, total

    def __init__(self, api_key, vt_threshold, apk_list, db_loaded=False, androzoo_client=None):
        super().__init__()
        self.api_key = api_key
        self.vt_threshold = vt_threshold
        self.apk_list = apk_list
        self.db_loaded = db_loaded
        self.client = androzoo_client

    def run(self):
        workspace = WorkspaceManager()

        # Initialize client if not provided
        if not self.client:
            self.status.emit("Initializing AndroZoo client...")
            self.client = AndroZooClient(self.api_key)

        # Download CSV if needed
        if not self.db_loaded and not self.client.csv_cache_path.exists():
            self.status.emit("Downloading AndroZoo database (~2.7GB)... This may take several minutes.")
            if not self.client.download_csv_database():
                self.status.emit("ERROR: Failed to download database")
                self.finished_scan.emit(0, len(self.apk_list))
                return

        # Load database
        if not self.db_loaded:
            self.status.emit("Loading AndroZoo database into memory...")
            if not self.client.load_csv_database():
                self.status.emit("ERROR: Failed to load database")
                self.finished_scan.emit(0, len(self.apk_list))
                return

        self.status.emit(f"Querying {len(self.apk_list)} APKs...")

        found_count = 0
        for i, apk_file in enumerate(self.apk_list):
            try:
                # Query APK
                metadata = self.client.query_apk_file(apk_file)

                if metadata:
                    found_count += 1

                    # Get label suggestion
                    suggestion = self.client.suggest_label(metadata, self.vt_threshold)

                    # Emit result (don't auto-organize, just suggest)
                    self.result.emit(
                        Path(apk_file).name,
                        suggestion['suggested_label'],
                        f"{suggestion['confidence']}%",
                        suggestion['vt_detections'],
                        suggestion['reasoning']
                    )
                else:
                    self.result.emit(
                        Path(apk_file).name,
                        'NOT_FOUND',
                        'N/A',
                        0,
                        'APK not found in AndroZoo database'
                    )

            except Exception as e:
                print(f"Error querying {apk_file}: {e}")
                self.result.emit(
                    Path(apk_file).name,
                    'ERROR',
                    'N/A',
                    0,
                    str(e)
                )

            self.progress.emit(i + 1, len(self.apk_list))

        self.finished_scan.emit(found_count, len(self.apk_list))


class LabelingTab(QWidget):
    """Unified labeling tab with all methods"""

    def __init__(self):
        super().__init__()
        self.workspace = WorkspaceManager()
        self.parent_window = None
        self.vt_thread = None
        self.az_thread = None
        self.androzoo_client = None
        self.az_db_loaded = False
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # 1. Folder-based labeling
        folder_group = self.create_folder_group()
        layout.addWidget(folder_group)

        # 2. Hash database (placeholder for now)
        hash_group = self.create_hash_group()
        layout.addWidget(hash_group)

        # 3. VirusTotal (MOVED FROM SEPARATE TAB)
        vt_group = self.create_virustotal_group()
        layout.addWidget(vt_group)

        # 4. Manual labeling
        manual_group = self.create_manual_group()
        layout.addWidget(manual_group)

        # 5. Status
        status_group = self.create_status_group()
        layout.addWidget(status_group)

        layout.addStretch()
        self.setLayout(layout)

    def create_folder_group(self) -> QGroupBox:
        """Folder-based labeling"""
        group = QGroupBox(tr('group_folder_labeling'))
        layout = QVBoxLayout()

        info = QLabel("Automatically detect APKs in malware/ and benign/ folders")
        info.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(info)

        self.folder_btn = QPushButton(tr('btn_scan_folders'))
        self.folder_btn.clicked.connect(self.scan_folder_structure)
        layout.addWidget(self.folder_btn)

        group.setLayout(layout)
        return group

    def create_hash_group(self) -> QGroupBox:
        """Hash database labeling"""
        group = QGroupBox(tr('group_hash_labeling'))
        layout = QVBoxLayout()

        info = QLabel("Check APKs against AndroZoo hash database")
        info.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(info)

        # AndroZoo API Key
        api_key_layout = QHBoxLayout()
        api_key_layout.addWidget(QLabel("AndroZoo API Key:"))
        self.az_api_key_input = QLineEdit()
        self.az_api_key_input.setPlaceholderText("Enter your AndroZoo API key")
        self.az_api_key_input.setEchoMode(QLineEdit.Password)
        api_key_layout.addWidget(self.az_api_key_input)
        layout.addLayout(api_key_layout)

        # VT Detection Threshold
        threshold_layout = QHBoxLayout()
        threshold_layout.addWidget(QLabel("VT Detection Threshold:"))
        self.az_threshold_spin = QSpinBox()
        self.az_threshold_spin.setRange(1, 70)
        self.az_threshold_spin.setValue(5)
        self.az_threshold_spin.setToolTip("Minimum VirusTotal detections to classify as MALWARE")
        threshold_layout.addWidget(self.az_threshold_spin)
        threshold_layout.addStretch()
        layout.addLayout(threshold_layout)

        # Progress bar (hidden by default)
        self.az_progress = QProgressBar()
        self.az_progress.setVisible(False)
        layout.addWidget(self.az_progress)

        # Lookup button
        self.hash_btn = QPushButton(tr('btn_hash_lookup'))
        self.hash_btn.clicked.connect(self.check_hash_database)
        layout.addWidget(self.hash_btn)

        # Log area
        self.az_log = QTextEdit()
        self.az_log.setMaximumHeight(150)
        self.az_log.setReadOnly(True)
        layout.addWidget(self.az_log)

        group.setLayout(layout)
        return group

    def create_virustotal_group(self) -> QGroupBox:
        """VirusTotal scanning group"""
        group = QGroupBox(tr('group_virustotal'))
        layout = QVBoxLayout()

        # API Key
        api_layout = QHBoxLayout()
        api_layout.addWidget(QLabel(tr('label_api_key')))
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setPlaceholderText(tr('placeholder_api_key'))
        api_layout.addWidget(self.api_key_input)
        layout.addLayout(api_layout)

        # Threshold
        threshold_layout = QHBoxLayout()
        threshold_layout.addWidget(QLabel(tr('label_threshold')))
        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(1, 10)
        self.threshold_spin.setValue(3)
        self.threshold_spin.setSuffix(' detections')
        threshold_layout.addWidget(self.threshold_spin)
        threshold_layout.addStretch()
        layout.addLayout(threshold_layout)

        # Rate limit info
        info = QLabel(tr('label_rate_limit'))
        info.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(info)

        # Scan button
        self.scan_btn = QPushButton(tr('btn_vt_scan'))
        self.scan_btn.setStyleSheet("background-color: #3498db; color: white; padding: 8px;")
        self.scan_btn.clicked.connect(self.start_virustotal_scan)
        layout.addWidget(self.scan_btn)

        # Progress
        self.vt_progress = QProgressBar()
        self.vt_progress.setVisible(False)
        layout.addWidget(self.vt_progress)

        # Log
        self.vt_log = QTextEdit()
        self.vt_log.setMaximumHeight(100)
        self.vt_log.setReadOnly(True)
        layout.addWidget(self.vt_log)

        group.setLayout(layout)
        return group

    def create_manual_group(self) -> QGroupBox:
        """Manual labeling"""
        group = QGroupBox(tr('group_manual_labeling'))
        layout = QVBoxLayout()

        info = QLabel("Label selected APKs manually")
        info.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(info)

        # Buttons
        btn_layout = QHBoxLayout()

        self.malware_btn = QPushButton(tr('btn_label_as_malware'))
        self.malware_btn.setStyleSheet("background-color: #e74c3c; color: white; padding: 8px;")
        self.malware_btn.clicked.connect(lambda: self.manual_label('MALWARE'))
        btn_layout.addWidget(self.malware_btn)

        self.benign_btn = QPushButton(tr('btn_label_as_benign'))
        self.benign_btn.setStyleSheet("background-color: #2ecc71; color: white; padding: 8px;")
        self.benign_btn.clicked.connect(lambda: self.manual_label('BENIGN'))
        btn_layout.addWidget(self.benign_btn)

        layout.addLayout(btn_layout)

        # Family selection (for malware)
        family_layout = QHBoxLayout()
        family_layout.addWidget(QLabel("Malware Family:"))
        self.family_combo = QComboBox()
        self.family_combo.addItems(['trojan', 'adware', 'ransomware',
                                    'spyware', 'backdoor', 'unknown'])
        family_layout.addWidget(self.family_combo)
        family_layout.addStretch()
        layout.addLayout(family_layout)

        group.setLayout(layout)
        return group

    def create_status_group(self) -> QGroupBox:
        """Status display"""
        group = QGroupBox(tr('group_status'))
        layout = QVBoxLayout()

        self.status_label = QLabel()
        self.status_label.setStyleSheet("padding: 10px; background-color: #ecf0f1;")
        self.update_status_label()
        layout.addWidget(self.status_label)

        group.setLayout(layout)
        return group

    def scan_folder_structure(self):
        """Scan folder structure for automatic labeling"""
        if not self.parent_window:
            self.parent_window = self.window()

        apk_tab = self.parent_window.tab_apk
        selected_apks = apk_tab.get_selected_apks()

        if not selected_apks:
            QMessageBox.warning(self, "Warning", tr('msg_select_apks'))
            return

        labeled_count = 0

        for apk_name in selected_apks:
            # Get APK path
            for apk_info in apk_tab.apk_list:
                if apk_info['filename'] == apk_name:
                    apk_path = apk_info['path']
                    folder_path = str(Path(apk_path).parent).lower()

                    # Detect label from folder
                    label = None
                    family = None

                    if any(kw in folder_path for kw in ['malware', 'virus', 'trojan', 'malicious']):
                        label = 'MALWARE'
                        # Try to detect family from folder name
                        for fam in ['trojan', 'adware', 'ransomware', 'spyware', 'backdoor']:
                            if fam in folder_path:
                                family = fam
                                break
                        if not family:
                            family = 'unknown'

                    elif any(kw in folder_path for kw in ['benign', 'goodware', 'clean', 'legitimate']):
                        label = 'BENIGN'

                    if label:
                        try:
                            self.workspace.organize_apk(apk_name, label, family)
                            apk_tab.update_apk_label(apk_name, label, family)
                            labeled_count += 1
                        except Exception as e:
                            print(f"Error organizing {apk_name}: {e}")
                    break

        self.update_status_label()
        QMessageBox.information(self, "Success",
                               f"Folder-based labeling completed\nLabeled {labeled_count} APKs")

    def check_hash_database(self):
        """Check AndroZoo hash database"""
        api_key = self.az_api_key_input.text().strip()

        if not api_key:
            QMessageBox.warning(self, "Warning", "Please enter your AndroZoo API key")
            return

        # Get selected APKs
        if not self.parent_window:
            self.parent_window = self.window()

        apk_tab = self.parent_window.tab_apk
        selected_apks = apk_tab.get_selected_apks()

        if not selected_apks:
            QMessageBox.warning(self, "Warning", tr('msg_select_apks'))
            return

        # Get full paths
        apk_paths = []
        for apk_name in selected_apks:
            for apk_info in apk_tab.apk_list:
                if apk_info['filename'] == apk_name:
                    apk_paths.append(apk_info['path'])
                    break

        # Start thread
        self.hash_btn.setEnabled(False)
        self.az_progress.setVisible(True)
        self.az_progress.setMaximum(len(apk_paths))
        self.az_progress.setValue(0)
        self.az_log.clear()
        self.az_log.append("Starting AndroZoo hash lookup...")

        vt_threshold = self.az_threshold_spin.value()
        self.az_thread = AndroZooThread(
            api_key,
            vt_threshold,
            apk_paths,
            self.az_db_loaded,
            self.androzoo_client
        )
        self.az_thread.progress.connect(self.update_az_progress)
        self.az_thread.result.connect(self.handle_az_result)
        self.az_thread.status.connect(self.update_az_status)
        self.az_thread.finished_scan.connect(self.az_scan_finished)
        self.az_thread.start()

    def update_az_progress(self, current: int, total: int):
        """Update AndroZoo progress bar"""
        self.az_progress.setValue(current)

    def update_az_status(self, message: str):
        """Update AndroZoo status message"""
        self.az_log.append(f"[STATUS] {message}")

    def handle_az_result(self, filename: str, suggested_label: str, confidence: str, vt_detections: int, reasoning: str):
        """Handle AndroZoo lookup result"""
        if suggested_label == 'NOT_FOUND':
            self.az_log.append(f"❌ {filename}: Not found in database")
        elif suggested_label == 'ERROR':
            self.az_log.append(f"⚠️  {filename}: {reasoning}")
        else:
            self.az_log.append(f"✓ {filename}: {suggested_label} (Confidence: {confidence}, VT: {vt_detections}) - {reasoning}")

    def az_scan_finished(self, found: int, total: int):
        """AndroZoo scanning finished"""
        self.hash_btn.setEnabled(True)
        self.az_progress.setVisible(False)

        # Save client and db_loaded status for future lookups
        if self.az_thread and self.az_thread.client:
            self.androzoo_client = self.az_thread.client
            self.az_db_loaded = True

        self.az_log.append("\n" + "="*50)
        self.az_log.append(f"✓ AndroZoo lookup completed!")
        self.az_log.append(f"  Found: {found}/{total} APKs")
        self.az_log.append("  Note: These are SUGGESTIONS only. Review and apply labels manually.")

        QMessageBox.information(
            self,
            "AndroZoo Lookup Complete",
            f"Found {found}/{total} APKs in AndroZoo database.\n\n"
            "Review the suggestions in the log and apply labels manually using the Manual Labeling section."
        )

    def start_virustotal_scan(self):
        """Start VirusTotal scanning"""
        api_key = self.api_key_input.text().strip()

        if not api_key:
            QMessageBox.warning(self, "Warning", tr('msg_no_api_key'))
            return

        # Get selected APKs
        if not self.parent_window:
            self.parent_window = self.window()

        apk_tab = self.parent_window.tab_apk
        selected_apks = apk_tab.get_selected_apks()

        if not selected_apks:
            QMessageBox.warning(self, "Warning", tr('msg_select_apks'))
            return

        # Get full paths
        apk_paths = []
        for apk_name in selected_apks:
            for apk_info in apk_tab.apk_list:
                if apk_info['filename'] == apk_name:
                    apk_paths.append(apk_info['path'])
                    break

        # Start thread
        self.scan_btn.setEnabled(False)
        self.vt_progress.setVisible(True)
        self.vt_progress.setMaximum(len(apk_paths))
        self.vt_progress.setValue(0)
        self.vt_log.clear()
        self.vt_log.append(tr('msg_scanning'))

        threshold = self.threshold_spin.value()
        self.vt_thread = VirusTotalThread(api_key, threshold, apk_paths)
        self.vt_thread.progress.connect(self.update_vt_progress)
        self.vt_thread.result.connect(self.handle_vt_result)
        self.vt_thread.finished_scan.connect(self.scan_finished)
        self.vt_thread.start()

    def update_vt_progress(self, current: int, total: int):
        """Update progress bar"""
        self.vt_progress.setValue(current)
        self.vt_log.append(tr('progress_analyzing', current=current, total=total))

    def handle_vt_result(self, filename: str, label: str, family: str):
        """Handle VirusTotal result"""
        self.vt_log.append(f"{filename}: {label} ({family})")

        # Update APK table
        if self.parent_window:
            apk_tab = self.parent_window.tab_apk
            apk_tab.update_apk_label(filename, label, family)

        # Update status
        self.update_status_label()

    def scan_finished(self):
        """Scanning finished"""
        self.scan_btn.setEnabled(True)
        self.vt_progress.setVisible(False)
        self.vt_log.append("\n" + "="*50)
        self.vt_log.append("VirusTotal scanning completed!")
        QMessageBox.information(self, "Success", "VirusTotal scanning completed!")

    def manual_label(self, label: str):
        """Manual labeling"""
        if not self.parent_window:
            self.parent_window = self.window()

        apk_tab = self.parent_window.tab_apk
        selected_apks = apk_tab.get_selected_apks()

        if not selected_apks:
            QMessageBox.warning(self, "Warning", tr('msg_select_apks'))
            return

        family = None
        if label == 'MALWARE':
            family = self.family_combo.currentText()

        # Organize APKs
        labeled_count = 0
        for apk_name in selected_apks:
            try:
                self.workspace.organize_apk(apk_name, label, family)
                apk_tab.update_apk_label(apk_name, label, family)
                labeled_count += 1
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

        self.update_status_label()
        QMessageBox.information(self, "Success",
                               f"Labeled {labeled_count} APKs as {label}")

    def update_status_label(self):
        """Update status label"""
        stats = self.workspace.get_organized_stats()

        text = f"{tr('status_imported', count=stats['imported'])}\n"
        text += f"{tr('status_malware', count=stats['malware'])}\n"
        text += f"{tr('status_benign', count=stats['benign'])}\n"
        text += f"{tr('status_unlabeled', count=stats['unlabeled'])}\n"

        if stats['families']:
            text += f"\nMalware Families: {', '.join(stats['families'].keys())}"

        self.status_label.setText(text)

    def refresh_translations(self):
        """Refresh UI text after language change"""
        # Update button texts
        self.folder_btn.setText(tr('btn_scan_folders'))
        self.hash_btn.setText(tr('btn_hash_lookup'))
        self.scan_btn.setText(tr('btn_vt_scan'))
        self.malware_btn.setText(tr('btn_label_as_malware'))
        self.benign_btn.setText(tr('btn_label_as_benign'))

        # Update status
        self.update_status_label()
