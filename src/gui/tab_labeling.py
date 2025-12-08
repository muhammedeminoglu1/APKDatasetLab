"""
Labeling Tab - Label APKs as Malware or Benign
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QGroupBox, QRadioButton, QLineEdit,
                             QMessageBox, QComboBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from pathlib import Path


class LabelingTab(QWidget):
    """Labeling tab for APK classification"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.apk_table = None
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Title
        title = QLabel("Label APK Files")
        title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(title)

        # Labeling methods group
        methods_group = self.create_labeling_methods_group()
        layout.addWidget(methods_group)

        # Manual labeling group
        manual_group = self.create_manual_labeling_group()
        layout.addWidget(manual_group)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Ready to label APKs")
        self.status_label.setStyleSheet("padding: 10px; background-color: #f0f0f0;")
        layout.addWidget(self.status_label)

        layout.addStretch()
        self.setLayout(layout)

    def create_labeling_methods_group(self) -> QGroupBox:
        """Create automatic labeling methods group"""
        group = QGroupBox("Automatic Labeling Methods")
        layout = QVBoxLayout()

        # Folder-based labeling
        folder_layout = QHBoxLayout()
        folder_label = QLabel("Folder-based: Automatically label based on parent folder name")
        folder_btn = QPushButton("Apply Folder-based Labeling")
        folder_btn.clicked.connect(self.apply_folder_labeling)
        folder_layout.addWidget(folder_label)
        folder_layout.addWidget(folder_btn)
        layout.addLayout(folder_layout)

        # Pattern-based labeling
        pattern_layout = QHBoxLayout()
        pattern_label = QLabel("Pattern-based: Label by filename pattern")
        self.pattern_input = QLineEdit()
        self.pattern_input.setPlaceholderText("e.g., malware, virus, trojan")
        self.pattern_label_combo = QComboBox()
        self.pattern_label_combo.addItems(["MALWARE", "BENIGN"])
        pattern_btn = QPushButton("Apply Pattern")
        pattern_btn.clicked.connect(self.apply_pattern_labeling)
        pattern_layout.addWidget(pattern_label)
        pattern_layout.addWidget(self.pattern_input)
        pattern_layout.addWidget(self.pattern_label_combo)
        pattern_layout.addWidget(pattern_btn)
        layout.addLayout(pattern_layout)

        # Info text
        info = QLabel("Note: Folder-based labeling looks for 'malware', 'virus', 'benign', 'goodware' in folder names")
        info.setStyleSheet("color: gray; font-size: 11px; padding: 5px;")
        layout.addWidget(info)

        group.setLayout(layout)
        return group

    def create_manual_labeling_group(self) -> QGroupBox:
        """Create manual labeling group"""
        group = QGroupBox("Manual Labeling")
        layout = QVBoxLayout()

        label = QLabel("Label selected APKs manually:")
        layout.addWidget(label)

        button_layout = QHBoxLayout()

        malware_btn = QPushButton("Mark as MALWARE")
        malware_btn.setStyleSheet("background-color: #ff6b6b; color: white; padding: 10px;")
        malware_btn.clicked.connect(lambda: self.apply_manual_label("MALWARE"))
        button_layout.addWidget(malware_btn)

        benign_btn = QPushButton("Mark as BENIGN")
        benign_btn.setStyleSheet("background-color: #51cf66; color: white; padding: 10px;")
        benign_btn.clicked.connect(lambda: self.apply_manual_label("BENIGN"))
        button_layout.addWidget(benign_btn)

        unknown_btn = QPushButton("Mark as UNKNOWN")
        unknown_btn.setStyleSheet("background-color: #868e96; color: white; padding: 10px;")
        unknown_btn.clicked.connect(lambda: self.apply_manual_label("UNKNOWN"))
        button_layout.addWidget(unknown_btn)

        layout.addLayout(button_layout)

        group.setLayout(layout)
        return group

    def set_apk_table(self, apk_table):
        """Set reference to APK table"""
        self.apk_table = apk_table

    def apply_folder_labeling(self):
        """Apply folder-based automatic labeling"""
        if not self.apk_table:
            QMessageBox.warning(self, "Error", "No APK table reference found")
            return

        if self.apk_table.rowCount() == 0:
            QMessageBox.information(self, "No APKs", "No APKs loaded to label")
            return

        labeled_count = 0

        for row in range(self.apk_table.rowCount()):
            path_item = self.apk_table.item(row, 4)
            if path_item:
                apk_path = path_item.text()
                folder_path = str(Path(apk_path).parent).lower()

                label = "UNKNOWN"
                if any(kw in folder_path for kw in ['malware', 'virus', 'trojan', 'malicious']):
                    label = "MALWARE"
                elif any(kw in folder_path for kw in ['benign', 'goodware', 'clean', 'legitimate']):
                    label = "BENIGN"

                if label != "UNKNOWN":
                    label_item = self.apk_table.item(row, 2)
                    if label_item:
                        label_item.setText(label)
                        if label == "MALWARE":
                            label_item.setBackground(Qt.red)
                        elif label == "BENIGN":
                            label_item.setBackground(Qt.green)
                        labeled_count += 1

        self.status_label.setText(f"Folder-based labeling completed: {labeled_count} APKs labeled")
        QMessageBox.information(self, "Labeling Complete",
                               f"Successfully labeled {labeled_count} APKs based on folder names")

    def apply_pattern_labeling(self):
        """Apply pattern-based labeling"""
        if not self.apk_table:
            QMessageBox.warning(self, "Error", "No APK table reference found")
            return

        pattern = self.pattern_input.text().strip().lower()
        if not pattern:
            QMessageBox.warning(self, "No Pattern", "Please enter a pattern to search for")
            return

        label = self.pattern_label_combo.currentText()
        labeled_count = 0

        for row in range(self.apk_table.rowCount()):
            filename_item = self.apk_table.item(row, 1)
            if filename_item:
                filename = filename_item.text().lower()
                if pattern in filename:
                    label_item = self.apk_table.item(row, 2)
                    if label_item:
                        label_item.setText(label)
                        if label == "MALWARE":
                            label_item.setBackground(Qt.red)
                        elif label == "BENIGN":
                            label_item.setBackground(Qt.green)
                        labeled_count += 1

        self.status_label.setText(f"Pattern-based labeling completed: {labeled_count} APKs labeled")
        QMessageBox.information(self, "Labeling Complete",
                               f"Successfully labeled {labeled_count} APKs matching pattern '{pattern}'")

    def apply_manual_label(self, label: str):
        """Apply manual label to selected APKs"""
        if not self.apk_table:
            QMessageBox.warning(self, "Error", "No APK table reference found")
            return

        labeled_count = 0

        for row in range(self.apk_table.rowCount()):
            checkbox_widget = self.apk_table.cellWidget(row, 0)
            if checkbox_widget:
                from PyQt5.QtWidgets import QCheckBox
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox and checkbox.isChecked():
                    label_item = self.apk_table.item(row, 2)
                    if label_item:
                        label_item.setText(label)
                        if label == "MALWARE":
                            label_item.setBackground(Qt.red)
                        elif label == "BENIGN":
                            label_item.setBackground(Qt.green)
                        else:
                            label_item.setBackground(Qt.white)
                        labeled_count += 1

        self.status_label.setText(f"Manual labeling completed: {labeled_count} APKs labeled as {label}")

        if labeled_count == 0:
            QMessageBox.information(self, "No Selection", "No APKs selected. Please select APKs from the table first.")
        else:
            QMessageBox.information(self, "Labeling Complete",
                                   f"Successfully labeled {labeled_count} selected APKs as {label}")
