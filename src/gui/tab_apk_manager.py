"""
APK Management Tab with workspace integration
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QTableWidget, QTableWidgetItem, QFileDialog,
                             QLabel, QHeaderView, QMessageBox, QCheckBox)
from PyQt5.QtCore import Qt, pyqtSignal
from pathlib import Path

from core.workspace_manager import WorkspaceManager
from core.apk_analyzer import APKAnalyzer
from utils.translator import tr


class APKManagerTab(QWidget):
    """APK loading and management with workspace"""

    # Signal emitted when APK list changes
    apk_list_changed = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.workspace = WorkspaceManager()
        self.apk_list = []
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Top toolbar
        toolbar = self.create_toolbar()
        layout.addLayout(toolbar)

        # APK table
        self.table = self.create_table()
        layout.addWidget(self.table)

        # Bottom info
        self.info_label = QLabel(tr('label_total_apks', count=0))
        layout.addWidget(self.info_label)

        self.setLayout(layout)

    def create_toolbar(self) -> QHBoxLayout:
        """Create toolbar with buttons"""
        toolbar = QHBoxLayout()

        self.btn_folder = QPushButton(tr('btn_select_folder'))
        self.btn_folder.clicked.connect(self.load_folder)
        toolbar.addWidget(self.btn_folder)

        self.btn_add = QPushButton(tr('btn_add_apk'))
        self.btn_add.clicked.connect(self.add_apk)
        toolbar.addWidget(self.btn_add)

        self.btn_clear = QPushButton(tr('btn_clear_list'))
        self.btn_clear.clicked.connect(self.clear_list)
        toolbar.addWidget(self.btn_clear)

        toolbar.addStretch()
        return toolbar

    def create_table(self) -> QTableWidget:
        """Create APK table"""
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([
            tr('col_checkbox'),
            tr('col_filename'),
            tr('col_label'),
            tr('col_family'),
            tr('col_size'),
            tr('col_path')
        ])

        # Column widths
        table.setColumnWidth(0, 40)
        table.setColumnWidth(1, 200)
        table.setColumnWidth(2, 100)
        table.setColumnWidth(3, 100)
        table.setColumnWidth(4, 100)
        table.horizontalHeader().setStretchLastSection(True)

        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)

        return table

    def load_folder(self):
        """Load APKs from folder"""
        folder_path = QFileDialog.getExistingDirectory(self, tr('btn_select_folder'))

        if folder_path:
            apk_files = list(Path(folder_path).rglob('*.apk'))

            if not apk_files:
                QMessageBox.warning(self, "Warning", "No APK files found in selected folder")
                return

            # Import to workspace
            for apk_file in apk_files:
                try:
                    imported_path = self.workspace.import_apk(apk_file)
                    self.add_apk_to_table(imported_path)
                except Exception as e:
                    print(f"Error importing {apk_file.name}: {e}")

            self.update_info_label()
            self.apk_list_changed.emit(len(self.apk_list))
            QMessageBox.information(self, "Success",
                                   f"Imported {len(apk_files)} APK files")

    def add_apk(self):
        """Add single APK"""
        file_path, _ = QFileDialog.getOpenFileName(self, tr('btn_add_apk'),
                                                     "", "APK Files (*.apk)")

        if file_path:
            try:
                imported_path = self.workspace.import_apk(file_path)
                self.add_apk_to_table(imported_path)
                self.update_info_label()
                self.apk_list_changed.emit(len(self.apk_list))
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def add_apk_to_table(self, apk_path: Path):
        """Add APK to table"""
        # Get label from workspace
        label, family = self.workspace.get_apk_label(apk_path.name)

        # Calculate size
        size_mb = apk_path.stat().st_size / (1024 * 1024)

        # Add row
        row = self.table.rowCount()
        self.table.insertRow(row)

        # Checkbox
        checkbox = QCheckBox()
        checkbox.setChecked(True)
        checkbox_widget = QWidget()
        checkbox_layout = QHBoxLayout(checkbox_widget)
        checkbox_layout.addWidget(checkbox)
        checkbox_layout.setAlignment(Qt.AlignCenter)
        checkbox_layout.setContentsMargins(0, 0, 0, 0)
        self.table.setCellWidget(row, 0, checkbox_widget)

        # Data
        self.table.setItem(row, 1, QTableWidgetItem(apk_path.name))
        self.table.setItem(row, 2, QTableWidgetItem(label))
        self.table.setItem(row, 3, QTableWidgetItem(family or '-'))
        self.table.setItem(row, 4, QTableWidgetItem(f"{size_mb:.2f}"))
        self.table.setItem(row, 5, QTableWidgetItem(str(apk_path)))

        # Store in list
        self.apk_list.append({
            'filename': apk_path.name,
            'path': str(apk_path),
            'label': label,
            'family': family,
            'size_mb': size_mb
        })

    def clear_list(self):
        """Clear APK list"""
        reply = QMessageBox.question(self, 'Confirm',
                                     'Clear all APKs from list?',
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.table.setRowCount(0)
            self.apk_list.clear()
            self.update_info_label()
            self.apk_list_changed.emit(0)

    def update_info_label(self):
        """Update info label"""
        count = len(self.apk_list)
        selected = self.get_selected_count()
        self.info_label.setText(
            f"{tr('label_total_apks', count=count)} | {tr('label_selected', count=selected)}"
        )

    def get_selected_count(self) -> int:
        """Get count of selected APKs"""
        count = 0
        for row in range(self.table.rowCount()):
            checkbox_widget = self.table.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox and checkbox.isChecked():
                    count += 1
        return count

    def get_selected_apks(self) -> list:
        """Get list of selected APK filenames"""
        selected = []
        for row in range(self.table.rowCount()):
            checkbox_widget = self.table.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox and checkbox.isChecked():
                    filename = self.table.item(row, 1).text()
                    selected.append(filename)
        return selected

    def update_apk_label(self, filename: str, label: str, family: str = None):
        """Update APK label in table"""
        for row in range(self.table.rowCount()):
            if self.table.item(row, 1).text() == filename:
                self.table.setItem(row, 2, QTableWidgetItem(label))
                self.table.setItem(row, 3, QTableWidgetItem(family or '-'))

                # Color code
                label_item = self.table.item(row, 2)
                if label == 'MALWARE':
                    label_item.setBackground(Qt.red)
                    label_item.setForeground(Qt.white)
                elif label == 'BENIGN':
                    label_item.setBackground(Qt.green)
                    label_item.setForeground(Qt.white)
                break

        # Update in list
        for apk in self.apk_list:
            if apk['filename'] == filename:
                apk['label'] = label
                apk['family'] = family
                break

    def refresh_translations(self):
        """Refresh UI text after language change"""
        # Toolbar buttons
        self.btn_folder.setText(tr('btn_select_folder'))
        self.btn_add.setText(tr('btn_add_apk'))
        self.btn_clear.setText(tr('btn_clear_list'))

        # Table headers
        self.table.setHorizontalHeaderLabels([
            tr('col_checkbox'),
            tr('col_filename'),
            tr('col_label'),
            tr('col_family'),
            tr('col_size'),
            tr('col_path')
        ])

        # Info label
        self.update_info_label()
