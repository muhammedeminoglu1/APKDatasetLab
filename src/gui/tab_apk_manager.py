"""
APK Management Tab
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QFileDialog, QMessageBox, QToolBar)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon
from pathlib import Path
from gui.widgets import APKTableWidget
from core.apk_analyzer import APKAnalyzer


class APKManagerTab(QWidget):
    """APK Management Tab - Load and manage APK files"""

    # Signal emitted when APK list changes
    apk_list_changed = pyqtSignal(int)  # Emit total count

    def __init__(self, parent=None):
        super().__init__(parent)
        self.apk_paths = []  # Store APK file paths
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Top Toolbar
        toolbar = self.create_toolbar()
        layout.addWidget(toolbar)

        # APK Table
        self.apk_table = APKTableWidget()
        self.apk_table.doubleClicked.connect(self.on_row_double_clicked)
        layout.addWidget(self.apk_table)

        # Bottom Info Label
        self.info_label = QLabel("Total APKs: 0 | Selected: 0")
        self.info_label.setStyleSheet("padding: 5px; background-color: #f0f0f0;")
        layout.addWidget(self.info_label)

        self.setLayout(layout)

    def create_toolbar(self) -> QToolBar:
        """Create top toolbar with buttons"""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setStyleSheet("QToolBar { spacing: 5px; padding: 5px; }")

        # Folder Select Button
        folder_btn = QPushButton("=Á Select Folder")
        folder_btn.setToolTip("Select folder containing APK files")
        folder_btn.clicked.connect(self.on_select_folder)
        toolbar.addWidget(folder_btn)

        toolbar.addSeparator()

        # Add APK Button
        apk_btn = QPushButton("=Ä Add APK")
        apk_btn.setToolTip("Select individual APK file")
        apk_btn.clicked.connect(self.on_add_apk)
        toolbar.addWidget(apk_btn)

        toolbar.addSeparator()

        # Clear Button
        clear_btn = QPushButton("=Ñ Clear")
        clear_btn.setToolTip("Clear all APKs from list")
        clear_btn.clicked.connect(self.on_clear)
        toolbar.addWidget(clear_btn)

        return toolbar

    def on_select_folder(self):
        """Handle folder selection - recursively find APK files"""
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Folder Containing APK Files",
            "",
            QFileDialog.ShowDirsOnly
        )

        if folder:
            self.load_apks_from_folder(folder)

    def load_apks_from_folder(self, folder_path: str):
        """Recursively load all APK files from folder"""
        try:
            folder = Path(folder_path)
            apk_files = list(folder.rglob("*.apk"))

            if not apk_files:
                QMessageBox.information(
                    self,
                    "No APKs Found",
                    f"No APK files found in:\n{folder_path}"
                )
                return

            # Add APKs to table
            for apk_path in apk_files:
                self.add_apk_to_table(str(apk_path))

            self.update_info_label()

            QMessageBox.information(
                self,
                "APKs Loaded",
                f"Successfully loaded {len(apk_files)} APK files"
            )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Error loading APKs from folder:\n{str(e)}"
            )

    def on_add_apk(self):
        """Handle individual APK file selection"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select APK File",
            "",
            "APK Files (*.apk);;All Files (*)"
        )

        if file_path:
            self.add_apk_to_table(file_path)
            self.update_info_label()

    def add_apk_to_table(self, apk_path: str):
        """Add APK to table with basic info"""
        try:
            # Avoid duplicates
            if apk_path in self.apk_paths:
                return

            self.apk_paths.append(apk_path)

            # Get APK info
            analyzer = APKAnalyzer(apk_path)
            filename = Path(apk_path).name
            size_mb = analyzer.get_file_size_mb()

            # Add to table
            self.apk_table.add_apk_row(
                filename=filename,
                label="UNKNOWN",
                size_mb=size_mb,
                path=apk_path
            )

        except Exception as e:
            print(f"Error adding APK to table: {e}")
            QMessageBox.warning(
                self,
                "Warning",
                f"Could not add APK:\n{apk_path}\n\nError: {str(e)}"
            )

    def on_clear(self):
        """Clear all APKs from table"""
        reply = QMessageBox.question(
            self,
            "Clear APK List",
            "Are you sure you want to clear all APKs from the list?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.apk_table.clear_all()
            self.apk_paths.clear()
            self.update_info_label()

    def update_info_label(self):
        """Update bottom info label with counts"""
        total = self.apk_table.rowCount()
        selected = self.apk_table.get_selected_count()
        self.info_label.setText(f"Total APKs: {total} | Selected: {selected}")
        self.apk_list_changed.emit(total)

    def on_row_double_clicked(self, index):
        """Handle double-click on table row - show APK info dialog"""
        row = index.row()
        filename = self.apk_table.item(row, 1).text()
        size = self.apk_table.item(row, 3).text()
        path = self.apk_table.item(row, 4).text()

        info_text = f"Filename: {filename}\n"
        info_text += f"Size: {size} MB\n"
        info_text += f"Path: {path}"

        QMessageBox.information(
            self,
            "APK Information",
            info_text
        )

    def get_selected_apk_paths(self) -> list:
        """Get list of selected APK paths"""
        selected_paths = []
        for row in range(self.apk_table.rowCount()):
            checkbox_widget = self.apk_table.cellWidget(row, 0)
            if checkbox_widget:
                from PyQt5.QtWidgets import QCheckBox
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox and checkbox.isChecked():
                    path = self.apk_table.item(row, 4).text()
                    selected_paths.append(path)
        return selected_paths
