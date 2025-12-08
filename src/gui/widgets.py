"""
Custom PyQt5 widgets for APKDatasetLab
"""
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QWidget, QHBoxLayout
from PyQt5.QtCore import Qt


class APKTableWidget(QTableWidget):
    """Custom table widget for APK list"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_table()

    def setup_table(self):
        """Setup table columns and appearance"""
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels([
            '', 'Filename', 'Label', 'Size (MB)', 'Path'
        ])

        # Column widths
        self.setColumnWidth(0, 30)   # Checkbox
        self.setColumnWidth(1, 200)  # Filename
        self.setColumnWidth(2, 100)  # Label
        self.setColumnWidth(3, 100)  # Size
        self.horizontalHeader().setStretchLastSection(True)  # Path stretches

        # Appearance
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)

    def add_apk_row(self, filename: str, label: str, size_mb: float, path: str):
        """Add a new APK row to the table"""
        row = self.rowCount()
        self.insertRow(row)

        # Checkbox
        checkbox_widget = QWidget()
        checkbox = QCheckBox()
        checkbox.setChecked(True)
        layout = QHBoxLayout(checkbox_widget)
        layout.addWidget(checkbox)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setCellWidget(row, 0, checkbox_widget)

        # Filename
        self.setItem(row, 1, QTableWidgetItem(filename))

        # Label
        self.setItem(row, 2, QTableWidgetItem(label))

        # Size (MB)
        self.setItem(row, 3, QTableWidgetItem(f"{size_mb:.2f}"))

        # Path
        self.setItem(row, 4, QTableWidgetItem(path))

    def get_selected_count(self) -> int:
        """Get count of selected (checked) APKs"""
        count = 0
        for row in range(self.rowCount()):
            checkbox_widget = self.cellWidget(row, 0)
            if checkbox_widget:
                checkbox = checkbox_widget.findChild(QCheckBox)
                if checkbox and checkbox.isChecked():
                    count += 1
        return count

    def clear_all(self):
        """Clear all rows from the table"""
        self.setRowCount(0)
