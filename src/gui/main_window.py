"""
Main Window for APKDatasetLab
"""
from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QAction, QMessageBox,
                             QStatusBar, QWidget)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from gui.tab_apk_manager import APKManagerTab
from gui.tab_labeling import LabelingTab
from gui.tab_features import FeaturesTab
from gui.tab_analysis import AnalysisTab
from gui.tab_export import ExportTab


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        # Window settings
        self.setWindowTitle("APKDatasetLab - Android Malware Dataset Builder v0.1")
        self.setGeometry(100, 100, 1200, 800)
        self.center_window()

        # Create menu bar
        self.create_menu_bar()

        # Create tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Create tabs
        self.create_tabs()

        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def center_window(self):
        """Center window on screen"""
        from PyQt5.QtWidgets import QDesktopWidget
        qt_rectangle = self.frameGeometry()
        center_point = QDesktopWidget().availableGeometry().center()
        qt_rectangle.moveCenter(center_point)
        self.move(qt_rectangle.topLeft())

    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()

        # File Menu
        file_menu = menubar.addMenu("File")

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setStatusTip("Exit application")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Help Menu
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.setStatusTip("About APKDatasetLab")
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_tabs(self):
        """Create all tabs"""
        # Tab 1: APK Management
        self.apk_manager_tab = APKManagerTab()
        self.apk_manager_tab.apk_list_changed.connect(self.on_apk_list_changed)
        self.tabs.addTab(self.apk_manager_tab, "1. APK Management")

        # Tab 2: Labeling
        self.labeling_tab = LabelingTab()
        self.tabs.addTab(self.labeling_tab, "2. Labeling")

        # Tab 3: Feature Selection
        self.features_tab = FeaturesTab()
        self.tabs.addTab(self.features_tab, "3. Feature Selection")

        # Tab 4: Analysis & Processing
        self.analysis_tab = AnalysisTab()
        self.tabs.addTab(self.analysis_tab, "4. Analysis & Processing")

        # Tab 5: Export Dataset
        self.export_tab = ExportTab()
        self.tabs.addTab(self.export_tab, "5. Export Dataset")

    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>APKDatasetLab</h2>
        <p>Version: 0.1.0</p>
        <p>Professional Android Malware Dataset Builder</p>
        <p>Built with PyQt5 and Androguard</p>
        <hr>
        <p><b>Author:</b> Muhammed Eminolu</p>
        <p><b>GitHub:</b> <a href="https://github.com/muhammedeminoglu1/APKDatasetLab">
        https://github.com/muhammedeminoglu1/APKDatasetLab</a></p>
        """
        QMessageBox.about(self, "About APKDatasetLab", about_text)

    def on_apk_list_changed(self, count: int):
        """Handle APK list changes"""
        self.status_bar.showMessage(f"Total APKs loaded: {count}")

    def closeEvent(self, event):
        """Handle window close event"""
        reply = QMessageBox.question(
            self,
            'Exit Confirmation',
            'Are you sure you want to exit?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()
