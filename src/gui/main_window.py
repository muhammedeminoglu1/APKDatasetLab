"""
Main application window with multi-language support
"""
from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QAction, QMessageBox,
                             QWidget, QVBoxLayout)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

from gui.tab_apk_manager import APKManagerTab
from gui.tab_labeling import LabelingTab
from gui.tab_inspector import InspectorTab
from gui.tab_features import FeaturesTab
from gui.tab_analysis import AnalysisTab
from gui.tab_export import ExportTab
from utils.translator import tr, change_language, get_translator


class MainWindow(QMainWindow):
    """Main application window with 6 tabs"""

    def __init__(self):
        super().__init__()
        self.init_ui()

        # Connect to language changes
        translator = get_translator()
        translator.language_changed.connect(self.refresh_ui)

    def init_ui(self):
        """Initialize user interface"""
        self.setWindowTitle(tr('app_title'))
        self.setGeometry(100, 100, 1200, 800)
        self.center_on_screen()

        # Create tabs
        self.tabs = QTabWidget()
        self.create_tabs()
        self.setCentralWidget(self.tabs)

        # Create menu bar
        self.create_menu_bar()

        # Status bar
        self.statusBar().showMessage(tr('msg_success'))

    def create_tabs(self):
        """Create all tabs (6 tabs)"""
        # Tab 1: APK Management
        self.tab_apk = APKManagerTab()
        self.tabs.addTab(self.tab_apk, tr('tab_apk_management'))

        # Tab 2: Labeling (includes VirusTotal)
        self.tab_label = LabelingTab()
        self.tab_label.parent_window = self
        self.tabs.addTab(self.tab_label, tr('tab_labeling'))

        # Tab 3: APK Inspector (NEW!)
        self.tab_inspector = InspectorTab()
        self.tab_inspector.set_apk_list(self.tab_apk.table)
        self.tabs.addTab(self.tab_inspector, tr('tab_inspector'))

        # Tab 4: Feature Selection
        self.tab_features = FeaturesTab()
        self.tabs.addTab(self.tab_features, tr('tab_features'))

        # Tab 5: Analysis & Processing
        self.tab_analysis = AnalysisTab()
        self.tab_analysis.set_apk_table(self.tab_apk.table)
        self.tab_analysis.set_features_tab(self.tab_features)
        self.tabs.addTab(self.tab_analysis, tr('tab_analysis'))

        # Tab 6: Export Dataset
        self.tab_export = ExportTab()
        self.tab_export.set_analysis_tab(self.tab_analysis)
        self.tab_export.set_features_tab(self.tab_features)  # FIX: Add features_tab reference
        self.tabs.addTab(self.tab_export, tr('tab_export'))

        # Connect APK table changes to inspector
        self.tab_apk.table.itemSelectionChanged.connect(
            lambda: self.tab_inspector.set_apk_list(self.tab_apk.table)
        )

    def create_menu_bar(self):
        """Initialize menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu(tr('menu_file'))

        exit_action = QAction(tr('menu_exit'), self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Language menu
        language_menu = menubar.addMenu(tr('menu_language'))

        en_action = QAction('English 🇬🇧', self)
        en_action.triggered.connect(lambda: self.change_language('en'))
        language_menu.addAction(en_action)

        tr_action = QAction('Türkçe 🇹🇷', self)
        tr_action.triggered.connect(lambda: self.change_language('tr'))
        language_menu.addAction(tr_action)

        # Help menu
        help_menu = menubar.addMenu(tr('menu_help'))

        about_action = QAction(tr('menu_about'), self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def change_language(self, lang: str):
        """Change application language"""
        change_language(lang)
        # UI will be updated via language_changed signal

    def refresh_ui(self):
        """Refresh all UI text after language change"""
        # Window title
        self.setWindowTitle(tr('app_title'))

        # Menu bar
        self.menuBar().clear()
        self.create_menu_bar()

        # Tab titles
        self.tabs.setTabText(0, tr('tab_apk_management'))
        self.tabs.setTabText(1, tr('tab_labeling'))
        self.tabs.setTabText(2, tr('tab_inspector'))
        self.tabs.setTabText(3, tr('tab_features'))
        self.tabs.setTabText(4, tr('tab_analysis'))
        self.tabs.setTabText(5, tr('tab_export'))

        # Refresh each tab
        for i in range(self.tabs.count()):
            widget = self.tabs.widget(i)
            if hasattr(widget, 'refresh_translations'):
                widget.refresh_translations()

        # Status bar
        self.statusBar().showMessage(tr('msg_success'))

    def center_on_screen(self):
        """Center window on screen"""
        frame_geometry = self.frameGeometry()
        screen_center = self.screen().availableGeometry().center()
        frame_geometry.moveCenter(screen_center)
        self.move(frame_geometry.topLeft())

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, tr('about_title'), tr('about_text'))

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
