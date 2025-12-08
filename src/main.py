"""
APKDatasetLab - Main Entry Point
Professional Android Malware Dataset Builder
"""
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from gui.main_window import MainWindow


def main():
    """Main entry point for the application"""
    # Enable High DPI scaling
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("APKDatasetLab")
    app.setApplicationVersion("0.1.0")
    app.setOrganizationName("APKDatasetLab")

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
