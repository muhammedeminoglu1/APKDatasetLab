"""
Translation system for multi-language support
"""
import json
from pathlib import Path
from PyQt5.QtCore import QObject, pyqtSignal


class Translator(QObject):
    """Singleton translator class"""
    language_changed = pyqtSignal(str)

    def __init__(self, language='en'):
        super().__init__()
        self.language = language
        self.translations = {}
        self.load_translations()

    def load_translations(self):
        """Load translation file for current language"""
        trans_file = Path(__file__).parent.parent.parent / 'config' / 'translations' / f'{self.language}.json'
        try:
            with open(trans_file, 'r', encoding='utf-8') as f:
                self.translations = json.load(f)
        except FileNotFoundError:
            print(f"Translation file not found: {trans_file}")
            self.translations = {}

    def tr(self, key: str, **kwargs) -> str:
        """
        Translate key with optional formatting

        Args:
            key: Translation key
            **kwargs: Format parameters

        Returns:
            Translated text
        """
        text = self.translations.get(key, key)
        return text.format(**kwargs) if kwargs else text

    def change_language(self, language: str):
        """Change language and reload translations"""
        self.language = language
        self.load_translations()
        self.language_changed.emit(language)

    def get_available_languages(self) -> list:
        """Get list of available languages"""
        trans_dir = Path(__file__).parent.parent.parent / 'config' / 'translations'
        return [f.stem for f in trans_dir.glob('*.json')]


# Global translator instance
_translator = Translator()


def tr(key: str, **kwargs) -> str:
    """Global translation function"""
    return _translator.tr(key, **kwargs)


def change_language(language: str):
    """Change global language"""
    _translator.change_language(language)


def get_translator() -> Translator:
    """Get global translator instance"""
    return _translator
