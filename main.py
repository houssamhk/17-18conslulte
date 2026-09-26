import sys
import logging
from PyQt6.QtWidgets import QApplication, QSplashScreen
from PyQt6.QtGui import QIcon, QPixmap, QFont, QColor
from PyQt6.QtCore import Qt

from gui.main_window import AlgPIIMainWindow
from gui.theme import apply_theme
from storage.secure_db import SecureDatabase
from storage.key_manager import KeyManager

def main():
    # Setup logging
    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.info("Starting Alg-PII Engine...")
    
    # Initialize QApplication
    app = QApplication(sys.argv)
    
    # Try setting an icon
    try:
        app.setWindowIcon(QIcon("assets/icon.png"))
    except Exception:
        pass
    
    # --- Splash Screen ---
    splash_pix = QPixmap(500, 300)
    splash_pix.fill(QColor("#1a1a2e"))
    
    # Try loading custom splash image
    custom_splash = QPixmap("assets/splash.png")
    if not custom_splash.isNull():
        splash_pix = custom_splash.scaled(500, 300, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
    
    splash = QSplashScreen(splash_pix)
    splash.setStyleSheet("""
        QSplashScreen {
            background-color: #1a1a2e;
            color: #e0e0e0;
            font-size: 14px;
        }
    """)
    splash.show()
    app.processEvents()
    
    # Status helper
    def splash_msg(msg: str):
        splash.showMessage(
            msg,
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignHCenter,
            QColor("#e94560")
        )
        app.processEvents()
    
    # --- Phase 1: Theme ---
    splash_msg("جاري تحميل الواجهة... (Loading UI Theme...)")
    apply_theme(app)
    
    # --- Phase 2: Database ---
    splash_msg("جاري تحميل قاعدة البيانات المشفرة... (Initializing Secure Database...)")
    KeyManager.ensure_key()
    db = SecureDatabase()
    
    # --- Phase 3: Main Window ---
    splash_msg("جاري تحميل النظام... (Loading System Components...)")
    window = AlgPIIMainWindow(db)
    
    # --- Done ---
    splash_msg("جاهز! (Ready!)")
    window.show()
    splash.finish(window)
    
    # Execute application loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
