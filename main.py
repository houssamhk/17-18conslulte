import sys
import os
import logging
import ctypes

# PyQt bundles older MSVC runtime DLLs. Preload the installed Windows runtime
# before Qt so optional PyTorch native libraries can initialize reliably.
_runtime_preload_errors = []
if os.name == "nt":
    _system_dir = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32")
    for _dll_name in ("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll"):
        _dll_path = os.path.join(_system_dir, _dll_name)
        if os.path.isfile(_dll_path):
            try:
                ctypes.WinDLL(_dll_path)
            except OSError as _dll_error:
                _runtime_preload_errors.append(f"{_dll_name}: {_dll_error}")

from PyQt6.QtWidgets import QApplication, QSplashScreen
from PyQt6.QtGui import QIcon, QPixmap, QFont, QColor
from PyQt6.QtCore import Qt

from gui.main_window import AlgPIIMainWindow
from gui.theme import apply_theme
from storage.secure_db import SecureDatabase
from storage.backup_manager import SecureBackupManager

def _asset_path(name: str) -> str:
    bundle_root = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(bundle_root, "assets", name)

def main():
    # Setup logging
    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    for runtime_error in _runtime_preload_errors:
        logging.warning("Could not preload a Windows runtime DLL: %s", runtime_error)
    logging.info("Starting Alg-PII Engine...")
    
    # Initialize QApplication
    app = QApplication(sys.argv)
    
    # Try setting an icon
    try:
        app.setWindowIcon(QIcon(_asset_path("icon.png")))
    except Exception:
        pass
    
    # --- Splash Screen ---
    splash_pix = QPixmap(500, 300)
    splash_pix.fill(QColor("#1a1a2e"))
    
    # Try loading custom splash image
    custom_splash = QPixmap(_asset_path("splash.png"))
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
    db_path = SecureDatabase._default_database_path()
    restored_backup = SecureBackupManager.apply_pending_restore(db_path)
    db = SecureDatabase()
    if restored_backup:
        if not db.refresh_audit_head_anchor_after_restore():
            logging.error("Could not update audit anchor after restoring a validated backup")
        db.log_audit("system", "BACKUP_RESTORE", "A validated encrypted backup was restored at application startup.")
    
    # --- Phase 3: Main Window ---
    splash_msg("جاري تحميل النظام... (Loading System Components...)")
    window = AlgPIIMainWindow(db)
    
    # --- Done ---
    splash_msg("جاهز! (Ready!)")
    window.showMaximized()
    splash.finish(window)
    
    # Execute application loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
