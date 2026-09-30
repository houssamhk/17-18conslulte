"""Screen-aware sizing helpers for application dialogs."""

from PyQt6.QtWidgets import QApplication


def configure_dialog_size(dialog, preferred=(760, 560), minimum=(420, 320), margin=48):
    """Give a dialog a useful resizable size without exceeding its screen."""
    dialog.setSizeGripEnabled(True)
    screen = dialog.screen() or QApplication.primaryScreen()
    if screen is None:
        dialog.resize(*preferred)
        dialog.setMinimumSize(*minimum)
        return

    available = screen.availableGeometry()
    max_width = max(320, available.width() - margin)
    max_height = max(240, available.height() - margin)
    min_width = min(minimum[0], max_width)
    min_height = min(minimum[1], max_height)
    dialog.setMinimumSize(min_width, min_height)
    dialog.resize(min(preferred[0], max_width), min(preferred[1], max_height))
