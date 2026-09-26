from PyQt6.QtWidgets import (QPushButton, QLabel, QFrame, QWidget, QVBoxLayout, 
                             QSizePolicy, QApplication)
from PyQt6.QtCore import (pyqtSignal, Qt, QPropertyAnimation, QEasingCurve, 
                          QTimer, QRectF)
from PyQt6.QtGui import (QPainter, QColor, QPen, QPainterPath, QLinearGradient, 
                         QFont, QDragEnterEvent, QDropEvent)
from .theme import COLORS

class AnimatedButton(QPushButton):
    """Button with hover scale animation and optional loading state."""
    def __init__(self, text, parent=None, primary=False):
        super().__init__(text, parent)
        self.primary = primary
        self.is_loading = False
        
        if self.primary:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS['ACCENT']};
                    color: white;
                    border: none;
                }}
                QPushButton:hover {{
                    background-color: #f75565;
                }}
                QPushButton:pressed {{
                    background-color: #d13a48;
                }}
            """)
            
        # Add basic scale property for animation if needed
        # (PyQt doesn't natively support scaling via QPropertyAnimation on QWidget without GraphicsView,
        # but we can simulate it with stylesheet or just rely on QSS hover state).
        # We will keep it simple and rely on the QSS transitions for now.

    def set_loading(self, loading: bool):
        self.is_loading = loading
        self.setEnabled(not loading)
        if loading:
            self.setText("جاري المعالجة..." if QApplication.layoutDirection() == Qt.LayoutDirection.RightToLeft else "Processing...")
        else:
            self.setText("فحص والامتثال 🔍" if QApplication.layoutDirection() == Qt.LayoutDirection.RightToLeft else "Scan & Comply 🔍")

class EntityBadge(QFrame):
    """Badge showing entity type and count."""
    def __init__(self, entity_type: str, count: int = 0, color: str = COLORS['BG_BUTTON'], parent=None):
        super().__init__(parent)
        self.entity_type = entity_type
        
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['BG_PANEL']};
                border: 2px solid {color};
                border-radius: 12px;
                padding: 2px 8px;
            }}
            QLabel {{
                color: {COLORS['TEXT_PRIMARY']};
                border: none;
                background: transparent;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        
        self.label = QLabel(f"{entity_type}: {count}")
        font = self.label.font()
        font.setBold(True)
        self.label.setFont(font)
        
        layout.addWidget(self.label)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

    def update_count(self, count: int):
        self.label.setText(f"{self.entity_type}: {count}")

class StatusIndicator(QWidget):
    """Pulsing dot indicating status."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(16, 16)
        self.state = 'ready'
        self.opacity = 1.0
        self.pulse_up = False
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._animate)
        self.timer.start(50)
        
    def set_state(self, state: str):
        self.state = state
        self.update()
        
    def _animate(self):
        if self.state == 'loading':
            if self.pulse_up:
                self.opacity += 0.05
                if self.opacity >= 1.0:
                    self.pulse_up = False
            else:
                self.opacity -= 0.05
                if self.opacity <= 0.3:
                    self.pulse_up = True
            self.update()
        else:
            self.opacity = 1.0
            
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        color = QColor(COLORS['SUCCESS'])
        if self.state == 'loading':
            color = QColor(COLORS['WARNING'])
        elif self.state == 'error':
            color = QColor(COLORS['ERROR'])
            
        color.setAlphaF(self.opacity)
        
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawEllipse(2, 2, 12, 12)

class DropZone(QFrame):
    """Drag and drop file area."""
    file_dropped = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        
        self.setStyleSheet(f"""
            QFrame {{
                border: 2px dashed {COLORS['BG_BUTTON']};
                border-radius: 8px;
                background-color: {COLORS['BG_PANEL']};
            }}
        """)
        
        layout = QVBoxLayout(self)
        self.label = QLabel("اسحب الملفات هنا\n(Drop files here: TXT, PDF, DOCX, XLSX, CSV, PNG, JPG, EML, MSG)")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("border: none; background: transparent; color: #a0a0a0;")
        layout.addWidget(self.label)
        
        self.setMinimumHeight(80)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            self.setStyleSheet(f"""
                QFrame {{
                    border: 2px dashed {COLORS['ACCENT']};
                    border-radius: 8px;
                    background-color: {COLORS['BG_BUTTON']};
                }}
            """)
            event.accept()
        else:
            event.ignore()
            
    def dragLeaveEvent(self, event):
        self.setStyleSheet(f"""
            QFrame {{
                border: 2px dashed {COLORS['BG_BUTTON']};
                border-radius: 8px;
                background-color: {COLORS['BG_PANEL']};
            }}
        """)
        
    def dropEvent(self, event: QDropEvent):
        self.dragLeaveEvent(None)
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            if file_path.lower().endswith(('.txt', '.pdf', '.docx', '.csv', '.xlsx', '.png', '.jpg', '.jpeg', '.tiff', '.bmp')):
                self.file_dropped.emit(file_path)

class ComplianceGauge(QWidget):
    """Circular arc showing compliance score."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(120, 120)
        self.value = 0
        
    def set_value(self, percent: int):
        self.value = max(0, min(100, percent))
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        rect = QRectF(10, 10, 100, 100)
        
        # Draw background arc
        painter.setPen(QPen(QColor(COLORS['BG_BUTTON']), 10, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(rect, 225 * 16, -270 * 16)
        
        # Determine color
        if self.value > 70:
            color = QColor(COLORS['SUCCESS'])
        elif self.value > 30:
            color = QColor(COLORS['WARNING'])
        else:
            color = QColor(COLORS['ERROR'])
            
        # Draw value arc
        span_angle = int(-270 * 16 * (self.value / 100.0))
        if span_angle != 0:
            painter.setPen(QPen(color, 10, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawArc(rect, 225 * 16, span_angle)
            
        # Draw text
        painter.setPen(QColor(COLORS['TEXT_PRIMARY']))
        font = painter.font()
        font.setPointSize(16)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{self.value}%")
