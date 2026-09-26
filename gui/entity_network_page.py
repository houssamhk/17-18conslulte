from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QPushButton)
from PyQt6.QtCore import Qt
from gui.theme import COLORS

class EntityNetworkPage(QWidget):
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self._init_ui()
        
    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("شبكة الكيانات (Entity Network)")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['TEXT_PRIMARY']};")
        
        refresh_btn = QPushButton("تحديث (Refresh)")
        refresh_btn.setFixedWidth(120)
        refresh_btn.clicked.connect(self.load_data)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(refresh_btn)
        layout.addLayout(header_layout)
        
        # Info label
        info = QLabel("يعرض هذا الجدول الكيانات (مثل أرقام الهوية، الأسماء) التي ظهرت في أكثر من مستند واحد، مما يشير إلى انتشار البيانات أو احتمال وجود تسريب.")
        info.setStyleSheet(f"color: {COLORS['TEXT_SECONDARY']};")
        info.setWordWrap(True)
        layout.addWidget(info)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["النوع (Type)", "الكيان (Entity)", "عدد المستندات (Doc Count)", "المستندات (Documents)"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)
        
        self.load_data()
        
    def load_data(self):
        from engine.cross_linker import CrossLinker
        linker = CrossLinker(self.db)
        
        results = linker.get_widespread_entities(min_documents=2)
        
        self.table.setRowCount(len(results))
        for row, res in enumerate(results):
            type_item = QTableWidgetItem(res['entity_type'])
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            val_item = QTableWidgetItem(res['entity_text'])
            val_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            count_item = QTableWidgetItem(str(res['document_count']))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Highlight if it's in many documents
            if res['document_count'] >= 5:
                count_item.setForeground(Qt.GlobalColor.red)
                
            docs_item = QTableWidgetItem(", ".join(res['documents']))
            
            self.table.setItem(row, 0, type_item)
            self.table.setItem(row, 1, val_item)
            self.table.setItem(row, 2, count_item)
            self.table.setItem(row, 3, docs_item)
