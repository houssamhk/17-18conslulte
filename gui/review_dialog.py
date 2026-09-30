import re

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from engine.regex_detector import DetectedEntity, RegexDetector
from .dialog_utils import configure_dialog_size


class EntityReviewDialog(QDialog):
    """Let a reviewer select detections and add exact-text entities to redact."""

    def __init__(self, original_text: str, entities: list, parent=None, selected_entities=None):
        super().__init__(parent)
        self.original_text = original_text
        self.manual_added_count = 0
        self._initial_selection = {
            self._entity_key(entity) for entity in (selected_entities if selected_entities is not None else entities)
        }
        self.setWindowTitle("مراجعة الكيانات قبل التصدير")
        configure_dialog_size(self, preferred=(1100, 720), minimum=(720, 500))

        layout = QVBoxLayout(self)
        guidance = QLabel(
            "أبقِ خيار الإخفاء محددًا للبيانات الحساسة. أزل التحديد عن النتائج الخاطئة، "
            "وأضف أي قيمة فاتت المحرك. إضافة قيمة تطابق كل ظهور حرفي لها في النص."
        )
        guidance.setWordWrap(True)
        layout.addWidget(guidance)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["إخفاء", "النوع", "النص المكتشف", "الثقة", "المصدر"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, stretch=1)

        actions = QHBoxLayout()
        self.add_button = QPushButton("إضافة كيان فات المحرك")
        self.add_button.clicked.connect(self._add_entity)
        actions.addWidget(self.add_button)
        self.count_label = QLabel()
        actions.addWidget(self.count_label)
        actions.addStretch()
        layout.addLayout(actions)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("تطبيق المراجعة")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("إلغاء")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        for entity in entities:
            self._append_entity(entity, self._entity_key(entity) in self._initial_selection)
        self._update_count()

    @staticmethod
    def _entity_key(entity):
        return entity.start, entity.end, entity.entity_type, entity.text, entity.source

    def _append_entity(self, entity: DetectedEntity, selected=True):
        row = self.table.rowCount()
        self.table.insertRow(row)

        checkbox = QCheckBox()
        checkbox.setChecked(selected)
        checkbox.setToolTip("إزالة التحديد لإبقاء هذا النص دون إخفاء")
        checkbox.stateChanged.connect(self._update_count)
        self.table.setCellWidget(row, 0, checkbox)

        for column, value in enumerate((entity.entity_type, entity.text, f"{entity.confidence:.1%}", entity.source), start=1):
            item = QTableWidgetItem(str(value))
            item.setData(Qt.ItemDataRole.UserRole, entity)
            self.table.setItem(row, column, item)
        self.table.setRowHeight(row, 34)

    def _selected_entities(self):
        selected = []
        for row in range(self.table.rowCount()):
            checkbox = self.table.cellWidget(row, 0)
            entity = self.table.item(row, 1).data(Qt.ItemDataRole.UserRole)
            if checkbox.isChecked():
                selected.append(entity)
        return sorted(selected, key=lambda entity: (entity.start, entity.end))

    def _update_count(self, *_):
        self.count_label.setText(f"سيتم إخفاء {len(self._selected_entities())} قيمة")

    def _add_entity(self):
        value, accepted = QInputDialog.getText(self, "إضافة كيان يدويًا", "أدخل النص الحرفي المراد إخفاؤه:")
        if not accepted or not value:
            return

        entity_labels = {
            **{entity_type: labels['ar'] for entity_type, labels in RegexDetector.TYPE_LABELS.items()},
            "PER": "شخص",
            "LOC": "موقع",
            "ORG": "منظمة",
            "MISC": "كيان آخر",
        }
        type_options = [f"{entity_type} — {label}" for entity_type, label in entity_labels.items()]
        selected, accepted = QInputDialog.getItem(
            self, "نوع الكيان", "اختر التصنيف:", type_options, 0, False
        )
        if not accepted:
            return
        entity_type = selected.split(" — ", 1)[0]

        existing_ranges = [(entity.start, entity.end) for entity in self._selected_entities()]
        matches = list(re.finditer(re.escape(value), self.original_text))
        added = 0
        for match in matches:
            start, end = match.span()
            if any(max(start, old_start) < min(end, old_end) for old_start, old_end in existing_ranges):
                continue
            entity = DetectedEntity(
                text=match.group(),
                entity_type=entity_type,
                start=start,
                end=end,
                confidence=1.0,
                source="manual_review",
            )
            self._append_entity(entity)
            existing_ranges.append((start, end))
            added += 1

        if not added:
            QMessageBox.information(
                self,
                "لم تتم إضافة قيمة",
                "لم يُعثر على النص حرفيًا، أو أن كل مرات ظهوره تتداخل مع كيانات محددة للإخفاء.",
            )
        else:
            self.manual_added_count += added
        self._update_count()

    def reviewed_entities(self):
        return self._selected_entities()

    def all_entities(self):
        return [
            self.table.item(row, 1).data(Qt.ItemDataRole.UserRole)
            for row in range(self.table.rowCount())
        ]
