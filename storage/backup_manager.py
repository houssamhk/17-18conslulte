"""Encrypted SQLCipher backup creation, validation, and restart-time restore."""

import os
import shutil
import time
import uuid
import hashlib
import hmac
import json

from . import secure_db as secure_db_module
from .key_manager import KeyManager


class SecureBackupManager:
    FORMAT_VERSION = b"ALGPII-SQLCIPHER-BACKUP-V1\n"

    @staticmethod
    def _key_for_database(db):
        key = KeyManager.ensure_key(data_exists=True)
        if not key or not db._use_sqlcipher:
            raise RuntimeError("لا يمكن إنشاء نسخة إلا باستخدام SQLCipher ومفتاح التخزين الحالي.")
        return key

    @classmethod
    def create_backup(cls, db, destination):
        """Create a consistent SQLCipher snapshot through the online backup API."""
        key = cls._key_for_database(db)
        destination = os.path.abspath(destination)
        if os.path.normcase(destination) == os.path.normcase(db.db_path):
            raise ValueError("لا يمكن حفظ النسخة فوق قاعدة البيانات المستخدمة.")
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        temporary = destination + "." + uuid.uuid4().hex + ".tmp"
        container_temporary = temporary + ".container"
        backup_conn = None
        try:
            backup_conn = secure_db_module.sqlite.connect(temporary, timeout=30.0)
            backup_conn.execute(f"PRAGMA key = '{key.hex()}'")
            db.conn.backup(backup_conn, pages=256, sleep=0.05)
            check = backup_conn.execute("PRAGMA quick_check").fetchone()
            if not check or str(check[0]).lower() != "ok":
                raise RuntimeError("فشل فحص سلامة النسخة الاحتياطية.")
            backup_conn.commit()
            backup_conn.close()
            backup_conn = None
            with open(temporary, "rb") as stream:
                header = stream.read(16)
                has_payload = os.fstat(stream.fileno()).st_size > 0
            if not has_payload or header.startswith(b"SQLite format 3\x00"):
                raise RuntimeError("النسخة الناتجة فارغة أو غير مشفّرة.")
            cls._wrap_database_file(temporary, container_temporary)
            # Do not publish or report a backup until the packaged snapshot
            # has been reopened and validated independently with the same key.
            cls._validate_backup(container_temporary, key)
            os.replace(container_temporary, destination)
            return {"path": destination, "size": os.path.getsize(destination), "header": header}
        finally:
            if backup_conn is not None:
                backup_conn.close()
            if os.path.exists(temporary):
                os.remove(temporary)
            if os.path.exists(container_temporary):
                os.remove(container_temporary)

    @classmethod
    def _validate_backup(cls, path, key):
        with open(path, "rb") as stream:
            if stream.read(len(cls.FORMAT_VERSION)) != cls.FORMAT_VERSION:
                raise ValueError("صيغة ملف النسخة الاحتياطية غير معروفة.")
        probe = path + "." + uuid.uuid4().hex + ".validate"
        try:
            with open(path, "rb") as source, open(probe, "wb") as target:
                source.seek(len(cls.FORMAT_VERSION))
                shutil.copyfileobj(source, target)
            connection = secure_db_module.sqlite.connect(probe, timeout=15.0)
            try:
                connection.execute(f"PRAGMA key = '{key.hex()}'")
                connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
                check = connection.execute("PRAGMA quick_check").fetchone()
                if not check or str(check[0]).lower() != "ok":
                    raise ValueError("فشل فحص سلامة قاعدة البيانات داخل النسخة.")
                cls._verify_backup_audit_chain(connection, key)
            finally:
                connection.close()
        except Exception as exc:
            if isinstance(exc, ValueError):
                raise
            raise ValueError("تعذر فتح النسخة بهذا المفتاح؛ تأكد أنها من هذا التثبيت ولم تتلف.") from exc
        finally:
            for temporary_path in (probe, probe + "-wal", probe + "-shm"):
                if os.path.exists(temporary_path):
                    os.remove(temporary_path)

    @staticmethod
    def _verify_backup_audit_chain(connection, key):
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "audit_log" not in tables:
            return
        columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_log)")}
        required = {"id", "timestamp", "username", "action", "details", "previous_hash", "entry_hash", "hash_version"}
        if not required.issubset(columns):
            return  # Legacy backup predating tamper-evident audit chains.
        rows = connection.execute(
            "SELECT id, timestamp, username, action, details, previous_hash, entry_hash, hash_version FROM audit_log ORDER BY id"
        ).fetchall()
        prefixed = [row for row in rows if isinstance(row[6], str) and row[6].startswith("hmac-sha256-v2:")]
        if not prefixed:
            return
        previous_entry_hash = None
        for entry_id, timestamp, username, action, details, previous_hash, entry_hash, version in rows:
            if version != "hmac-sha256-v2" or not isinstance(entry_hash, str) or not entry_hash.startswith("hmac-sha256-v2:"):
                raise ValueError(f"سجل التدقيق في النسخة غير مكتمل عند السجل {entry_id}.")
            payload = json.dumps(
                [entry_id, timestamp or "", username or "", action or "", details or "", previous_hash or ""],
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            expected = "hmac-sha256-v2:" + hmac.new(key, payload, hashlib.sha256).hexdigest()
            if previous_entry_hash is not None and (previous_hash or "") != previous_entry_hash:
                raise ValueError(f"رابط سلسلة التدقيق تالف عند السجل {entry_id}.")
            if not hmac.compare_digest(entry_hash, expected):
                raise ValueError(f"بصمة سجل التدقيق غير صحيحة عند السجل {entry_id}.")
            previous_entry_hash = entry_hash

    @classmethod
    def _wrap_database_file(cls, source_path, destination_path):
        temporary = destination_path + "." + uuid.uuid4().hex + ".tmp"
        try:
            with open(temporary, "wb") as output:
                output.write(cls.FORMAT_VERSION)
                with open(source_path, "rb") as source:
                    shutil.copyfileobj(source, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination_path)
        finally:
            if os.path.exists(temporary):
                os.remove(temporary)

    @classmethod
    def stage_restore(cls, db, backup_path):
        """Validate then stage a backup for application of on the next launch."""
        key = cls._key_for_database(db)
        backup_path = os.path.abspath(backup_path)
        cls._validate_backup(backup_path, key)
        pending_path = db.db_path + ".restore-pending"
        temporary = pending_path + "." + uuid.uuid4().hex + ".tmp"
        try:
            shutil.copy2(backup_path, temporary)
            os.replace(temporary, pending_path)
        finally:
            if os.path.exists(temporary):
                os.remove(temporary)
        return pending_path

    @classmethod
    def validate_backup(cls, db, backup_path):
        """Validate format, SQLCipher key, database pages, and audit-chain HMACs."""
        key = cls._key_for_database(db)
        cls._validate_backup(os.path.abspath(backup_path), key)
        return True

    @classmethod
    def apply_pending_restore(cls, db_path):
        """Apply a validated staged restore before the application opens the DB."""
        db_path = os.path.abspath(db_path)
        pending_path = db_path + ".restore-pending"
        if not os.path.isfile(pending_path):
            return False
        key = KeyManager.ensure_key(data_exists=True)
        cls._validate_backup(pending_path, key)
        staged_db = db_path + ".restore-staged"
        with open(pending_path, "rb") as source, open(staged_db, "wb") as target:
            source.seek(len(cls.FORMAT_VERSION))
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())

        safety_copy = f"{db_path}.pre-restore-{time.strftime('%Y%m%d-%H%M%S')}"
        moved_old_db = False
        try:
            if os.path.exists(db_path):
                cls._wrap_database_file(db_path, safety_copy + ".apibak")
                safety_copy += ".apibak"
                moved_old_db = True
            for suffix in ("-wal", "-shm"):
                sidecar = db_path + suffix
                if os.path.exists(sidecar):
                    os.remove(sidecar)
            os.replace(staged_db, db_path)
            os.remove(pending_path)
            return True
        except Exception:
            if moved_old_db and os.path.exists(safety_copy):
                try:
                    key = KeyManager.ensure_key(data_exists=True)
                    cls._validate_backup(safety_copy, key)
                    with open(safety_copy, "rb") as source, open(db_path, "wb") as target:
                        source.seek(len(cls.FORMAT_VERSION))
                        shutil.copyfileobj(source, target)
                except Exception:
                    pass
            raise
        finally:
            if os.path.exists(staged_db):
                os.remove(staged_db)
