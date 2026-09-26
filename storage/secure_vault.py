import os
import uuid
import shutil
from cryptography.fernet import Fernet
from storage.secure_db import SecureDatabase
from storage.key_manager import KeyManager

class SecureVault:
    """Manages AES-256 encrypted storage for sensitive documents."""
    
    def __init__(self, db: SecureDatabase, vault_dir: str = 'd:/draham/storage/document_vault'):
        self.db = db
        self.vault_dir = vault_dir
        
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)
            
        # We reuse the main encryption key, or generate a specific one for the vault
        key = KeyManager.ensure_key()
        self.fernet = Fernet(key)
        
    def store_document(self, source_path: str, department: str, username: str, description: str = "") -> bool:
        """Encrypts and stores a document in the vault."""
        if not os.path.exists(source_path):
            return False
            
        original_filename = os.path.basename(source_path)
        file_id = str(uuid.uuid4())
        vault_path = os.path.join(self.vault_dir, f"{file_id}.enc")
        
        try:
            with open(source_path, 'rb') as f:
                data = f.read()
                
            encrypted_data = self.fernet.encrypt(data)
            
            with open(vault_path, 'wb') as f:
                f.write(encrypted_data)
                
            # Log in DB (we don't need a separate IV for Fernet as it handles it)
            c = self.db.conn.cursor()
            c.execute('''INSERT INTO document_vault 
                         (original_filename, vault_path, encryption_iv, uploaded_by, department, description)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (original_filename, vault_path, 'fernet_v1', username, department, description))
            self.db.conn.commit()
            return True
        except Exception as e:
            import logging
            logging.error(f"Failed to store document in vault: {e}")
            return False
            
    def retrieve_document(self, vault_id: int, destination_path: str) -> bool:
        """Decrypts and retrieves a document from the vault."""
        c = self.db.conn.cursor()
        c.execute("SELECT vault_path, original_filename FROM document_vault WHERE id=?", (vault_id,))
        row = c.fetchone()
        
        if not row:
            return False
            
        vault_path, original_filename = row
        
        if os.path.isdir(destination_path):
            destination_path = os.path.join(destination_path, original_filename)
            
        try:
            with open(vault_path, 'rb') as f:
                encrypted_data = f.read()
                
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            with open(destination_path, 'wb') as f:
                f.write(decrypted_data)
                
            return True
        except Exception as e:
            import logging
            logging.error(f"Failed to retrieve document from vault: {e}")
            return False

    def list_documents(self, department: str = None) -> list:
        c = self.db.conn.cursor()
        if department:
            c.execute("SELECT id, original_filename, uploaded_by, department, description, created_at FROM document_vault WHERE department=? ORDER BY created_at DESC", (department,))
        else:
            c.execute("SELECT id, original_filename, uploaded_by, department, description, created_at FROM document_vault ORDER BY created_at DESC")
        return c.fetchall()

    def delete_document(self, vault_id: int) -> bool:
        c = self.db.conn.cursor()
        c.execute("SELECT vault_path FROM document_vault WHERE id=?", (vault_id,))
        row = c.fetchone()
        if row:
            vault_path = row[0]
            if os.path.exists(vault_path):
                os.remove(vault_path)
            c.execute("DELETE FROM document_vault WHERE id=?", (vault_id,))
            self.db.conn.commit()
            return True
        return False
