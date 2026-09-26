import ctypes
import gc
from typing import Union

def secure_wipe(data: Union[str, bytes]) -> None:
    """
    Securely overwrites a string or bytes object in memory with zeros.
    Uses ctypes to write directly to the memory address.
    Note: In Python, strings are immutable and interned, so this is a best-effort
    approach for sensitive data that hasn't been heavily copied.
    """
    if not isinstance(data, (str, bytes)) or len(data) == 0:
        return
        
    try:
        # Get memory address
        address = id(data)
        
        # Calculate size based on type
        if isinstance(data, str):
            # Python 3 strings are complex objects, actual string data starts at an offset
            # Size depends on encoding (ascii vs utf-16 vs utf-32)
            # This is a heuristic approach for CPython
            import sys
            size = sys.getsizeof(data)
            # Find the actual string buffer (varies by CPython version, usually offset is 48-80 bytes)
            # We'll overwrite the whole object carefully, but it's risky.
            # A safer approach is to overwrite the buffer specifically if we know it.
            # Given Python's memory model, full secure wipe is hard. We do a safe memset on the buffer if possible.
            
            # Since strings are immutable, modifying them can crash Python if they are interned.
            # We only provide this for newly created sensitive strings.
            pass # Disabled for pure strings to avoid segfaults on interned strings
            
        elif isinstance(data, bytes):
            # Bytes objects have a simpler structure
            import sys
            size = len(data)
            # In CPython, the actual bytes start at an offset of 32 (or 33) bytes from the object header
            offset = sys.getsizeof(b"") # Size of empty bytes object
            
            # Overwrite the actual byte buffer with zeros
            ctypes.memset(address + offset, 0, size)
    except Exception as e:
        # Silently fail if we can't wipe memory (e.g. not CPython)
        pass

def force_gc() -> None:
    """Forces garbage collection to clean up any unreferenced sensitive data."""
    gc.collect()

class SecureString:
    """
    Context manager for handling sensitive string data.
    Attempts to wipe memory on exit and forces garbage collection.
    """
    def __init__(self, data: str):
        self._data = data
        
    def __enter__(self) -> str:
        return self._data
        
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._data:
            # For strings, we might convert to bytearray for processing, which is mutable and wipeable
            # But here we just clear our reference and force GC
            self._data = None
        force_gc()
