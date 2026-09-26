import jwt
import argparse
from datetime import datetime, timedelta

# Import the secret key directly from the engine
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from engine.license_manager import LicenseManager

def generate_key(hwid: str, days_valid: int = 365) -> str:
    """Generates a JWT license key for a specific Hardware ID."""
    payload = {
        "hwid": hwid.upper(),
        "exp": datetime.utcnow() + timedelta(days=days_valid),
        "iat": datetime.utcnow(),
        "product": "Alg-PII Engine Enterprise"
    }
    
    token = jwt.encode(payload, LicenseManager.SECRET_KEY, algorithm="HS256")
    return token

if __name__ == "__main__":
    print("="*50)
    print("Alg-PII Engine - License Key Generator")
    print("="*50)
    
    hwid = input("Enter Client Hardware ID (HWID): ").strip()
    if hwid:
        try:
            days = int(input("Enter validity in days (default 365): ").strip() or "365")
            token = generate_key(hwid, days)
            print("\n[SUCCESS] Generated License Key:")
            print("-" * 50)
            print(token)
            print("-" * 50)
            print(f"Valid for {days} days.")
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("HWID cannot be empty.")
