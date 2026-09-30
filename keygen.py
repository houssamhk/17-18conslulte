from engine.license_signer import generate_license

if __name__ == "__main__":
    print("="*50)
    print("Alg-PII Engine - License Key Generator")
    print("="*50)
    
    hwid = input("Enter Client Hardware ID (HWID): ").strip()
    if hwid:
        try:
            days = int(input("Enter validity in days (default 365): ").strip() or "365")
            token = generate_license(hwid, days)
            print("\n[SUCCESS] Generated License Key:")
            print("-" * 50)
            print(token)
            print("-" * 50)
            print(f"Valid for {days} days.")
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("HWID cannot be empty.")
