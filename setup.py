from setuptools import setup, find_packages

setup(
    name="alg_pii_engine",
    version="1.0.0",
    description="Algerian RegTech PII Compliance Platform (Law 18-07)",
    author="Alg-PII Team",
    packages=find_packages(),
    install_requires=[
        "PyQt6>=6.6.0",
        "transformers>=4.40.0",
        "optimum[onnxruntime]>=1.19.0",
        "onnxruntime>=1.17.0",
        "tokenizers>=0.19.0",
        "regex>=2024.4.0",
        "cryptography>=42.0.0",
        "keyring>=25.0.0",
    ],
    entry_points={
        "console_scripts": [
            "alg-pii-engine=main:main",
        ],
    },
)
