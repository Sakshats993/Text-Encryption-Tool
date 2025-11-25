# Run all tests
pytest tests/ -v --cov=src

# Run specific test categories
pytest tests/test_crypto.py::TestCryptoCore -v
pytest tests/test_crypto.py::TestHybridCrypto -v

# Run security tests
pytest tests/test_security.py -v

# Performance benchmarks
python tests/benchmark.py