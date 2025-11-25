#!/usr/bin/env python3
"""
Text Crypto Tool - Main entry point
Secure text encryption using AES, DES, and RSA algorithms
"""

import sys
from src.cli import cli

def main():
    """Main entry point for the application"""
    try:
        # Start the CLI in interactive mode if no arguments provided
        if len(sys.argv) == 1:
            sys.argv.append('interactive')
        
        cli()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()