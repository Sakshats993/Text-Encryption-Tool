"""
Command-line interface for the text encryption tool.
Provides interactive menus and operation handling.
"""

import click
import json
import sys
from pathlib import Path
from colorama import init, Fore, Style
from .crypto_core import CryptoCore
from .hybrid_crypto import HybridCrypto
from .key_manager import KeyManager

# Initialize colorama for cross-platform colored output
init()


class CryptoTool:
    """Main CLI handler for crypto operations"""
    
    def __init__(self):
        self.crypto = CryptoCore()
        self.hybrid = HybridCrypto()
        self.key_mgr = KeyManager()
    
    def print_success(self, message: str):
        """Print success message in green"""
        click.echo(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
    
    def print_error(self, message: str):
        """Print error message in red"""
        click.echo(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")
    
    def print_warning(self, message: str):
        """Print warning message in yellow"""
        click.echo(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")
    
    def print_info(self, message: str):
        """Print info message in blue"""
        click.echo(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")
    
    def save_result(self, data: dict, filename: str = None) -> str:
        """Save encryption result to file"""
        if not filename:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"encrypted_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filename
    
    def load_result(self, filename: str) -> dict:
        """Load encryption result from file"""
        with open(filename, 'r') as f:
            return json.load(f)


@click.group()
@click.pass_context
def cli(ctx):
    """Text Crypto Tool - Secure text encryption with AES, DES, and RSA"""
    ctx.obj = CryptoTool()


@cli.command()
@click.pass_obj
def interactive(tool):
    """Interactive mode with menu"""
    while True:
        click.clear()
        click.echo(f"{Fore.CYAN}{'='*50}")
        click.echo(f"      TEXT CRYPTO TOOL - Main Menu")
        click.echo(f"{'='*50}{Style.RESET_ALL}\n")
        
        click.echo("1. Encrypt text")
        click.echo("2. Decrypt text")
        click.echo("3. Generate keys")
        click.echo("4. Manage keys")
        click.echo("5. Run tests")
        click.echo("6. Exit\n")
        
        choice = click.prompt("Select an option", type=int)
        
        if choice == 1:
            encrypt_menu(tool)
        elif choice == 2:
            decrypt_menu(tool)
        elif choice == 3:
            generate_keys_menu(tool)
        elif choice == 4:
            manage_keys_menu(tool)
        elif choice == 5:
            run_tests(tool)
        elif choice == 6:
            click.echo("\nGoodbye!")
            sys.exit(0)
        else:
            tool.print_error("Invalid option")
        
        click.pause()


def encrypt_menu(tool):
    """Encryption submenu"""
    click.clear()
    click.echo(f"{Fore.CYAN}ENCRYPTION{Style.RESET_ALL}\n")
    
    click.echo("Select algorithm:")
    click.echo("1. AES-256-GCM (Recommended)")
    click.echo("2. DES-CBC (Educational only - NOT SECURE)")
    click.echo("3. RSA-OAEP (Small text only)")
    click.echo("4. Hybrid (RSA + AES for large text)")
    
    alg_choice = click.prompt("\nSelect algorithm", type=int)
    
    # Get plaintext
    click.echo("\nEnter text to encrypt (press Enter twice to finish):")
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    plaintext = '\n'.join(lines)
    
    if not plaintext:
        tool.print_error("No text provided")
        return
    
    try:
        result = None
        
        if alg_choice == 1:  # AES
            tool.print_info("Encrypting with AES-256-GCM...")
            result = tool.crypto.encrypt_aes_gcm(plaintext)
            
        elif alg_choice == 2:  # DES
            tool.print_warning("DES is obsolete and insecure - for educational purposes only!")
            if click.confirm("Continue anyway?"):
                tool.print_info("Encrypting with DES-CBC...")
                result = tool.crypto.encrypt_des_cbc(plaintext)
            
        elif alg_choice == 3:  # RSA
            # Check for existing or generate new RSA keys
            keys = tool.key_mgr.list_keys()
            if keys['rsa_pairs']:
                click.echo("\nAvailable RSA key pairs:")
                for i, name in enumerate(keys['rsa_pairs'], 1):
                    click.echo(f"{i}. {name}")
                click.echo(f"{len(keys['rsa_pairs'])+1}. Generate new key pair")
                
                key_choice = click.prompt("Select key", type=int)
                if key_choice <= len(keys['rsa_pairs']):
                    key_name = keys['rsa_pairs'][key_choice-1]
                    _, public_key = tool.key_mgr.load_rsa_keypair(key_name)
                else:
                    key_name = "default"
                    private_key, public_key = tool.crypto.generate_rsa_keypair()
                    tool.key_mgr.save_rsa_keypair(key_name, private_key, public_key)
            else:
                tool.print_info("Generating RSA key pair...")
                private_key, public_key = tool.crypto.generate_rsa_keypair()
                key_name = click.prompt("Enter name for key pair", default="default")
                tool.key_mgr.save_rsa_keypair(key_name, private_key, public_key)
            
            tool.print_info("Encrypting with RSA-OAEP...")
            result = tool.crypto.encrypt_rsa_oaep(plaintext, public_key)
            
        elif alg_choice == 4:  # Hybrid
            # Similar to RSA, but use hybrid encryption
            keys = tool.key_mgr.list_keys()
            if keys['rsa_pairs']:
                click.echo("\nAvailable RSA key pairs:")
                for i, name in enumerate(keys['rsa_pairs'], 1):
                    click.echo(f"{i}. {name}")
                
                key_choice = click.prompt("Select key", type=int, default=1)
                key_name = keys['rsa_pairs'][key_choice-1]
                _, public_key = tool.key_mgr.load_rsa_keypair(key_name)
            else:
                tool.print_info("Generating RSA key pair...")
                private_key, public_key = tool.crypto.generate_rsa_keypair()
                key_name = click.prompt("Enter name for key pair", default="default")
                tool.key_mgr.save_rsa_keypair(key_name, private_key, public_key)
            
            tool.print_info("Encrypting with Hybrid (RSA + AES)...")
            result = tool.hybrid.encrypt(plaintext, public_key)
        
        if result:
            # Save to file
            filename = tool.save_result(result)
            tool.print_success(f"Encrypted data saved to {filename}")
            
            # Display summary
            click.echo(f"\n{Fore.GREEN}Encryption successful!{Style.RESET_ALL}")
            click.echo(f"Algorithm: {result['scheme']}")
            click.echo(f"Timestamp: {result['meta'].get('timestamp', 'N/A')}")
            
            if click.confirm("\nShow encrypted data?"):
                click.echo(json.dumps(result, indent=2))
    
    except Exception as e:
        tool.print_error(f"Encryption failed: {str(e)}")


def decrypt_menu(tool):
    """Decryption submenu"""
    click.clear()
    click.echo(f"{Fore.CYAN}DECRYPTION{Style.RESET_ALL}\n")
    
    # Get encrypted file
    filename = click.prompt("Enter encrypted file path", type=click.Path(exists=True))
    
    try:
        # Load encrypted data
        encrypted_data = tool.load_result(filename)
        scheme = encrypted_data.get('scheme', 'unknown')
        
        tool.print_info(f"Loaded {scheme} encrypted data")
        
        result = None
        
        if scheme == "AES-256-GCM":
            tool.print_info("Decrypting AES-256-GCM...")
            result = tool.crypto.decrypt_aes_gcm(encrypted_data)
            
        elif scheme == "DES-CBC":
            tool.print_warning("Decrypting DES-CBC (obsolete algorithm)...")
            result = tool.crypto.decrypt_des_cbc(encrypted_data)
            
        elif scheme == "RSA-OAEP":
            # Need to select private key
            keys = tool.key_mgr.list_keys()
            if not keys['rsa_pairs']:
                tool.print_error("No RSA keys found")
                return
            
            click.echo("\nAvailable RSA key pairs:")
            for i, name in enumerate(keys['rsa_pairs'], 1):
                click.echo(f"{i}. {name}")
            
            key_choice = click.prompt("Select private key", type=int)
            key_name = keys['rsa_pairs'][key_choice-1]
            private_key, _ = tool.key_mgr.load_rsa_keypair(key_name)
            
            tool.print_info("Decrypting RSA-OAEP...")
            result = tool.crypto.decrypt_rsa_oaep(encrypted_data, private_key)
            
        elif scheme == "hybrid":
            # Need private key for hybrid
            keys = tool.key_mgr.list_keys()
            if not keys['rsa_pairs']:
                tool.print_error("No RSA keys found")
                return
            
            click.echo("\nAvailable RSA key pairs:")
            for i, name in enumerate(keys['rsa_pairs'], 1):
                click.echo(f"{i}. {name}")
            
            key_choice = click.prompt("Select private key", type=int)
            key_name = keys['rsa_pairs'][key_choice-1]
            private_key, _ = tool.key_mgr.load_rsa_keypair(key_name)
            
            tool.print_info("Decrypting Hybrid (RSA + AES)...")
            result = tool.hybrid.decrypt(encrypted_data, private_key)
        
        else:
            tool.print_error(f"Unknown encryption scheme: {scheme}")
            return
        
        if result:
            tool.print_success("Decryption successful!")
            click.echo(f"\n{Fore.GREEN}Decrypted text:{Style.RESET_ALL}")
            click.echo("-" * 40)
            click.echo(result)
            click.echo("-" * 40)
    
    except Exception as e:
        tool.print_error(f"Decryption failed: {str(e)}")


def generate_keys_menu(tool):
    """Key generation submenu"""
    click.clear()
    click.echo(f"{Fore.CYAN}KEY GENERATION{Style.RESET_ALL}\n")
    
    click.echo("1. Generate RSA key pair")
    click.echo("2. Generate AES key")
    click.echo("3. Generate DES key (educational only)")
    
    choice = click.prompt("\nSelect option", type=int)
    
    try:
        if choice == 1:
            key_size = click.prompt("RSA key size", type=click.Choice(['2048', '3072', '4096']), default='2048')
            key_name = click.prompt("Enter name for key pair", default="rsa_key")
            
            tool.print_info(f"Generating {key_size}-bit RSA key pair...")
            private_key, public_key = tool.crypto.generate_rsa_keypair(int(key_size))
            
            tool.key_mgr.save_rsa_keypair(key_name, private_key, public_key)
            tool.print_success(f"RSA key pair '{key_name}' generated and saved")
            
        elif choice == 2:
            key_size = click.prompt("AES key size", type=click.Choice(['128', '192', '256']), default='256')
            key_name = click.prompt("Enter name for key", default="aes_key")
            
            tool.print_info(f"Generating {key_size}-bit AES key...")
            key = tool.crypto.generate_key("AES", int(key_size))
            
            tool.key_mgr.save_symmetric_key(key_name, key, {"algorithm": "AES", "size": key_size})
            tool.print_success(f"AES key '{key_name}' generated and saved")
            
        elif choice == 3:
            tool.print_warning("DES is obsolete and insecure!")
            if click.confirm("Generate anyway?"):
                key_name = click.prompt("Enter name for key", default="des_key")
                
                tool.print_info("Generating DES key...")
                key = tool.crypto.generate_key("DES")
                
                tool.key_mgr.save_symmetric_key(key_name, key, {"algorithm": "DES", "warning": "obsolete"})
                tool.print_success(f"DES key '{key_name}' generated and saved")
    
    except Exception as e:
        tool.print_error(f"Key generation failed: {str(e)}")


def manage_keys_menu(tool):
    """Key management submenu"""
    click.clear()
    click.echo(f"{Fore.CYAN}KEY MANAGEMENT{Style.RESET_ALL}\n")
    
    keys = tool.key_mgr.list_keys()
    
    if not keys['rsa_pairs'] and not keys['symmetric_keys']:
        tool.print_info("No keys found")
        return
    
    click.echo("Available keys:\n")
    
    if keys['rsa_pairs']:
        click.echo(f"{Fore.YELLOW}RSA Key Pairs:{Style.RESET_ALL}")
        for name in keys['rsa_pairs']:
            click.echo(f"  • {name}")
    
    if keys['symmetric_keys']:
        click.echo(f"\n{Fore.YELLOW}Symmetric Keys:{Style.RESET_ALL}")
        for name in keys['symmetric_keys']:
            click.echo(f"  • {name}")
    
    click.echo("\nOptions:")
    click.echo("1. Delete a key")
    click.echo("2. Export public key")
    click.echo("3. Back to main menu")
    
    choice = click.prompt("\nSelect option", type=int)
    
    if choice == 1:
        key_name = click.prompt("Enter key name to delete")
        key_type = click.prompt("Key type", type=click.Choice(['rsa', 'symmetric', 'all']), default='all')
        
        if click.confirm(f"Delete '{key_name}'? This cannot be undone."):
            try:
                tool.key_mgr.delete_key(key_name, key_type)
                tool.print_success(f"Key '{key_name}' deleted")
            except Exception as e:
                tool.print_error(f"Failed to delete key: {str(e)}")
    
    elif choice == 2:
        if not keys['rsa_pairs']:
            tool.print_info("No RSA keys available")
            return
        
        key_name = click.prompt("Enter RSA key pair name")
        try:
            _, public_key = tool.key_mgr.load_rsa_keypair(key_name)
            export_file = f"{key_name}_public_export.pem"
            
            with open(export_file, 'wb') as f:
                f.write(public_key)
            
            tool.print_success(f"Public key exported to {export_file}")
        except Exception as e:
            tool.print_error(f"Failed to export key: {str(e)}")


def run_tests(tool):
    """Run basic tests to verify functionality"""
    click.clear()
    click.echo(f"{Fore.CYAN}RUNNING TESTS{Style.RESET_ALL}\n")
    
    test_text = "Hello, World! This is a test message. 🔐"
    tests_passed = 0
    tests_failed = 0
    
    # Test 1: AES-GCM
    try:
        tool.print_info("Testing AES-256-GCM...")
        encrypted = tool.crypto.encrypt_aes_gcm(test_text)
        decrypted = tool.crypto.decrypt_aes_gcm(encrypted)
        assert decrypted == test_text
        tool.print_success("AES-256-GCM test passed")
        tests_passed += 1
    except Exception as e:
        tool.print_error(f"AES-256-GCM test failed: {str(e)}")
        tests_failed += 1
    
    # Test 2: DES-CBC
    try:
        tool.print_info("Testing DES-CBC...")
        encrypted = tool.crypto.encrypt_des_cbc(test_text)
        decrypted = tool.crypto.decrypt_des_cbc(encrypted)
        assert decrypted == test_text
        tool.print_success("DES-CBC test passed")
        tests_passed += 1
    except Exception as e:
        tool.print_error(f"DES-CBC test failed: {str(e)}")
        tests_failed += 1
    
    # Test 3: RSA-OAEP (small text)
    try:
        tool.print_info("Testing RSA-OAEP...")
        private_key, public_key = tool.crypto.generate_rsa_keypair(2048)
        small_text = "Small test"
        encrypted = tool.crypto.encrypt_rsa_oaep(small_text, public_key)
        decrypted = tool.crypto.decrypt_rsa_oaep(encrypted, private_key)
        assert decrypted == small_text
        tool.print_success("RSA-OAEP test passed")
        tests_passed += 1
    except Exception as e:
        tool.print_error(f"RSA-OAEP test failed: {str(e)}")
        tests_failed += 1
    
    # Test 4: Hybrid encryption
    try:
        tool.print_info("Testing Hybrid encryption...")
        private_key, public_key = tool.crypto.generate_rsa_keypair(2048)
        encrypted = tool.hybrid.encrypt(test_text, public_key)
        decrypted = tool.hybrid.decrypt(encrypted, private_key)
        assert decrypted == test_text
        tool.print_success("Hybrid encryption test passed")
        tests_passed += 1
    except Exception as e:
        tool.print_error(f"Hybrid encryption test failed: {str(e)}")
        tests_failed += 1
    
    # Test 5: Tampering detection
    try:
        tool.print_info("Testing tampering detection...")
        encrypted = tool.crypto.encrypt_aes_gcm(test_text)
        
        # Tamper with ciphertext
        import base64
        tampered = encrypted.copy()
        ciphertext = base64.b64decode(tampered['ciphertext'])
        tampered_ciphertext = bytes([(b + 1) % 256 for b in ciphertext])
        tampered['ciphertext'] = base64.b64encode(tampered_ciphertext).decode('utf-8')
        
        # Should raise an exception
        try:
            tool.crypto.decrypt_aes_gcm(tampered)
            tool.print_error("Tampering detection failed - decryption should have failed!")
            tests_failed += 1
        except:
            tool.print_success("Tampering detection test passed")
            tests_passed += 1
    except Exception as e:
        tool.print_error(f"Tampering detection test failed: {str(e)}")
        tests_failed += 1
    
    # Summary
    click.echo(f"\n{Fore.CYAN}{'='*40}")
    click.echo(f"Test Results:")
    click.echo(f"{'='*40}{Style.RESET_ALL}")
    click.echo(f"{Fore.GREEN}Passed: {tests_passed}{Style.RESET_ALL}")
    click.echo(f"{Fore.RED}Failed: {tests_failed}{Style.RESET_ALL}")
    
    if tests_failed == 0:
        tool.print_success("All tests passed! ✨")
    else:
        tool.print_warning(f"{tests_failed} test(s) failed")


if __name__ == '__main__':
    cli()