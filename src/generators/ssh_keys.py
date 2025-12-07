"""
SSH Key Generator
Generates fake SSH private and public keys
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.backends import default_backend
from typing import Dict, Tuple
import base64


class SSHKeyGenerator:
    """Generate fake SSH keys"""
    
    @staticmethod
    def generate_rsa_keypair(bits: int = 2048, comment: str = "user@host") -> Dict[str, str]:
        """
        Generate a fake RSA SSH key pair
        
        Args:
            bits: Key size (2048 or 4096)
            comment: Comment for the key
            
        Returns:
            Dictionary with private_key and public_key
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key = private_key.public_key()
        public_ssh = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        public_ssh_with_comment = f"{public_ssh} {comment}"
        
        return {
            "private_key": private_pem,
            "public_key": public_ssh_with_comment,
            "type": "rsa",
            "bits": bits,
            "comment": comment
        }
    
    @staticmethod
    def generate_ed25519_keypair(comment: str = "user@host") -> Dict[str, str]:
        """
        Generate a fake ED25519 SSH key pair
        
        Args:
            comment: Comment for the key
            
        Returns:
            Dictionary with private_key and public_key
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key = private_key.public_key()
        public_ssh = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        public_ssh_with_comment = f"{public_ssh} {comment}"
        
        return {
            "private_key": private_pem,
            "public_key": public_ssh_with_comment,
            "type": "ed25519",
            "comment": comment
        }
    
    @staticmethod
    def generate_all_ssh_keys() -> list[Dict[str, str]]:
        """Generate multiple SSH keys with different comments"""
        keys = []
        
        keys.append(SSHKeyGenerator.generate_rsa_keypair(
            bits=2048,
            comment="prod-server-backup@production.internal"
        ))
        
        keys.append(SSHKeyGenerator.generate_rsa_keypair(
            bits=4096,
            comment="root@db-cluster-01.region-a"
        ))
        
        keys.append(SSHKeyGenerator.generate_ed25519_keypair(
            comment="deploy@production"
        ))
        
        keys.append(SSHKeyGenerator.generate_ed25519_keypair(
            comment="ci-cd@jenkins.internal"
        ))
        
        keys.append(SSHKeyGenerator.generate_rsa_keypair(
            bits=2048,
            comment="admin@vpn-gateway"
        ))
        
        keys.append(SSHKeyGenerator.generate_ed25519_keypair(
            comment="backup-user@nas-01"
        ))
        
        return keys


if __name__ == "__main__":
    print("=== Generating SSH Keys ===\n")
    
    print("RSA 2048-bit Key:")
    rsa_key = SSHKeyGenerator.generate_rsa_keypair(comment="test@example.com")
    print(f"Private Key:\n{rsa_key['private_key'][:200]}...\n")
    print(f"Public Key:\n{rsa_key['public_key']}\n")
    
    print("ED25519 Key:")
    ed_key = SSHKeyGenerator.generate_ed25519_keypair(comment="deploy@production")
    print(f"Private Key:\n{ed_key['private_key'][:200]}...\n")
    print(f"Public Key:\n{ed_key['public_key']}\n")
    
    print("=== All Generated Keys ===")
    all_keys = SSHKeyGenerator.generate_all_ssh_keys()
    for i, key in enumerate(all_keys, 1):
        print(f"\nKey {i}: {key['type'].upper()} - {key['comment']}")

