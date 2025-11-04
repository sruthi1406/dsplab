"""
Hash Functions Implementation
Implementation of common hash functions using Python's hashlib library
Supports hashing of strings, files, and custom data
"""

import hashlib
import os
from typing import Union, Optional

class HashGenerator:
    """A class to generate various hash values for strings and files"""
    
    def __init__(self):
        """Initialize the hash generator"""
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha224': hashlib.sha224,
            'sha384': hashlib.sha384
        }
    
    def hash_string(self, text: str, algorithm: str = 'sha256') -> str:
        """
        Generate hash for a string
        
        Args:
            text (str): Input string to hash
            algorithm (str): Hash algorithm to use (default: sha256)
            
        Returns:
            str: Hexadecimal hash value
        """
        if algorithm.lower() not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Create hash object
        hash_obj = self.supported_algorithms[algorithm.lower()]()
        
        # Update hash with encoded string
        hash_obj.update(text.encode('utf-8'))
        
        # Return hexadecimal representation
        return hash_obj.hexdigest()
    
    def hash_file(self, file_path: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> str:
        """
        Generate hash for a file
        
        Args:
            file_path (str): Path to the file
            algorithm (str): Hash algorithm to use (default: sha256)
            chunk_size (int): Size of chunks to read (default: 8192 bytes)
            
        Returns:
            str: Hexadecimal hash value
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if algorithm.lower() not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Create hash object
        hash_obj = self.supported_algorithms[algorithm.lower()]()
        
        # Read file in chunks to handle large files
        with open(file_path, 'rb') as file:
            while chunk := file.read(chunk_size):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def hash_multiple_algorithms(self, text: str) -> dict:
        """
        Generate hashes using multiple algorithms
        
        Args:
            text (str): Input string to hash
            
        Returns:
            dict: Dictionary with algorithm names as keys and hash values as values
        """
        results = {}
        for algorithm in self.supported_algorithms:
            results[algorithm] = self.hash_string(text, algorithm)
        return results
    
    def compare_hashes(self, text1: str, text2: str, algorithm: str = 'sha256') -> bool:
        """
        Compare hash values of two strings
        
        Args:
            text1 (str): First string
            text2 (str): Second string
            algorithm (str): Hash algorithm to use
            
        Returns:
            bool: True if hashes match, False otherwise
        """
        hash1 = self.hash_string(text1, algorithm)
        hash2 = self.hash_string(text2, algorithm)
        return hash1 == hash2
    
    def verify_file_integrity(self, file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """
        Verify file integrity by comparing with expected hash
        
        Args:
            file_path (str): Path to the file
            expected_hash (str): Expected hash value
            algorithm (str): Hash algorithm to use
            
        Returns:
            bool: True if file hash matches expected hash
        """
        actual_hash = self.hash_file(file_path, algorithm)
        return actual_hash.lower() == expected_hash.lower()


def demonstrate_hash_functions():
    """Demonstrate various hash function capabilities"""
    print("=" * 60)
    print("HASH FUNCTIONS DEMONSTRATION")
    print("=" * 60)
    
    hasher = HashGenerator()
    
    # Test string hashing
    test_string = "Hello, World! This is a test string for hashing."
    print(f"\nOriginal String: {test_string}")
    print("-" * 40)
    
    # Generate hashes with different algorithms
    hashes = hasher.hash_multiple_algorithms(test_string)
    for algorithm, hash_value in hashes.items():
        print(f"{algorithm.upper()}: {hash_value}")
    
    # Test hash comparison
    print("\n" + "=" * 40)
    print("HASH COMPARISON TEST")
    print("=" * 40)
    
    string1 = "identical"
    string2 = "identical"
    string3 = "different"
    
    print(f"String 1: '{string1}'")
    print(f"String 2: '{string2}'")
    print(f"String 3: '{string3}'")
    
    print(f"\nAre strings 1 and 2 identical? {hasher.compare_hashes(string1, string2)}")
    print(f"Are strings 1 and 3 identical? {hasher.compare_hashes(string1, string3)}")
    
    # Demonstrate avalanche effect
    print("\n" + "=" * 40)
    print("AVALANCHE EFFECT DEMONSTRATION")
    print("=" * 40)
    
    original = "password"
    modified = "Password"  # Only one character changed
    
    print(f"Original: '{original}'")
    print(f"Modified: '{modified}'")
    print(f"\nSHA-256 of '{original}': {hasher.hash_string(original)}")
    print(f"SHA-256 of '{modified}': {hasher.hash_string(modified)}")
    
    # Create a test file and hash it
    print("\n" + "=" * 40)
    print("FILE HASHING DEMONSTRATION")
    print("=" * 40)
    
    test_file_path = "test_file.txt"
    test_content = "This is a test file for demonstrating file hashing.\nIt contains multiple lines.\nHash functions work on binary data."
    
    # Create test file
    with open(test_file_path, 'w', encoding='utf-8') as f:
        f.write(test_content)
    
    print(f"Created test file: {test_file_path}")
    file_hash = hasher.hash_file(test_file_path)
    print(f"SHA-256 of file: {file_hash}")
    
    # Verify file integrity
    print(f"File integrity check: {hasher.verify_file_integrity(test_file_path, file_hash)}")
    
    # Clean up
    if os.path.exists(test_file_path):
        os.remove(test_file_path)
        print(f"Cleaned up test file: {test_file_path}")


if __name__ == "__main__":
    demonstrate_hash_functions()
