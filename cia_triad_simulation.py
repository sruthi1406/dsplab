import hashlib
import time
import threading
import os

# --- Utility Functions ---
def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    """Prints a formatted header."""
    clear_screen()
    print("=" * 50)
    print(f"--- {title.upper()} ---")
    print("=" * 50)
    print()

# --- 1. Confidentiality Module (Simple XOR Cipher) ---
def xor_cipher(text, key):
    """A simple XOR cipher for demonstration."""
    return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(text, key * (len(text) // len(key) + 1)))

def simulate_confidentiality():
    """Demonstrates encryption and decryption."""
    print_header("Confidentiality Simulation")
    print("Confidentiality means keeping data secret.")
    print("We'll use a simple XOR cipher to encrypt your message.\n")
    
    try:
        message = input("Enter a secret message to encrypt: ")
        key = input("Enter a simple password (key) to use: ")
        
        if not message or not key:
            print("\nMessage and key cannot be empty.")
            return

        print("\nEncrypting your message...")
        time.sleep(1)
        encrypted_message = xor_cipher(message, key)
        print(f" -> Encrypted (unreadable) data: {encrypted_message}\n")

        print("The data is now confidential. Only someone with the key can read it.")
        time.sleep(2)
        
        decrypt_choice = input("Do you want to decrypt it back? (yes/no): ").lower()
        if decrypt_choice.startswith('y'):
            print("\nDecrypting with the same key...")
            time.sleep(1)
            decrypted_message = xor_cipher(encrypted_message, key)
            print(f" -> Decrypted (original) message: {decrypted_message}")
        else:
            print("\nDecryption skipped. The message remains confidential.")

    except Exception as e:
        print(f"An error occurred: {e}")


# --- 2. Integrity Module (SHA-256 Hashing) ---
def get_hash(message):
    """Calculates the SHA-256 hash of a message."""
    return hashlib.sha256(message.encode()).hexdigest()

def simulate_integrity():
    """Demonstrates data integrity with hashing."""
    print_header("Integrity Simulation")

    original_message = input("Enter a message to protect: ")
    original_hash = get_hash(original_message)
    
    print("\nCalculating the original hash...")
    time.sleep(1)
    print(f" -> Original Hash: {original_hash}\n")
    
    print("Let's check it on the other side to see if it was changed.\n")
    time.sleep(2)
    
    received_message = input("Re-enter the message as if you just received it: ")
    received_hash = get_hash(received_message)
    
    print("\nCalculating the received hash...")
    time.sleep(1)
    print(f" -> Received Hash: {received_hash}\n")
    
    print("Comparing hashes...")
    time.sleep(1)
    if original_hash == received_hash:
        print("✅ SUCCESS: The hashes match! The message integrity is verified.")
    else:
        print("❌ FAILURE: The hashes DO NOT match! The message was tampered with.")


# --- 3. Availability Module (Threaded Request Simulation) ---
def server_request(request_id):
    """Simulates a server processing a request."""
    processing_time = 0.1
    time.sleep(processing_time)
    # The print statement is removed to avoid clutter during the flood
    
def simulate_availability():
    """Demonstrates system availability under load."""
    print_header("Availability Simulation")
    print("Availability means the system is accessible when needed.")
    print("We will simulate a server handling requests.\n")
    
    # Normal Operation
    print("1. Simulating normal traffic (3 requests)...")
    for i in range(3):
        server_request(i)
        print(f"   -> Request {i+1} completed.")
        time.sleep(0.5)
    print("Server handled normal traffic easily.\n")
    time.sleep(2)
    
    # Flood Simulation
    num_requests = 100
    print(f"2. Simulating a flood of {num_requests} requests (like a DDoS attack)...")
    
    threads = []
    start_time = time.time()
    
    for i in range(num_requests):
        t = threading.Thread(target=server_request, args=(i,))
        t.start()
        threads.append(t)
        
    # Simple progress bar
    for i, t in enumerate(threads):
        t.join()
        progress = int((i + 1) / num_requests * 20)
        print(f"   Processing: [{'#' * progress}{'-' * (20 - progress)}] {i+1}/{num_requests}", end='\r')
    
    end_time = time.time()
    
    print("\n\nProcessing complete.")
    print(f"Total time taken: {end_time - start_time:.2f} seconds.\n")
    
    if end_time - start_time < 5: # Arbitrary threshold for success
        print("✅ SUCCESS: The server handled all requests and remained available!")
    else:
        print("❌ FAILURE: The server slowed down significantly and availability was impacted.")


# --- Main Menu ---
def main():
    """Main function to run the CIA Triad simulation menu."""
    while True:
        print_header("CIA Triad Interactive Simulation")
        print("Choose a concept to explore:")
        print("  1. Confidentiality (Keeping data secret)")
        print("  2. Integrity (Preventing data tampering)")
        print("  3. Availability (Ensuring data is accessible)")
        print("  4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '1':
            simulate_confidentiality()
        elif choice == '2':
            simulate_integrity()
        elif choice == '3':
            simulate_availability()
        elif choice == '4':
            print("\nExiting simulation. Goodbye!\n")
            break
        else:
            print("\nInvalid choice. Please enter a number between 1 and 4.")
            
        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main()
