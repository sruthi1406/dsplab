import asyncio
import websockets
import ssl
from nacl.public import PrivateKey, SealedBox, PublicKey
import sys

# --- Get client name from command-line arguments ---
if len(sys.argv) > 1:
    CLIENT_NAME = sys.argv[1]
else:
    # Default name if none is provided
    CLIENT_NAME = "Client"

# --- TLS setup ---
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# --- Generate keys ---
private_key = PrivateKey.generate()
public_key = private_key.public_key

print(f"📢 {CLIENT_NAME}, share this public key with your friend:")
print(public_key.encode().hex())

# --- Friend's public key (paste from the other client!) ---
FRIEND_PUBLIC_KEY_HEX = input("Paste friend's public key: ").strip()
friend_public_key = bytes.fromhex(FRIEND_PUBLIC_KEY_HEX)
friend_box = SealedBox(PublicKey(friend_public_key))

async def chat():
    # Use a separate thread for blocking input
    loop = asyncio.get_running_loop()

    async with websockets.connect("wss://localhost:8765", ssl=ssl_context) as websocket:
        print(f"✅ {CLIENT_NAME} connected. Start typing and press Enter. Type 'exit' to quit.\n")
        print(f"{CLIENT_NAME}: ", end="", flush=True) # Initial prompt

        async def send_messages():
            while True:
                msg = await loop.run_in_executor(None, input) # Bare input, prompt is handled by receive_messages
                if msg.lower() == 'exit':
                    break
                
                # Prepend name to message for sending
                full_message = f"{CLIENT_NAME}: {msg}"
                try:
                    ciphertext = friend_box.encrypt(full_message.encode())
                    await websocket.send(ciphertext.hex())
                except Exception as e:
                    print(f"Error sending message: {e}")
            await websocket.close()


        async def receive_messages():
            try:
                async for message in websocket:
                    ciphertext = bytes.fromhex(message)
                    box = SealedBox(private_key)
                    try:
                        plaintext = box.decrypt(ciphertext).decode()
                        # Clear the current line and print the message (which now includes the sender's name)
                        print(f"\r{' ' * 80}\r{plaintext}")
                        print(f"{CLIENT_NAME}: ", end="", flush=True) # Reprint the input prompt
                    except Exception:
                        print(f"\r{' ' * 80}\r⚠️ Received undecryptable message!")
                        print(f"{CLIENT_NAME}: ", end="", flush=True)
            except websockets.exceptions.ConnectionClosed:
                print("\nConnection to server lost.")

        # Run both tasks concurrently
        send_task = asyncio.create_task(send_messages())
        receive_task = asyncio.create_task(receive_messages())
        
        await asyncio.wait([send_task, receive_task], return_when=asyncio.FIRST_COMPLETED)

if __name__ == "__main__":
    try:
        asyncio.run(chat())
    except (KeyboardInterrupt, EOFError):
        print("\nExiting chat.")
