import asyncio
import ssl
import websockets

# TLS setup
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

connected_clients = set()

async def relay(websocket):
    # register
    connected_clients.add(websocket)
    try:
        async for message in websocket:
            # relay to all others
            for client in connected_clients:
                if client != websocket:
                    await client.send(message)
    finally:
        connected_clients.remove(websocket)

async def main():
    async with websockets.serve(relay, "localhost", 8765, ssl=ssl_context):
        print("✅ Secure server running on wss://localhost:8765")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
