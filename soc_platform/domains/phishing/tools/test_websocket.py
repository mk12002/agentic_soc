import asyncio
import json
from pathlib import Path
import websockets
import httpx
import sys

async def upload_file(client, file_path):
    with open(file_path, "rb") as f:
        files = {"file": (file_path.name, f, "text/plain")}
        print(f"Uploading {file_path.name}...")
        response = await client.post("http://localhost:8000/ingest-raw-email", files=files)
        response.raise_for_status()
        data = response.json()
        print(f"Upload successful. Analysis ID: {data['analysis_id']}")
        return data['analysis_id']

async def run_websocket_probe() -> int:
    # 1. Create a dummy EML file
    dummy_eml = Path("dummy.eml")
    dummy_eml.write_bytes(b"From: badguy@evil.com\nTo: user@company.com\nSubject: Invoice\n\nPlease pay the invoice.")

    try:
        async with httpx.AsyncClient() as client:
            analysis_id = await upload_file(client, dummy_eml)

        # 2. Connect to WS
        print("Connecting to ws://localhost:8000/ws/orchestrator")
        async with websockets.connect("ws://localhost:8000/ws/orchestrator") as websocket:
            print("Connected.")
            updates = []
            
            while True:
                msg_str = await asyncio.wait_for(websocket.recv(), timeout=20.0)
                msg = json.loads(msg_str)
                if msg.get("analysis_id") != analysis_id:
                    continue
                
                print(f"Received WS Event: {msg['event_type']} - {msg.get('agent_name', msg.get('verdict', ''))}")
                updates.append(msg)
                
                if msg["event_type"] == "final_verdict":
                    print("Received final verdict! WebSocket probe PASSED.")
                    break
    except Exception as e:
        print(f"Probe failed: {e}")
        return 1
    finally:
        if dummy_eml.exists():
            dummy_eml.unlink()
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(run_websocket_probe()))
