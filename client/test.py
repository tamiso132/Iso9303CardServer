import websocket

ws = websocket.WebSocket()
ws.connect("ws://localhost:5000/ws")
ws.send("Hello server!")
print(ws.recv())
ws.close()