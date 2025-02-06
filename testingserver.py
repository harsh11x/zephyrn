import asyncio
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread

class ChatServer:
    def __init__(self):
        self.clients = []
        self.server = None

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        self.clients.append(writer)
        print(f"Client connected: {addr}")
        chat_display.insert(tk.END, f"Client connected: {addr}\n")
        chat_display.yview(tk.END)

        while True:
            data = await reader.read(100)
            if not data:
                break
            message = data.decode()
            print(f"Received: {message}")
            chat_display.insert(tk.END, f"Client: {message}\n")
            chat_display.yview(tk.END)
            for client in self.clients:
                if client is not writer:
                    client.write(data)
                    await client.drain()

        print(f"Client disconnected: {addr}")
        chat_display.insert(tk.END, f"Client disconnected: {addr}\n")
        chat_display.yview(tk.END)
        self.clients.remove(writer)
        writer.close()

    async def start_server(self):
        self.server = await asyncio.start_server(self.handle_client, '0.0.0.0', 12345)
        addr = self.server.sockets[0].getsockname()
        print(f'Serving on {addr}')
        status_label.config(text=f"Server started and listening on {addr}")
        while True:
            await asyncio.sleep(3600)

def run_server():
    server = ChatServer()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(server.start_server())

def start_server():
    global server_thread
    server_thread = Thread(target=run_server)
    server_thread.start()

# GUI setup
root = tk.Tk()
root.title("Chat Application")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

tk.Button(frame, text="Start Server", command=start_server).pack(pady=5)

status_label = tk.Label(frame, text="")
status_label.pack()

chat_display = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20, width=50)
chat_display.pack(pady=5)

message_entry = tk.Entry(frame, width=40)
message_entry.pack(side=tk.LEFT, padx=5)

def send_message():
    # Functionality for sending messages will be added later
    pass

send_button = tk.Button(frame, text="Send", command=send_message)
send_button.pack(side=tk.LEFT)

root.mainloop()
