import socket

def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server is listening for connections...")
    client_socket, client_address = server_socket.accept()
    print(f"Connected to client: {client_address}")

    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            print("Received from client:", data.decode())
    finally:
        client_socket.close()
        server_socket.close()

if __name__ == "__main__":
    host = '127.0.0.1'
    port = 12345
    start_server(host, port)
