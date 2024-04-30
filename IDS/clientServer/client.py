import socket

def start_client(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("Connected to server.")

    try:
        while True:
            message = input("Enter message to send: ")
            client_socket.sendall(message.encode())
    finally:
        client_socket.close()

if __name__ == "__main__":
    host = '127.0.0.1'
    port = 12345
    start_client(host, port)
