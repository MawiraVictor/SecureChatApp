import socket
import select
import json
import struct
import sqlite3 
import bcrypt
from base64 import b64encode,b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ===============================
# Secure Chat Server Implementation
# ===============================
# This server supports:
# - Client authentication (login/signup)
# - RSA public key exchange
# - Session key relay between clients
# - Encrypted message delivery
# - Real-time client connection management
# ===============================

class Server():
    def __init__(self):
        # Server configuration
        self.listeningPort: int = 9876
        self.server_sock = None 
        self.listening_address = "localhost"
        
        # Active clients list
        self.active_clients: list[Active_Client] = []
        # Buffer to handle partial message reads from clients
        self.client_buffers = {}

        # Import server RSA keys
        self.private_key, self.public_key = self.import_rsa_keys("server_privkey.pem", "server_pubkey.pem")

        # Confirm key loading
        if self.private_key is None:
            print("Could not get private key")
        if self.public_key is None:
            print("Could not get public key")

    def start_server(self):
        """Starts the main TCP server loop and handles incoming client connections."""
        try:
            # Create non-blocking TCP socket
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.listening_address, self.listeningPort))
            self.server_sock.listen(10)
            self.server_sock.setblocking(False)

            sockets2poll = [self.server_sock]

            print(f"Server Listening on address {self.listening_address} port {self.listeningPort}")

            # Main event loop
            while True:
                # Monitor sockets ready for reading
                readable_socks,_,_ = select.select(sockets2poll, [], [])
                for sock in readable_socks:
                    # If the listening socket, accept new client
                    if sock is self.server_sock:
                        client_conn, addr = self.server_sock.accept()
                        client_conn.setblocking(False)
                        sockets2poll.append(client_conn)
                        self.client_buffers[client_conn] = b""
                        print(f"Got connection from {addr[0]} on port {addr[1]}")
                    else:
                        # Handle client communication
                        print("Client socket ready for reading")
                        try:
                            data = sock.recv(4096)
                            if not data:
                                # Client disconnected
                                print(f"Client disconnected")
                                sockets2poll.remove(sock)
                                del self.client_buffers[sock]
                                self.remove_active_client(sock)
                                sock.close()
                                continue

                            # Append received chunk to buffer
                            self.client_buffers[sock] += data 
                            self.process_client_data(sock)
                        except ConnectionResetError:
                            print("Client forcibly closed connection")
                            sockets2poll.remove(sock)
                            del self.client_buffers[sock]
                            sock.close()
        except KeyboardInterrupt:
            print("Server stopping.....")
        except ConnectionResetError:
            print("Client disconnected")
        except Exception as e:
            print(f"Got error starting server: {e}")
        finally:
            self.server_sock.close()

    def import_rsa_keys(self, private_key_path, public_key_path):
        """Loads RSA keys from PEM files."""
        private_key = None
        public_key = None

        if private_key_path:
            with open(private_key_path, "rb") as f:
                private_key_data = f.read()
                private_key = RSA.import_key(private_key_data)

        if public_key_path:
            with open(public_key_path, "rb") as f:
                public_key_data = f.read()
                public_key = RSA.import_key(public_key_data)

        return private_key, public_key

    def process_client_data(self, sock):
        """Handles buffering and extraction of full JSON messages from clients."""
        print("Processing some client data")
        buff = self.client_buffers[sock]
        while True:
            # Ensure message length header (4 bytes) is available
            if len(buff) < 4:
                break

            # Extract message length (big-endian unsigned int)
            msg_len = struct.unpack(">I", buff[:4])[0]

            # Wait for complete message
            if len(buff) < 4 + msg_len:
                break

            # Extract full message payload
            msg_data = buff[4: 4+msg_len]
            # Remove processed portion from buffer
            buff = buff[4+msg_len:]

            # Handle decoded message
            self.handle_client_message(sock, msg_data)

        # Save leftover partial message
        self.client_buffers[sock] = buff

    def handle_client_message(self, client_conn: socket.socket, msg_data):
        """Decodes and routes client JSON messages."""
        try:
            msg = json.loads(msg_data.decode("utf-8"))
            print(f"Got message from client {msg}")
            command = msg["command"]

            # Match client command
            match command:
                case "login" | "signup":
                    self.authenticate_user(client_conn, command, msg)
                case "send_message":
                    self.send_client_message(msg)
                case "exchange_session_key":
                    self.exchange_session_key(msg)
                case _:
                    print(f"Got unknown command: {command}")

        except Exception as e:
            print(f"Error: {e}")
            return 0

    def authenticate_user(self, client_conn: socket.socket, command, data):
        """Handles secure client login or signup."""
        db = DB()
        message = {
            "command": "auth_denied"
        }
        
        pubkey = data["public_key"]
        uname = data["username"]
        passwd = data["password"]

        # Convert Base64 encoded RSA ciphertext to bytes
        enc_uname = b64decode(uname)
        enc_passwd = b64decode(passwd)

        # Decrypt credentials using server's RSA private key
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        uname = cipher_rsa.decrypt(enc_uname).decode()
        passwd = cipher_rsa.decrypt(enc_passwd).decode()

        # Get list of currently active users and public keys
        active_users = []
        for client in self.active_clients:
            client_details = {
                "username": client.get_name(),
                "public_key": client.get_publickey()
            }
            active_users.append(client_details)

        # Authenticate or register
        status = False
        if command == "login":
            status = db.authenticate_user(uname, passwd)
        elif command == "signup":
            status = db.add_user(uname, passwd)
        else:
            return

        # Send failure response
        if status == False:
            self.send_to_client(client_conn, message)

        # On success, send active peer list
        if status == True:
            message = {
                "command": "auth_granted",
                "peers": active_users
            }
            self.send_to_client(client_conn, message)
            self.add_active_client(Active_Client(uname, pubkey, client_conn))

        db.close()

    def exchange_session_key(self, data: dict):
        """Forwards symmetric session key between peers."""
        receiver = data["peername"]
        sender = data["username"]

        for client in self.active_clients:
            if receiver == client.name:
                message = {
                    "command": "recv_session_key",
                    "peername": sender,
                    "session_key": data["session_key"]
                }
                self.send_to_client(client.connection, message)
                break

    def send_client_message(self, data: dict):
        """Relays encrypted messages between clients."""
        receiver = data["peername"]
        sender = data["username"]

        for client in self.active_clients:
            if receiver == client.name:
                message = {
                    "command": "recv_message",
                    "peername": sender,
                    "message": data["message"],
                    "iv": data["iv"],
                    "mac": data["mac"]
                }
                self.send_to_client(client.connection, message)
                break

    def remove_active_client(self, client_conn: socket.socket):
        """Removes disconnected clients and notifies peers."""
        username = ""
        client_exists = False
        for client in self.active_clients:
            if client_conn == client.connection:
                username = client.name
                client_exists = True
                self.active_clients.remove(client)
                break

        if not client_exists:
            return

        message = {
            "command": "close_peer",
            "peername": username,
        }

        # Notify all active clients
        for client in self.active_clients:
            self.send_to_client(client.connection, message)
        
    def add_active_client(self, client: 'Active_Client'):
        """Adds new authenticated clients and broadcasts their presence."""
        self.active_clients.append(client)

        message = {
            "command": "new_peer",
            "peername": client.name,
            "public_key": client.public_key
        }

        for client in self.active_clients:
            self.send_to_client(client.connection, message)

    def send_to_client(self, client_conn: socket.socket, data: dict):
        """Encodes JSON data and sends length-prefixed packet to client."""
        data = json.dumps(data).encode("utf-8")
        data_len = struct.pack(">I", len(data))
        client_conn.sendall(data_len + data)

# ===============================
# Active Client Representation
# ===============================
class Active_Client():
    def __init__(self, name, public_key, conn):
        self.name = name
        self.public_key = public_key
        self.connection = conn
    
    def set_name(self, name):
        self.name = name

    def set_publickey(self, pubkey):
        self.public_key = pubkey

    def get_name(self):
        return self.name
    
    def get_publickey(self):
        return self.public_key

# ===============================
# Database Management for Users
# ===============================
class DB():
    def __init__(self):
        self.dbname = "securechat.db"
        self.conn = sqlite3.connect(self.dbname)
        self.cursor = self.conn.cursor()

    def add_user(self, username, password) -> bool:
        """Registers a new user if not already in DB."""
        if self.user_exists(username):
            return False
        query = "INSERT INTO users(username, password_hash) VALUES(?, ?)"
        hashed_pass = self.hash_password(password)
        self.cursor.execute(query, (username, hashed_pass))
        self.conn.commit()
        return True

    def hash_password(self, password) -> bytes:
        """Generates bcrypt hash for secure password storage."""
        password = password.encode("utf-8")
        hashed_pass = bcrypt.hashpw(password, bcrypt.gensalt())
        return hashed_pass

    def authenticate_user(self, username, password) -> bool:
        """Verifies login credentials."""
        if not self.user_exists(username):
            print(f"User {username} does not exist")
            return False 

        hashed_pass = self.get_table_field("password_hash", username)
        password = password.encode("utf-8")
        return bcrypt.checkpw(password, hashed_pass)
        
    def get_table_field(self, field_name, username) -> str:
        """Retrieves specific user fields from DB."""
        allowed_fields = ["username", "password_hash", "public_key"]
        if field_name not in allowed_fields:
            print(f"Unknown field {field_name}")
            return None

        query = f"SELECT {field_name} FROM users WHERE username = ?"
        self.cursor.execute(query, (username,))
        row = self.cursor.fetchone()

        if (row is None):
            return None
        return row[0]

    def user_exists(self, username) -> bool:
        """Checks if a username already exists."""
        self.cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", (username,))
        result = self.cursor.fetchone()[0]
        return bool(result)

    def close(self):
        """Closes the database connection."""
        self.conn.close()

# ===============================
# Program Entry Point
# ===============================
if __name__ == "__main__":
    server = Server()
    server.start_server()
