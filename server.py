import socket
import select
import json
import struct
import sqlite3 
import bcrypt
import traceback


class Server():
    def __init__(self):
        self.listeningPort: int = 9876
        self.server_sock = None 
        self.listening_address = "localhost"
        self.active_clients: list[Active_Client] = []
        self.client_buffers = {}

    def start_server(self):
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.listening_address, self.listeningPort))
            self.server_sock.listen(10)
            self.server_sock.setblocking(False)

            
            sockets2poll = [self.server_sock]

            print(f"Server Listening on address {self.listening_address} port {self.listeningPort}")

            while True:
                readable_socks,_,_ = select.select(sockets2poll, [], [])
                for sock in readable_socks:
                    #if the socket is the listening socket meaning a new connection has arrived
                    if sock is self.server_sock:
                        client_conn, addr = self.server_sock.accept()
                        client_conn.setblocking(False)
                        #add the new socket to client sockets to poll
                        sockets2poll.append(client_conn)
                        self.client_buffers[client_conn] = b""
                        print(f"Got connection from {addr[0]} on port {addr[1]}")
                    else:
                        print("Client socket reading for reading")
                        try:
                            data = sock.recv(4096)
                            if not data:
                                print(f"Client disconnected")
                                sockets2poll.remove(sock)
                                del self.client_buffers[sock]
                                self.remove_active_client(sock)
                                sock.close()
                                continue

                            #append received chunck to client buffer
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
            traceback.print_exc()
        finally:
            self.server_sock.close()


    def process_client_data(self, sock):
        print("Processing some client data")
        buff = self.client_buffers[sock]
        while True:
            if len(buff) < 4:
                break   # not enough data

            msg_len = struct.unpack(">I", buff[:4])[0]

            if len(buff) < 4 + msg_len:
                break  #full message not yet  received

            #extract and process full message
            msg_data = buff[4: 4+msg_len]
            #remove processed bytes
            buff = buff[4+msg_len:]

            self.handle_client_message(sock, msg_data)

        #save remaining unprocessed data back
        self.client_buffers[sock] = buff

    def handle_client_message(self, client_conn: socket.socket, msg_data):
        try:
            msg = json.loads(msg_data.decode("utf-8"))

            print(f"Got message from client {msg}")
            #read the command from json
            command = msg["command"]
            #available commands from client: login, signup, exchange_session_key, send_message

            match command:
                case "login" | "signup":
                    self.authenticate_user(client_conn, command, msg)
                case "send_message":
                    self.send_client_message(msg, client_conn)
                case "exchange_session_key":
                    self.exchange_session_key(msg, client_conn)
                case _:
                    print(f"Got unknown command: {command}")

        except Exception as e:
            print(f"Error: {e}")
            return 0

    def authenticate_user(self, client_conn: socket.socket, command, data):
        db = DB()
        message = {
            "command": "auth_denied"
        }
        
        uname = data["username"]
        passwd = data["password"]
        pubkey = data["public_key"]

        #get all other active users and public keys to send to client
        active_users = []
        for client in self.active_clients:
            client_details = {
                "username": client.get_name(),
                "public_key"  : client.get_publickey()
            }
            active_users.append(client_details)

        status = False

        if command == "login":
            status = db.authenticate_user(uname, passwd)
        elif command == "signup":
            status = db.add_user(uname,passwd)
        else: 
            return

        #if not authorized
        if status == False:
            self.send_to_client(client_conn, message)

        #check if authorized then send peers and auth_granted
        if status == True:
            message = {
                "command": "auth_granted",
                "peers": active_users
            }
            self.send_to_client(client_conn, message)
            self.add_active_client(Active_Client(uname, pubkey, client_conn))

        db.close()

    def exchange_session_key(self, data: dict, client_conn: socket.socket):
        receiver = data["peername"]
        sender = data["username"]

        for client in self.active_clients:
            if receiver == client.name:
                message = {
                    "command" : "recv_session_key",
                    "peername": sender,
                    "session_key": data["session_key"]
                }

                self.send_to_client(client_conn, message)
                break

    def send_client_message(self, data: dict, client_conn: socket.socket):
        receiver = data["peername"]
        sender = data["username"]

        for client in self.active_clients:
            if receiver == client.name:
                message = {
                    "command" : "recv_message",
                    "peername": sender,
                    "message": data["message"],
                    "iv"    : data["iv"]
                }

                self.send_to_client(client_conn, message)
                break

    def remove_active_client(self, client_conn: socket.socket):
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
        for client in self.active_clients:
            self.send_to_client(client.connection, message)
        
    def add_active_client(self, client: Active_Client):
        self.active_clients.append(client)

        message = {
            "command" : "new_peer",
            "peername": client.name,
            "public_key": client.public_key
        }

        for client in self.active_clients:
            self.send_to_client(client.connection, message)

    def send_to_client(self, client_conn: socket.socket, data: dict):
        data = json.dumps(data).encode("utf-8")
        data_len = struct.pack(">I", len(data))
        client_conn.sendall(data_len + data)

class Active_Client():
    def __init__(self, name, public_key,conn):
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
        
class DB():
    def __init__(self):
        self.dbname = "securechat.db"
        self.conn = sqlite3.connect(self.dbname)
        self.cursor = self.conn.cursor()

    def add_user(self, username, password) -> bool:
        if self.user_exists(username):
            return False
        query = "INSERT INTO users(username, password_hash, public_key) VALUES(?, ?, ?)"
        hashed_pass = self.hash_password(password);
        self.cursor.execute(query, (username, hashed_pass, "samplepubkey"))
        self.conn.commit()
        return True

    def hash_password(self, password) -> bytes:
        #converting string to bytes first
        password = password.encode("utf-8")
        hashed_pass = bcrypt.hashpw(password, bcrypt.gensalt())
        return hashed_pass

    def authenticate_user(self, username, password) -> bool:
        if not self.user_exists(username):
            print(f"User {username} does not exist")
            return False 

        hashed_pass = self.get_table_field("password_hash", username)
        
        #changing string pass to bytes
        password = password.encode("utf-8")
        return bcrypt.checkpw(password, hashed_pass)
        

    def get_table_field(self, field_name, username) -> str:
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
        self.cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", (username,))
        result = self.cursor.fetchone()[0]
        return bool(result)

    def close(self):
        self.conn.close()

if __name__ == "__main__":
    server = Server()
    server.start_server()



