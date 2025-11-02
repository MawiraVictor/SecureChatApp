import tkinter as tk
from tkinter import messagebox, scrolledtext
import queue

import time
import threading

from client import Client


class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("700x500")
        self.root.configure(bg="#1e1e1e")
        

        self.client: Client = None
        self.username = None
        self.message_queue = queue.Queue()

        # Initialize all frames
        self.login_frame = LoginFrame(self)
        self.signup_frame = SignupFrame(self)
        self.chat_frame = ChatFrame(self)

        # Start with login
        self.show_login()

        #start processing queue
        self.process_queue()

    def process_queue(self):
        try:
            while True:
                command, data = self.message_queue.get_nowait()
                self.do_command(command,data)
        except queue.Empty:
            pass
        finally:
            #check again after 100ms
            self.root.after(100, self.process_queue)

    def show_login(self):
        """Display login page."""
        self.signup_frame.frame.pack_forget()
        self.chat_frame.frame.pack_forget()
        self.login_frame.frame.pack(fill=tk.BOTH, expand=True)

    def show_signup(self):
        """Display signup page."""
        self.login_frame.frame.pack_forget()
        self.chat_frame.frame.pack_forget()
        self.signup_frame.frame.pack(fill=tk.BOTH, expand=True)

    def show_chat(self):
        """Display chat page."""
        self.login_frame.frame.pack_forget()
        self.signup_frame.frame.pack_forget()
        self.chat_frame.frame.pack(fill=tk.BOTH, expand=True)

    def login(self, username):
        """Triggered when user logs in successfully."""
        self.username = username
        self.show_chat()

    def signup(self, username):
        """Triggered when a new user signs up."""
        messagebox.showinfo("Account Created", f"Account created for {username}")
        self.show_login()

    def listen_for_updates(self, client: Client):
        while True:
            client.poll_server()
            time.sleep(0.5)

    def do_command(self, command, data=None):
        match command:
            case "show_chat":
                try:
                    self.root.after(0, lambda: self.login("TestUser"))
                except Exception as e:
                    print(f"Error in after: {e}")
            case _:
                return
        #TODO TODO TODO

# ====================== LOGIN PAGE ======================
class LoginFrame:
    def __init__(self, app):
        self.app = app
        self.frame = tk.Frame(app.root, bg="#1e1e1e")

        tk.Label(self.frame, text="Secure Chat Login", bg="#1e1e1e", fg="white",
                 font=("Arial", 18, "bold")).pack(pady=40)

        tk.Label(self.frame, text="Username:", bg="#1e1e1e", fg="white",
                 font=("Arial", 12)).pack(pady=(10, 5))

        self.username_entry = tk.Entry(self.frame, width=25, bg="#2c2c2c", fg="white",
                                       insertbackground="white", font=("Arial", 12))
        self.username_entry.pack(pady=(0, 15))

        tk.Label(self.frame, text="Password:", bg="#1e1e1e", fg="white",
                 font=("Arial", 12)).pack(pady=(5, 5))
        self.password_entry = tk.Entry(self.frame, width=25, bg="#2c2c2c", fg="white",
                                       insertbackground="white", font=("Arial", 12),
                                       show="*")

        self.password_entry.pack(pady=(0, 20))
        self.password_entry.bind("<Return>", self.handle_login)

        login_btn = tk.Button(self.frame, text="Login", bg="#007acc", fg="white",
                              font=("Arial", 12, "bold"), relief="flat", width=10,
                              command=self.handle_login)

        login_btn.pack(pady=(5, 10))

        # --- Signup navigation ---
        tk.Label(self.frame, text="Don't have an account?", bg="#1e1e1e", fg="gray").pack(pady=(10, 2))
        signup_btn = tk.Button(self.frame, text="Sign Up", bg="#3a3a3a", fg="white",
                               relief="flat", width=12, command=self.app.show_signup)
        signup_btn.pack()

    def handle_login(self, event=None):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        if username == "admin" and password == "1234":
            self.app.login(username)
        else:
            messagebox.showerror("Error", "Invalid username or password.")


# ====================== SIGNUP PAGE ======================
class SignupFrame:
    def __init__(self, app):
        self.app: SecureChatApp= app
        self.frame = tk.Frame(app.root, bg="#1e1e1e")

        tk.Label(self.frame, text="Create Account", bg="#1e1e1e", fg="white",
                 font=("Arial", 18, "bold")).pack(pady=40)

        tk.Label(self.frame, text="Choose a Username:", bg="#1e1e1e", fg="white",
                 font=("Arial", 12)).pack(pady=(10, 5))

        self.username_entry = tk.Entry(self.frame, width=25, bg="#2c2c2c", fg="white",
                                       insertbackground="white", font=("Arial", 12))
        self.username_entry.pack(pady=(0, 15))

        tk.Label(self.frame, text="Choose a Password:", bg="#1e1e1e", fg="white",
                 font=("Arial", 12)).pack(pady=(5, 5))
        self.password_entry = tk.Entry(self.frame, width=25, bg="#2c2c2c", fg="white",
                                       insertbackground="white", font=("Arial", 12),
                                       show="*")
        self.password_entry.pack(pady=(0, 15))

        tk.Label(self.frame, text="Confirm Password:", bg="#1e1e1e", fg="white",
                 font=("Arial", 12)).pack(pady=(5, 5))
        self.confirm_entry = tk.Entry(self.frame, width=25, bg="#2c2c2c", fg="white",
                                      insertbackground="white", font=("Arial", 12),
                                      show="*")
        self.confirm_entry.pack(pady=(0, 20))

        signup_btn = tk.Button(self.frame, text="Sign Up", bg="#007acc", fg="white",
                               font=("Arial", 12, "bold"), relief="flat", width=10,
                               command=self.handle_signup)
        signup_btn.pack(pady=(5, 10))

        # --- Back to Login ---
        tk.Label(self.frame, text="Already have an account?", bg="#1e1e1e", fg="gray").pack(pady=(10, 2))
        login_btn = tk.Button(self.frame, text="Log In", bg="#3a3a3a", fg="white",
                              relief="flat", width=12, command=self.app.show_login)
        login_btn.pack()

    def handle_signup(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        confirm = self.confirm_entry.get().strip()

        if not username or not password or not confirm:
            messagebox.showerror("Error", "All fields are required.")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        self.app.client.username = username
        self.app.client.password = password
        self.app.client.send_signup_request()


# ====================== CHAT PAGE ======================
class ChatFrame:
    def __init__(self, app):
        self.app = app
        self.frame = tk.Frame(app.root, bg="#1e1e1e")

        # LEFT FRAME - users
        self.left_frame = tk.Frame(self.frame, width=200, bg="#2c2c2c")
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)

        tk.Label(self.left_frame, text="Online Users", bg="#2c2c2c", fg="white",
                 font=("Arial", 12, "bold")).pack(pady=10)

        self.user_listbox = tk.Listbox(self.left_frame, bg="#3a3a3a", fg="white",
                                       selectbackground="#5c5c5c")

        self.user_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for user in ["Alice", "Bob", "Charlie"]:
            self.user_listbox.insert(tk.END, user)

        # RIGHT FRAME - chat + input
        self.right_frame = tk.Frame(self.frame, bg="#1e1e1e")
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.chat_area = scrolledtext.ScrolledText(self.right_frame, wrap=tk.WORD,
                                                   state='disabled', bg="#252526", fg="white")

        self.chat_area.tag_config("right", justify="right")
        self.chat_area.tag_config("left", justify="left")

        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.bottom_frame = tk.Frame(self.right_frame, bg="#1e1e1e")
        self.bottom_frame.pack(fill=tk.X, padx=10, pady=10)

        self.msg_entry = tk.Entry(self.bottom_frame, bg="#3a3a3a", fg="white",
                                  insertbackground="white")
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.msg_entry.bind("<Return>", self.send_message)

        send_button = tk.Button(self.bottom_frame, text="Send", bg="#007acc", fg="white",
                                relief="flat", command=self.send_message)
        send_button.pack(side=tk.RIGHT)

        logout_button = tk.Button(self.left_frame, text="Logout", bg="#cc0000", fg="white",
                                  relief="flat", command=self.logout)
        logout_button.pack(pady=10)

    def display_message(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + "\n\n", "left")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def send_message(self, event=None):
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        self.display_message(f"You: {msg}")
        self.msg_entry.delete(0, tk.END)

    def logout(self):
        confirm = messagebox.askyesno("Logout", "Are you sure you want to log out?")
        if confirm:
            self.app.show_login()

# ====================== RUN APP ======================
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)

    client = Client()
    client.on_message = lambda cmd, data=None: app.message_queue.put((cmd, data))
    app.client = client

    client.dial_server()

    thread = threading.Thread(target=app.listen_for_updates,args=(client,), daemon=True)
    thread.start()
    root.mainloop()



