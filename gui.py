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
        self.login_frame: LoginFrame = LoginFrame(self)
        self.signup_frame: SignupFrame = SignupFrame(self)
        self.chat_frame: ChatFrame = ChatFrame(self)

        # Start with login
        self.show_login()

        #start processing queue for info from server
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
        self.root.title(f"Secure Chat - {self.username}")
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
                    self.root.after(0, lambda: self.login(data))
                except Exception as e:
                    print(f"Error in after: {e}")
            case "show_auth_error":
                self.root.after(0, lambda: messagebox.showerror("Invalid Login", "Invalid User name or password"))
            case "add_active_user":
                self.root.after(0, lambda: self.chat_frame.add_active_user(data))
            case "remove_active_user":
                self.root.after(0, lambda: self.chat_frame.remove_active_user(data))
            case "display_message":
                self.root.after(0, lambda: self.chat_frame.display_message(data[0], data[1]))
            case _:
                return
        #TODO TODO TODO i need more commands here

# ====================== LOGIN PAGE ======================
class LoginFrame:
    def __init__(self, app):
        self.app: SecureChatApp= app
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
        
        self.app.client.username = username
        self.app.client.password = password

        self.app.client.send_login_request()


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
        self.app: SecureChatApp = app
        self.frame = tk.Frame(app.root, bg="#1e1e1e")
        
        #store current selected user and chat history
        self.current_user = None
        self.chat_histories = {} # {username: {list_of_messages}}

        # LEFT FRAME - users
        self.left_frame = tk.Frame(self.frame, width=200, bg="#2c2c2c")
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y)

        tk.Label(self.left_frame, text="Online Users", bg="#2c2c2c", fg="white",
                 font=("Arial", 12, "bold")).pack(pady=10)

        self.user_listbox = tk.Listbox(self.left_frame, bg="#3a3a3a", fg="white",
                                       selectbackground="#5c5c5c")

        self.user_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        #add click event binding
        self.user_listbox.bind('<<ListboxSelect>>', self.on_user_select)

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

    def on_user_select(self, event):
        """Handle user selection from the listbox"""
        selection = self.user_listbox.curselection()
        if selection:
            index = selection[0]
            selected_user = self.user_listbox.get(index)

            #only update if different user
            if selected_user != self.current_user:
                self.current_user = selected_user
                self.update_chat_display()

    def add_active_user(self, name):
        self.user_listbox.insert(tk.END, name)
        #Initialize empty chat history
        self.chat_histories[name] = []

    def remove_active_user(self, name):
        #find user in listbox
        user_list = self.user_listbox.get(0, tk.END)

        for index, username in enumerate(user_list):
            if username == name:
                #remove from listbox
                self.user_listbox.delete(index)

                #remove from chat_histories
                if name in self.chat_histories:
                    del self.chat_histories[name]

            
        
    def update_chat_display(self):
        self.chat_area.config(state='normal')
        self.chat_area.delete(1.0, tk.END)

        if self.current_user and self.current_user in self.chat_histories:
            for message in self.chat_histories[self.current_user]:
                text, alignment = message
                if alignment == "right":
                    self.chat_area.insert(tk.END, f"{text}\n\n", "right")
                else:
                    self.chat_area.insert(tk.END, f"{text}\n\n", "left")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def display_message(self, sender, message):
        if sender not in self.chat_histories:
            self.chat_histories[sender] = []

        self.chat_histories[sender].append((message, "left"))

        #if this sender is currently selected, update the display
        if self.current_user == sender:
            self.update_chat_display()

    def send_message(self, event=None):
        msg = self.msg_entry.get().strip()
        if not msg or not self.current_user:
            return

        #add message to current user chat history
        if self.current_user not in self.chat_histories:
            self.chat_histories[self.current_user] = []

        self.chat_histories[self.current_user].append((msg, "right"))

        #Update display
        self.update_chat_display()

        #clear input and send via client
        self.msg_entry.delete(0, tk.END)

        if self.app.client:
            self.app.client.send_encrypted_message(self.current_user, msg)

    def logout(self):
        confirm = messagebox.askyesno("Logout", "Are you sure you want to log out?")
        if confirm:
            self.app.show_login()

# ====================== RUNN APP ======================
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)

    #a client object to communicate with server
    client = Client()

    #a callback that client will use to send updates to gui using a queue
    client.on_message = lambda cmd, data=None: app.message_queue.put((cmd, data))
    app.client = client

    #connecting to server
    client.dial_server()

    #listen for updates from server through client object in another thread
    thread = threading.Thread(target=app.listen_for_updates,args=(client,), daemon=True)
    thread.start()

    #running main gui
    root.mainloop()



