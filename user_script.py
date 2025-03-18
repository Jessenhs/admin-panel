import socket
import requests
import datetime

# Use localhost since both scripts are running on the same machine
ADMIN_IP = "127.0.0.1"  # Localhost IP for same machine communication
ADMIN_PORT = 4444  # Port that the admin server is listening on

try:
    # Get the public IP address of the machine using an external service
    public_ip = requests.get("https://api64.ipify.org").text
    
    # Get geolocation data for the public IP address
    geo_url = f"https://ipinfo.io/{public_ip}/json"
    geo_data = requests.get(geo_url).json()
    
    # Get location and ISP from the response
    location = geo_data.get("city", "Unknown") + ", " + geo_data.get("country", "Unknown")
    isp = geo_data.get("org", "Unknown ISP")
    
    # Get the current date and time for the report
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create the report string with all the gathered info
    report = f"""
    Time: {timestamp}
    IP: {public_ip}
    Location: {location}
    ISP: {isp}
    """
    
    # Send the report data to the admin server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ADMIN_IP, ADMIN_PORT))  # Connect to the admin's server
    client.send(report.encode())  # Send the data

    # Close the connection after sending the data
    client.close()
    print("[+] Data sent to admin server.")
    
except Exception as e:
    print(f"Error: {e}")
