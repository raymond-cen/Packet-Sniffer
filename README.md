# Packet Sniffing Program
This is a packet sniffing program written in Python for the Something Awesome Project. The program creates a raw socket that constantly listens for any packets that are sent in and out of the computer. It binds all the IP addresses of the computer and runs the program in a thread for every IP address. The program then unpacks all the data through many bit-wise operations and prints it out to the terminal. Additionally, the program makes an API call to Google Drive every 10 packets detected and writes all the data that was printed out to a Google Doc, ensuring everything is recorded.

## Installation
1. Clone the repository using git clone https://github.com/raymond-cen/Packet-Sniffer.git
2. Install the required dependencies using pip install -r requirements.txt
3. Run the program using python sniff_packets.py
# How it works
The program performs the following actions:

1. Creates a raw socket that listens for any packets sent in and out of the computer.
2. Binds all the IP addresses of the computer and runs the program in a thread for every IP address.
3. Unpacks all the data through bit-wise operations and prints it out to the terminal.
4. Makes an API call to Google Drive every 10 packets detected and writes all the data to a Google Doc.
# Challenges faced
The development of the program involved some challenges, mainly due to research. One issue was that the program could not unpack the Ethernet frame on Windows 10, as it does not support this feature. Another challenge was getting the IP address of the computer, as the function to retrieve it only printed out UDP packets and not TCP packets, which were the main focus of the program. To overcome this, the IP address was manually changed to the router's IP address, allowing the program to detect TCP packets. Another challenge was discovering that computers can have multiple network adapters, which can result in multiple IP addresses. This issue was encountered on a laptop but not a desktop PC.
