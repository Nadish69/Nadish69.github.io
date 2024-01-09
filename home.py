import mysql.connector
from scapy.all import sniff, IP

# MySQL Connection
conn = mysql.connector.connect(
    host="your_mysql_host",
    user="your_mysql_user",
    password="your_mysql_password",
    database="your_database_name"
)

# Packet processing function
def process_packet(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet.sprintf('%IP.proto%')
        payload = str(packet.payload)

        # Insert data into MySQL
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO network_packets (source_ip, destination_ip, protocol, payload)
            VALUES (%s, %s, %s, %s)
        ''', (source_ip, destination_ip, protocol, payload))
        conn.commit()

# Sniff network traffic
sniff(prn=process_packet, store=0)
