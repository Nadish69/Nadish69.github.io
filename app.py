# app.py
from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze_network', methods=['GET'])
def analyze_network():
    # Call your modified Scapy code for network analysis
    results = perform_network_analysis()

    # Return the results as JSON
    return jsonify(results)

def perform_network_analysis():
    # Sniff 10 packets and analyze each packet
    packets = sniff(count=10, prn=analyze_packet)

    # Extract relevant information for demonstration
    results = [{'src': pkt[IP].src, 'dst': pkt[IP].dst, 'protocol': pkt[IP].proto} for pkt in packets]

    return results

def analyze_packet(packet):
    # Your custom packet analysis code goes here
    # Modify this function based on your specific analysis requirements
    pass

if __name__ == '__main__':
    app.run(debug=True)
