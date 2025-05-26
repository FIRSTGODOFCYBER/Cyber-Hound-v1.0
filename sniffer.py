from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
import datetime
import sqlite3
import os

# Load trained model and selected features
model = joblib.load("randomforest_model.joblib")
features = joblib.load("selected_features.joblib")

# Connect to SQLite database (create if not exists)
conn = sqlite3.connect("traffic.db")
cursor = conn.cursor()

# Create table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS traffic_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    prediction TEXT,
    flow_packets REAL,
    packet_len INTEGER,
    syn_flag INTEGER,
    ack_flag INTEGER,
    psh_flag INTEGER,
    fin_flag INTEGER
)
""")
conn.commit()

# Function to process each packet
def process_packet(packet):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"

            stats = {
                "Destination Port": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0,
                "Fwd Packet Length Max": len(packet),
                "Fwd Packet Length Min": len(packet),
                "Fwd Packet Length Mean": len(packet),
                "Bwd Packet Length Max": len(packet),
                "Bwd Packet Length Min": len(packet),
                "Flow Packets/s": 1,
                "Fwd PSH Flags": int("P" in packet.sprintf("%TCP.flags%")) if TCP in packet else 0,
                "Fwd Packets/s": 1,
                "Min Packet Length": len(packet),
                "Max Packet Length": len(packet),
                "FIN Flag Count": int("F" in packet.sprintf("%TCP.flags%")) if TCP in packet else 0,
                "SYN Flag Count": int("S" in packet.sprintf("%TCP.flags%")) if TCP in packet else 0,
                "PSH Flag Count": int("P" in packet.sprintf("%TCP.flags%")) if TCP in packet else 0,
                "ACK Flag Count": int("A" in packet.sprintf("%TCP.flags%")) if TCP in packet else 0,
                "URG Flag Count": int("U" in packet.sprintf("%TCP.flags%")) if TCP in packet else 0,
                "Down/Up Ratio": 1.0,
                "Avg Fwd Segment Size": len(packet),
                "Init_Win_bytes_forward": packet[TCP].window if TCP in packet else 0,
                "Init_Win_bytes_backward": 0
            }

            # Align with feature set
            df = pd.DataFrame([stats])[features]

            # Predict
            prediction = model.predict(df)[0]

            # Log result
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO traffic_log (
                    timestamp, src_ip, dst_ip, src_port, dst_port,
                    protocol, prediction, flow_packets, packet_len,
                    syn_flag, ack_flag, psh_flag, fin_flag
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                ip_layer.src,
                ip_layer.dst,
                packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
                stats["Destination Port"],
                proto,
                prediction,
                stats["Flow Packets/s"],
                len(packet),
                stats["SYN Flag Count"],
                stats["ACK Flag Count"],
                stats["PSH Flag Count"],
                stats["FIN Flag Count"]
            ))
            conn.commit()

            print(f"[{timestamp}] 🔍 {ip_layer.src} → {ip_layer.dst} | Protocol: {proto} | Prediction: {prediction}")
    except Exception as e:
        print(f"⚠️ Error: {e}")

# Start live sniffing
print("📡 Sniffing... Press Ctrl+C to stop.\n")
sniff(prn=process_packet, store=0)
