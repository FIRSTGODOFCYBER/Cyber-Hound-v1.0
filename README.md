# 🐾 CyberHound – AI-Powered Intrusion Detection System

**CyberHound** is a real-time Intrusion Detection System (IDS) built with machine learning. It captures and analyzes live network traffic to detect suspicious activity such as **DoS attacks**, **Brute Force**, and **Port Scans**, then displays the results in a live web dashboard with PDF reporting.

---

## 🚀 Features

- 🧠 Trained ML model using CIC-IDS2017 dataset
- 🌐 Real-time packet sniffing with Scapy
- 📊 Live traffic visualization with Flask dashboard
- 📥 PDF export of recent threats
- 🔍 Filter results by time range and IP address
- 📦 Lightweight and easy to deploy

---

## 📁 Project Structure
CyberHound/
│
├── dashboard/ # Flask web dashboard
│ ├── app.py # Main Flask app
│ ├── static/style.css # Stylesheet
│ └── templates/dashboard.html
│
├── sniffer.py # Live traffic sniffer with model inference
├── traffic.db # SQLite database storing traffic logs
├── randomforest_model.joblib # Trained ML model
├── selected_features.joblib # Top prediction features used while sniffing the network to determinate
└── README.md # You’re here




## 🛠️ Installation

1. **Clone the repository**
  
   git clone https://github.com/FIRSTGODOFCYBER/Cyber-Hound-v1.0.git
   cd CyberHound

2. **Set up a virtual environment**
      python3 -m venv venv
      source venv/bin/activate

3. **Install dependencies**
     pip install -r requirements.txt

4. **Run the sniffer and dashboard on seperate terminals for easy analysis of output**
      python sniffer.py      # Start traffic monitoring
   
  cd dashboard
    python app.py          # Start the dashboard

## 💻 Usage
Dashboard URL: http://localhost:5000

Filters: Use the dashboard to filter by time range or IP address.

Export: Click the Download PDF button to export results with timestamps and a custom header.    

## 🧠 Model Info
Dataset: CIC-IDS2017

Algorithms used: RandomForestClassifier

Accuracy: ~99% on test data

Supports: BENIGN, DoS, BruteForce, PortScan (expandable)   

## Built with Python 🐍


