import streamlit as st
import os
import requests

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
MAX_FILE_SIZE_MB = 5
VIRUSTOTAL_API_KEY = '438bca178b2ff57027a56f98593e2c1802607969dec372ca157d824cbd52d4f1'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def scan_file_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
    }
    with open(file_path, 'rb') as f:
        response = requests.post(url, headers=headers, files={'file': f})
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Streamlit app
st.title("Secure File Upload with VirusTotal")

uploaded_file = st.file_uploader("Choose a file", type=list(ALLOWED_EXTENSIONS))

if uploaded_file:
    file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    if file_size_mb > MAX_FILE_SIZE_MB:
        st.error("File size exceeds the limit.")
        os.remove(file_path)
    elif allowed_file(uploaded_file.name):
        result = scan_file_virustotal(file_path)
        if result and result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) == 0:
            st.success("File is safe!")
        else:
            st.error("Malicious file detected!")
        os.remove(file_path)
    else:
        st.error("Invalid file type.")
