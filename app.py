# app.py
from flask import Flask, request, jsonify, send_from_directory
import requests
import hashlib
import os
from dotenv import load_dotenv

load_dotenv()  # Charge la clé API depuis .env

app = Flask(__name__)
API_KEY = os.getenv('VT_API_KEY')

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/scan/file', methods=['POST'])
def scan_file():
    try:
        file = request.files['file']
        file_content = file.read()
        
        # Génération du hash SHA-256
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        # Requête à l'API VirusTotal
        headers = {'x-apikey': API_KEY}
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        response = requests.get(url, headers=headers)
        
        return jsonify(response.json())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scan/url', methods=['POST'])
def scan_url():
    data = request.json
    headers = {'x-apikey': API_KEY}
    
    # Soumission de l'URL
    submit_response = requests.post(
        'https://www.virustotal.com/api/v3/urls',
        headers=headers,
        data={'url': data['url']}
    )
    analysis_id = submit_response.json()['data']['id']
    
    # Récupération des résultats
    analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    return jsonify(requests.get(analysis_url, headers=headers).json())

if __name__ == '__main__':
    app.run(debug=True)