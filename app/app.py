import os
import requests
import time
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from pathlib import Path
from pydantic import BaseModel
from enum import Enum
from typing import List
import ollama  # Asegúrate de que ollama esté correctamente instalado

# Load environment variables from .env file
load_dotenv()

# Get the API Key from environment variables
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

# Initialize Flask app
app = Flask(__name__)

# API URL to upload files
upload_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
report_url = 'https://www.virustotal.com/vtapi/v2/file/report'

# Definición de modelos Pydantic para el análisis estructurado
class PhishingProbability(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class SuspiciousElement(BaseModel):
    element: str
    reason: str

class SimplePhishingAnalysis(BaseModel):
    is_potential_phishing: bool
    is_malicious: bool
    phishing_probability: PhishingProbability
    suspicious_elements: List[SuspiciousElement]
    recommended_actions: List[str]
    explanation: str

# Endpoint para manejar el análisis de archivos
@app.route('/analyze', methods=['POST'])
def analyze_file():
    # Check if the API Key is loaded
    if not API_KEY:
        return jsonify({"error": "API Key not found"}), 400

    # Check if a file is present in the request
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    # Get the file from the request
    file = request.files['file']

    # Check if the file has a name
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # If file exists, proceed to send it to VirusTotal for analysis
    if file:
        # Save the file temporarily to send it to VirusTotal
        temp_path = Path(f"/tmp/{file.filename}")
        file.save(temp_path)

        # Open the file in binary mode and send it for analysis
        with open(temp_path, 'rb') as f:
            params = {'apikey': API_KEY}
            files = {'file': (file.filename, f)}
            response = requests.post(upload_url, files=files, params=params)

        # Check if the upload was successful
        if response.status_code == 200:
            result = response.json()
            scan_id = result['scan_id']

            # Wait for the file analysis to be processed
            time.sleep(10)

            # Query the report using the scan_id
            report_params = {'apikey': API_KEY, 'resource': scan_id}
            report_response = requests.get(report_url, params=report_params)

            # Check if the report retrieval was successful
            if report_response.status_code == 200:
                report_result = report_response.json()

                # Get the number of antivirus engines that flagged the file as malicious
                positives = report_result.get('positives', 0)
                total = report_result.get('total', 0)

                # Build the result object to be returned as JSON
                file_result = {
                    "file_name": file.filename,
                    "scan_id": scan_id,
                    "positives": positives,
                    "total": total,
                    "is_malicious": positives > 0,
                    "permalink": report_result.get('permalink')
                }

                # Return the result as JSON
                return jsonify(file_result), 200
            else:
                return jsonify({"error": "Error retrieving report from VirusTotal"}), 500
        else:
            return jsonify({"error": "Error uploading file to VirusTotal"}), 500

# Endpoint para formatear texto a HTML
@app.route('/format_text', methods=['POST'])
def format_text():
    try:
        # Extraer el contenido del texto desde el cuerpo de la solicitud POST
        data = request.get_json()  # Asegurarse de que se obtiene un JSON parseado

        # Verificar si 'text' está en el JSON
        text = data.get('text')
        if not text:
            return jsonify({"error": "El texto es requerido."}), 400

        # Verificar si 'from' está en el JSON
        email_from = data.get('from')
        if not email_from:
            return jsonify({"error": "El campo 'from' es requerido."}), 400

        # Construir el mensaje a ser enviado al modelo
        model_messages = [
            {
                "role": "system",
                "content": (
                    "Formatea el texto proporcionado en HTML. "
                    "Asegúrate de que la salida esté bien estructurada, visualmente atractiva, y en español. "
                    "El HTML debe estar organizado según la siguiente estructura:\n"
                    "- is_potential_phishing: booleano\n"
                    "- is_malicious: booleano\n"
                    "- phishing_probability: enum (BAJA, MEDIA, ALTA)\n"
                    "- suspicious_elements: lista de objetos (elemento, motivo)\n"
                    "- recommended_actions: lista de acciones recomendadas\n"
                    "- explanation: explicación"
                )
            },
            {
                "role": "user",
                "content": text  # Aquí se incluye el texto a formatear
            }
        ]

        # Llamada al modelo local de Ollama para formatear el texto
        response = ollama.chat(
            model=os.getenv('OLLAMA_MODEL', 'gemma2:9b-instruct-q4_K_M'),  # Usar la variable de entorno para el modelo
            messages=model_messages
        )

        # Limpiar el texto recibido eliminando '```html\n' al inicio y '```' al final
        formatted_html = response.get('message', {}).get('content', "")
        formatted_html = formatted_html.replace("```html\n", "").replace("```", "").strip()

        # Incluir 'from' en el resultado JSON
        result = {
            "formatted_html": formatted_html,
            "from": email_from  # Agregar 'from' al resultado
        }

        # Retornar el resultado formateado como JSON
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Ruta para analizar el cuerpo del correo
@app.route('/analyze_email', methods=['POST'])
def analyze_email():
    try:
        # Extraer el contenido del correo desde el cuerpo de la solicitud POST
        data = request.get_json()  # Asegurarse de que se obtiene un JSON parseado

        # Verificar si 'email_content' está en el JSON
        email_content = data.get('email_content')
        if not email_content:
            return jsonify({"error": "El contenido del correo es requerido."}), 400

        # Verificar si 'from' está en el JSON
        email_from = data.get('from')
        if not email_from:
            return jsonify({"error": "El campo 'from' es requerido."}), 400

        # Construir el mensaje a ser enviado al modelo
        model_messages = [
            {
                "role": "system",
                "content": "Analyze the provided email content and metadata to determine if it's a potential phishing attempt. Provide your analysis in a structured format matching the SimplePhishingAnalysis model. Important the response in HTML Format",
            },
            {
                "role": "user",
                "content": email_content,  # Aquí se incluye el contenido del correo
            }
        ]

        # Llamada al modelo local de Ollama para analizar el correo
        response = ollama.chat(
            model=os.getenv('OLLAMA_MODEL', 'gemma2:9b-instruct-q4_K_M'),  # Usar la variable de entorno para el modelo
            messages=model_messages
        )

        # Como `ollama.chat` devuelve una cadena, la parseamos para agregar 'from'
        analysis_result = {"result": response, "from": email_from}

        # Retornar el análisis con el campo 'from' incluido
        return jsonify({"analysis_result": analysis_result})

    except Exception as e:
        # En caso de error, retornar el mensaje de error
        return jsonify({"error": str(e)}), 500



# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
