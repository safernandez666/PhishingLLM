# Usar una imagen base de Python
FROM python:3.9-slim

# Establecer el directorio de trabajo en el contenedor
WORKDIR /

# Copiar el archivo de requisitos (requirements.txt) en el contenedor
COPY requirements.txt .

# Instalar las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto de los archivos de la aplicación al contenedor
COPY . .

# Exponer el puerto en el que corre la aplicación Flask
EXPOSE 5000

# Comando por defecto para ejecutar la aplicación
CMD ["python", "app.py"]
