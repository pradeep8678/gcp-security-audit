# Use slim Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose port (Cloud Run provides $PORT)
EXPOSE 8080

# Run Flask app using environment PORT
CMD ["python", "main.py"]
