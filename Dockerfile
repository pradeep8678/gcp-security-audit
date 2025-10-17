# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Cloud Run port
EXPOSE 8080

# Use gunicorn to serve the Flask app
CMD ["gunicorn", "-b", "0.0.0.0:8080", "main:app"]
