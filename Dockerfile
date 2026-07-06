FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server source code
COPY . .

# Expose the API port
EXPOSE 8085

# Run the FastAPI server using uvicorn
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8085"]
