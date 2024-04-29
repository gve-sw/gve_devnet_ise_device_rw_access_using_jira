FROM python:3.12-slim

# Install requirements
WORKDIR /app
COPY ./requirements.txt /app
RUN pip install -r requirements.txt

COPY ./src /app/src

# Expose FastAPI port
EXPOSE 8000

# Run the application
CMD ["python", "src/main.py"]