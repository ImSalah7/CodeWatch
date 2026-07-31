FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml ./
COPY src/ src/
COPY run_api.py ./
RUN pip install --no-cache-dir -e .

EXPOSE 8443

CMD ["python", "run_api.py"]
