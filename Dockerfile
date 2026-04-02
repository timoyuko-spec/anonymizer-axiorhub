FROM python:3.11-slim

WORKDIR /app

# dépendances
RUN pip install fastapi uvicorn httpx \
    pydantic regex presidio-anonymizer presidio-analyzer

# copier ton tool + proxy
COPY anonymizer_axiorhub.py proxy.py .

CMD ["uvicorn", "proxy:app", "--host", "0.0.0.0", "--port", "8000"]