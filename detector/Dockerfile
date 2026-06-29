FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY train.py .

# model.joblib is expected at /app/model.joblib via a volume mount or COPY.
# Run train.py locally first: python detector/train.py --output detector/model.joblib

CMD ["python", "main.py"]
