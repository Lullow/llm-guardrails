FROM python:3.12-slim

WORKDIR /app

# CPU-versionen av torch räcker för en deberta-base-modell och är mycket mindre.
RUN pip install --no-cache-dir torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Ladda ner modellen vid bygget så att containern startar utan nätverk.
# Modellen låses till en exakt commit på Hugging Face, av samma skäl som LiteLLM-imagen.
ARG DETECTOR_MODEL=protectai/deberta-v3-base-prompt-injection-v2
ARG DETECTOR_MODEL_REVISION=90c9989b1a342275dd0d1a95aad283c04e075671
ENV DETECTOR_MODEL=${DETECTOR_MODEL} DETECTOR_MODEL_REVISION=${DETECTOR_MODEL_REVISION}
RUN python -c "import os; from transformers import pipeline; pipeline('text-classification', model=os.environ['DETECTOR_MODEL'], revision=os.environ['DETECTOR_MODEL_REVISION'])"

COPY app.py .
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
