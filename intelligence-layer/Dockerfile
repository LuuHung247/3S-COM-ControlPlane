FROM python:3.12-slim

WORKDIR /app

RUN pip install uv

COPY pyproject.toml .
RUN uv pip install --system --no-cache .

# The embedding model is baked into the image: a recreated container must never
# download it on the first alert (that download sat on the decision path).
ENV FASTEMBED_CACHE_PATH=/opt/fastembed
RUN python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5', cache_dir='/opt/fastembed')"
ENV HF_HUB_OFFLINE=1

COPY src/ ./src/
COPY knowledge/ ./knowledge/
COPY knowledge_v2/ ./knowledge_v2/
COPY compiled/ ./compiled/

EXPOSE 8767
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8767"]
