FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples
COPY docs ./docs

ENV PYTHONPATH=/app/src
ENTRYPOINT ["python", "-m", "trustai"]
