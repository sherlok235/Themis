FROM python:3.12-slim
WORKDIR /app
# Build context is project root, so both files are reachable
COPY consensus.py .
COPY coordinator/coordinator.py .
EXPOSE 8000
CMD ["python3", "coordinator.py"]
