FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN useradd --system --uid 10001 --no-create-home appuser
COPY risk_calculator.py llm_analyzer.py main.py soc_persona.md ./
USER appuser
CMD ["python", "main.py"]
