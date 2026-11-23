FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY plc-modbus/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin lab
COPY plc-modbus/plc.py /app/plc.py
USER 10001
CMD ["python", "/app/plc.py"]
