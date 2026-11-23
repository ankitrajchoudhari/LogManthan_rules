FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin lab
COPY common/labnet.py common/dnp3.py dnp3-master/master.py /app/
USER 10001
CMD ["python", "/app/master.py"]
