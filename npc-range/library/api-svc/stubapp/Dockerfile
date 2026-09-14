FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3 psycopg[binary]==3.2.1
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 80
CMD ["python", "app.py"]
