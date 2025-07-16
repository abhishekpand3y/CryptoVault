FROM python:3.11-slim

# Create non-root user
RUN useradd -m cryptovault

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R cryptovault:cryptovault /app
USER cryptovault

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:create_app()", "--certfile=certs/server.crt", "--keyfile=certs/server.key"]
