FROM python:3.9-alpine
WORKDIR /app
COPY requirements.txt .
RUN apk add --no-cache --virtual .build-deps \
    build-base \
    python3-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del --no-cache .build-deps
COPY arp_responder.py .
RUN apk add --no-cache tcpdump
CMD ["python", "arp_responder.py"]