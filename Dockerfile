FROM python:3.13-alpine
RUN addgroup -S publisher && adduser -S -G publisher publisher
WORKDIR /app
COPY --chown=publisher:publisher app.py /app/app.py
RUN mkdir /data && chown publisher:publisher /data
USER publisher
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O- http://127.0.0.1:8080/healthz || exit 1
CMD ["python", "/app/app.py"]
