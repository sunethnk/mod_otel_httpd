docker run --rm -it \
  -v "$(pwd)/otel-local.yaml:/etc/otelcol/config.yaml" \
  -p 4318:4318 \
  otel/opentelemetry-collector-contrib:latest \
  --config /etc/otelcol/config.yaml