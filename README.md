# mod_otel_http

Apache HTTPD module for emitting OpenTelemetry logs and traces to an OTLP collector.

## Overview

`mod_otel_http` is a high-performance Apache module that instruments HTTP requests with OpenTelemetry observability. It generates structured logs and distributed traces conforming to the OTLP (OpenTelemetry Protocol) specification, enabling deep visibility into Apache traffic patterns, performance metrics, and request flows.

### Key Features

- **Dual Signal Support**: Emit both logs (`/v1/logs`) and traces (`/v1/traces`) to OTLP collectors
- **Distributed Tracing**: Automatic `traceparent` header propagation and trace context management
- **Flexible URL Filtering**: Include or exclude requests based on regex patterns
- **Header Control**: Fine-grained filtering of request/response headers in telemetry
- **Service Metadata**: Configurable service name, version, and environment tags
- **Status Code Classification**: Customizable error semantics for 4xx/5xx responses
- **Zero-Copy Performance**: Minimal overhead with efficient JSON serialization
- **AppDynamics Compatible**: Severity mapping aligned with enterprise APM systems

## Requirements

- Apache HTTPD 2.4+
- `apxs` (Apache Extension Tool)
- libcurl development headers
- APR (Apache Portable Runtime)

### Installing Dependencies

**RHEL/CentOS/Rocky Linux:**
```bash
sudo yum install httpd-devel curl-devel
```

**Debian/Ubuntu:**
```bash
sudo apt-get install apache2-dev libcurl4-openssl-dev
```

## Building and Installation

### 1. Build the Module

```bash
make
```

Override `apxs` location if needed:
```bash
make APXS=/usr/bin/apxs2
```

For custom curl installations:
```bash
make CURL_LIBS="-L/opt/curl/lib -lcurl"
```

### 2. Install the Module

```bash
sudo make install
```

This automatically:
- Copies `mod_otel_http.so` to Apache's modules directory
- Adds `LoadModule otel_http_module modules/mod_otel_http.so` to `httpd.conf`

### 3. Configure the Module

Add configuration to your Apache config file (e.g., `/etc/httpd/conf.d/otel.conf`):

```apache
LoadModule otel_http_module modules/mod_otel_http.so

# Enable logs
OtelEnabled On
OtelCollectorEndpoint "http://localhost:4318/v1/logs"

# Enable traces
OtelTracesEnabled On
OtelTracesEndpoint "http://localhost:4318/v1/traces"

# Service metadata
OtelServiceName    "apache-front"
OtelServiceVersion "2.4.58"
OtelEnvironment    "production"

# URL filtering: only instrument specific paths
OtelURLFilterMode include
OtelURLFilterPattern ^/webconsole/
OtelURLFilterPattern ^/selfservice/
OtelURLFilterPattern ^/idp/

# Header filtering: exclude sensitive headers
OtelHeaderExclude "Authorization, Cookie, Set-Cookie"

# Error classification
OtelError4xxIsError On
OtelError5xxIsError On
```

### 4. Restart Apache

```bash
sudo systemctl restart httpd
# or
sudo apachectl -k graceful
```

## Configuration Directives

### Core Settings

| Directive | Type | Default | Description |
|-----------|------|---------|-------------|
| `OtelEnabled` | On/Off | Off | Enable OpenTelemetry logs (`/v1/logs`) |
| `OtelCollectorEndpoint` | URL | - | OTLP logs endpoint (e.g., `http://collector:4318/v1/logs`) |
| `OtelTracesEnabled` | On/Off | Off | Enable OpenTelemetry traces (`/v1/traces`) |
| `OtelTracesEndpoint` | URL | - | OTLP traces endpoint (e.g., `http://collector:4318/v1/traces`) |

### Service Metadata

| Directive | Type | Default | Description |
|-----------|------|---------|-------------|
| `OtelServiceName` | String | "apache-httpd" | Service name for resource attributes |
| `OtelServiceVersion` | String | - | Service version tag |
| `OtelEnvironment` | String | - | Deployment environment (e.g., `production`, `staging`) |

### URL Filtering

| Directive | Type | Default | Description |
|-----------|------|---------|-------------|
| `OtelURLFilterMode` | off/include/exclude | off | URL filtering strategy |
| `OtelURLFilterPattern` | Regex | - | Regex pattern for URL matching (repeatable) |

**Filter Modes:**
- `off`: No filtering, instrument all requests
- `include`: Only instrument URLs matching patterns (whitelist)
- `exclude`: Instrument all URLs except those matching patterns (blacklist)

**Example: Include Mode**
```apache
OtelURLFilterMode include
OtelURLFilterPattern ^/api/
OtelURLFilterPattern ^/app/
# Only /api/* and /app/* will be instrumented
```

**Example: Exclude Mode**
```apache
OtelURLFilterMode exclude
OtelURLFilterPattern ^/health$
OtelURLFilterPattern ^/metrics$
# All requests except /health and /metrics will be instrumented
```

### Header Filtering

| Directive | Type | Default | Description |
|-----------|------|---------|-------------|
| `OtelHeaderInclude` | String | - | Comma-separated whitelist of headers (case-insensitive) |
| `OtelHeaderExclude` | String | - | Comma-separated blacklist of headers (case-insensitive) |

**Filtering Logic:**
1. If `OtelHeaderInclude` is set, only those headers are sent
2. `OtelHeaderExclude` always takes precedence (overrides include)

**Example:**
```apache
# Only send these headers
OtelHeaderInclude "User-Agent, Content-Type, Accept"

# Never send these (even if in include list)
OtelHeaderExclude "Authorization, Cookie, Set-Cookie, X-Api-Key"
```

### Error Classification

| Directive | Type | Default | Description |
|-----------|------|---------|-------------|
| `OtelError4xxIsError` | On/Off | Off | Treat 4xx responses as ERROR spans |
| `OtelError5xxIsError` | On/Off | On | Treat 5xx responses as ERROR spans |

**Span Status Mapping:**
- `OK` (code=1): 2xx/3xx responses, or 4xx/5xx when not configured as errors
- `ERROR` (code=2): 4xx/5xx responses when flagged as errors

## Telemetry Schema

### Log Records (OTLP LogsRequest)

Each HTTP request generates a structured log with:

**Standard Attributes:**
- `http.method`: HTTP method (GET, POST, etc.)
- `url.scheme`: URL scheme (http, https)
- `url.host`: Host header value
- `url.path`: Request URI
- `url.query`: Query string
- `http.status_code`: HTTP response status
- `client.address`: Client IP address
- `http.response.duration_ms`: Request duration in milliseconds
- `trace_id`: W3C trace ID (32 hex chars)
- `span_id`: W3C span ID (16 hex chars)

**Header Attributes:**
- `http.request.header.<Name>`: Request headers (filtered)
- `http.response.header.<Name>`: Response headers (filtered)

**Severity Mapping:**
- 2xx/3xx → `INFO` (severity=9)
- 4xx → `WARN` (severity=13)
- 5xx → `ERROR` (severity=17)

### Trace Spans (OTLP TracesRequest)

Each HTTP request generates a SERVER span with:

**Standard Attributes:**
- `http.method`: HTTP method
- `url.scheme`, `url.host`, `url.path`, `url.query`: URL components
- `http.status_code`: Response status
- `net.peer.ip`: Client IP
- `server.address`: Server hostname
- `server.port`: Server port
- `user_agent.original`: User-Agent header
- `trace_id`, `span_id`: Trace context

**Span Metadata:**
- `name`: `"<METHOD> <URI>"` (e.g., `"GET /api/users"`)
- `kind`: 2 (SERVER)
- `startTimeUnixNano`: Request start time
- `endTimeUnixNano`: Request end time
- `status.code`: 1 (OK) or 2 (ERROR) based on error classification

## Trace Context Propagation

`mod_otel_http` implements W3C Trace Context propagation:

1. **Incoming `traceparent` Header**: If present and valid, extracts trace ID and span ID
2. **Generate New Context**: If missing or invalid, generates new trace ID (16 bytes) and span ID (8 bytes)
3. **Propagate Downstream**: Adds `traceparent` to both request and response headers

**Format:**
```
traceparent: 00-<trace-id>-<span-id>-01
```

Example:
```
traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
```

This enables distributed tracing across multiple services.

## Example Configurations

### Minimal Configuration

```apache
LoadModule otel_http_module modules/mod_otel_http.so

OtelEnabled On
OtelCollectorEndpoint "http://localhost:4318/v1/logs"
```

### Production Configuration

```apache
LoadModule otel_http_module modules/mod_otel_http.so

# Logs
OtelEnabled On
OtelCollectorEndpoint "http://otel-collector.monitoring.svc:4318/v1/logs"

# Traces
OtelTracesEnabled On
OtelTracesEndpoint "http://otel-collector.monitoring.svc:4318/v1/traces"

# Service identification
OtelServiceName    "apache-gateway"
OtelServiceVersion "2.4.58"
OtelEnvironment    "production"

# Only instrument application endpoints
OtelURLFilterMode include
OtelURLFilterPattern ^/api/v1/
OtelURLFilterPattern ^/api/v2/
OtelURLFilterPattern ^/webhook/

# Exclude sensitive headers
OtelHeaderExclude "Authorization, Cookie, Set-Cookie, X-Api-Key, X-Auth-Token"

# Classify all errors as ERROR spans
OtelError4xxIsError On
OtelError5xxIsError On
```

### Development Configuration

```apache
LoadModule otel_http_module modules/mod_otel_http.so

OtelEnabled On
OtelCollectorEndpoint "http://localhost:4318/v1/logs"

OtelTracesEnabled On
OtelTracesEndpoint "http://localhost:4318/v1/traces"

OtelServiceName    "apache-dev"
OtelEnvironment    "dev"

# Exclude health checks
OtelURLFilterMode exclude
OtelURLFilterPattern ^/health$
OtelURLFilterPattern ^/_status$

# Keep all headers in dev
# (no header filtering)

# Only 5xx are errors
OtelError4xxIsError Off
OtelError5xxIsError On
```

## Testing and Verification

### 1. Test with Local OTEL Collector

Run OpenTelemetry Collector locally:

```bash
docker run -d \
  -p 4318:4318 \
  -v $(pwd)/otel-config.yaml:/etc/otel/config.yaml \
  otel/opentelemetry-collector:latest \
  --config=/etc/otel/config.yaml
```

**otel-config.yaml:**
```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:

exporters:
  debug:
    verbosity: detailed

service:
  telemetry:
    logs:
      level: debug

  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]

    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]

```

### 2. Generate Test Requests

```bash
curl -v http://localhost/api/test
curl -v http://localhost/webconsole/dashboard
curl -v -H "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" \
  http://localhost/api/users
```

### 3. Verify in Collector Logs

```bash
docker logs -f <collector-container-id>
```

Look for:
- `resourceLogs` with your service name
- `resourceSpans` with span data
- `traceId` and `spanId` matching `traceparent` headers

### 4. Enable Apache Debug Logging

```apache
LogLevel otel_http:debug
```

This logs the raw JSON payloads sent to the collector:
```
[otel_http:debug] mod_otel_http: Log JSON: {"resourceLogs":[...]}
[otel_http:debug] mod_otel_http: Trace JSON: {"resourceSpans":[...]}
```

## Performance Considerations

- **Minimal Overhead**: Asynchronous telemetry with 200ms timeout
- **Header Filtering**: Reduces payload size and processing time
- **URL Filtering**: Avoids instrumenting high-volume health check endpoints
- **JSON Serialization**: Zero-copy string operations using APR memory pools

**Recommendations:**
- Use `OtelURLFilterMode exclude` to skip `/health`, `/metrics`, `/status` endpoints
- Set `OtelHeaderExclude` for high-cardinality or sensitive headers
- Point to a local collector (same host/network) to minimize latency

## Troubleshooting

### Module Not Loading

**Symptom:** Apache fails to start with "Cannot load modules/mod_otel_http.so"

**Solution:**
```bash
# Check module exists
ls -l /usr/lib64/httpd/modules/mod_otel_http.so

# Verify dependencies
ldd /usr/lib64/httpd/modules/mod_otel_http.so

# Check SELinux (RHEL/CentOS)
sudo setenforce 0
sudo systemctl restart httpd
```

### No Telemetry Being Sent

**Check Configuration:**
```bash
# Verify OtelEnabled is On
apachectl -M | grep otel

# Test collector endpoint
curl -v http://localhost:4318/v1/logs

# Check Apache error log
tail -f /var/log/httpd/error_log
```

**Enable Debug Logging:**
```apache
LogLevel otel_http:debug
```

### Collector Connection Refused

**Symptom:** `curl_easy_perform failed: Couldn't connect to server`

**Solution:**
- Verify collector is running: `netstat -tlnp | grep 4318`
- Check firewall rules
- Ensure `OtelCollectorEndpoint` URL is correct
- Test with `curl -v http://collector:4318/v1/logs`

### Trace Context Not Propagating

**Check:**
1. Ensure `OtelTracesEnabled On`
2. Verify `traceparent` header in response: `curl -v http://localhost/api`
3. Look for `traceparent` in upstream service logs

### High Memory Usage

**Solution:**
- Enable URL filtering to reduce instrumentation scope
- Increase `OtelHeaderExclude` list to reduce payload size
- Adjust collector's `batch` processor settings

## Integration with Observability Platforms

### Grafana + Tempo + Loki

```yaml
# OTEL Collector config
exporters:
  loki:
    endpoint: http://loki:3100/loki/api/v1/push
  otlp/tempo:
    endpoint: http://tempo:4317

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [loki]
    traces:
      receivers: [otlp]
      exporters: [otlp/tempo]
```

### AppDynamics

The module uses AppDynamics-compatible severity levels:
- `INFO` (9) for successful requests
- `WARN` (13) for client errors (4xx)
- `ERROR` (17) for server errors (5xx)

### Datadog

```yaml
exporters:
  datadog:
    api:
      site: datadoghq.com
      key: ${DD_API_KEY}

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [datadog]
    traces:
      receivers: [otlp]
      exporters: [datadog]
```

## Building from Source

### Clean Build

```bash
make clean
make
```

### Custom Compiler Flags

Edit `Makefile` to add optimization or debug flags:

```makefile
$(MODULE_NAME).so: $(SRC)
	$(APXS) -c \
	    -Wc,"-Wall -Wextra -O3 -march=native" \
	    -Wl,"$(CURL_LIBS)" \
	    $(SRC)
```

### Static Linking (Optional)

To statically link libcurl:

```makefile
CURL_LIBS = /usr/lib64/libcurl.a -lz -lssl -lcrypto -lpthread
```

## Uninstalling

```bash
# Remove module
sudo rm /usr/lib64/httpd/modules/mod_otel_http.so

# Remove LoadModule line from httpd.conf
sudo sed -i '/otel_http_module/d' /etc/httpd/conf/httpd.conf

# Restart Apache
sudo systemctl restart httpd
```

## License

```
Copyright 2025 Suneth Kariyawasam

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the project repository.

## Support

For issues, questions, or feature requests, please open an issue on GitHub or contact the maintainer.

---

**Version:** 1.0.0  
**Author:** Suneth Kariyawasam  
**Last Updated:** 2025
