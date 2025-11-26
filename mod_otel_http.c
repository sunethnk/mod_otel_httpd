/*
 * ----------------------------------------------------------------------------
 *  Copyright 2025 Suneth Kariyawasam
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  File: mod_otel_http.c
 *  Description: Apache HTTPD module for emitting OpenTelemetry telemetry.
 * ----------------------------------------------------------------------------
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "ap_regex.h"
#include "http_core.h"
#include "http_request.h"
#include <inttypes.h>
#include "apr_random.h"

#include <curl/curl.h>

#define URL_FILTER_PATTERN_COUNT 16

module AP_MODULE_DECLARE_DATA otel_http_module;

/* -------------------------------------------------------------------------
 * Config structures
 * ------------------------------------------------------------------------- */

typedef struct {
    int enabled;                    /* 0 = off, 1 = on */
    const char *endpoint;           /* OTEL collector HTTP endpoint */

    int  filter_mode;              /* 0 = off, 1 = include, 2 = exclude */
    apr_array_header_t *patterns;  /* array of ap_regex_t* */

    /* Header filtering (used for both request + response headers) */
    apr_array_header_t *include_headers;  /* array of const char* (lowercased) */
    apr_array_header_t *exclude_headers;  /* array of const char* (lowercased) */
    
    /* NEW: traces */
    int traces_enabled;             /* 0 = off, 1 = on */
    const char *traces_endpoint;    /* OTLP /v1/traces */
    
    /* NEW: service metadata */
    const char *service_name;
    const char *service_version;
    const char *environment;
    
    int error_4xx;  /* 0 = not error, 1 = error */
    int error_5xx;  /* 0 = not error, 1 = error */
    
} otel_srv_conf;

typedef struct {
    const char *trace_id;  /* 32 hex chars */
    const char *span_id;   /* 16 hex chars */
} otel_trace_ctx;


/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

/* Simple JSON string escaper (minimal) */
static char *json_escape(apr_pool_t *p, const char *in)
{
    if (!in) return apr_pstrdup(p, "");

    size_t len = strlen(in);
    /* worst case: every char becomes two chars */
    char *out = apr_palloc(p, len * 2 + 1);
    char *dst = out;

    for (const char *src = in; *src; ++src) {
        unsigned char c = (unsigned char)*src;
        switch (c) {
        case '\"':
        case '\\':
            *dst++ = '\\';
            *dst++ = (char)c;
            break;
        case '\b':
            *dst++ = '\\';
            *dst++ = 'b';
            break;
        case '\f':
            *dst++ = '\\';
            *dst++ = 'f';
            break;
        case '\n':
            *dst++ = '\\';
            *dst++ = 'n';
            break;
        case '\r':
            *dst++ = '\\';
            *dst++ = 'r';
            break;
        case '\t':
            *dst++ = '\\';
            *dst++ = 't';
            break;
        default:
            if (c < 0x20) {
                /* control chars – skip or encode; here we just skip */
            } else {
                *dst++ = (char)c;
            }
        }
    }
    *dst = '\0';
    return out;
}

/* Lowercase copy of header name */
static char *lowercase_header_name(apr_pool_t *p, const char *name)
{
    if (!name) return NULL;
    char *out = apr_pstrdup(p, name);
    for (char *c = out; *c; ++c) {
        *c = (char)apr_tolower(*c);
    }
    return out;
}

/* Parse a comma/space-separated header list into array of lowercased names */
static void parse_header_list(apr_pool_t *p,
                              const char *arg,
                              apr_array_header_t **arr_out)
{
    if (!arg || !*arg) return;

    if (!*arr_out) {
        *arr_out = apr_array_make(p, 4, sizeof(const char *));
    }
    apr_array_header_t *arr = *arr_out;

    const char *s = arg;
    while (*s) {
        /* Skip separators: commas and whitespace */
        while (*s && (apr_isspace(*s) || *s == ',')) s++;
        if (!*s) break;

        const char *start = s;
        while (*s && *s != ',' && !apr_isspace(*s)) s++;
        size_t len = s - start;
        if (len == 0) continue;

        char *name = apr_pstrndup(p, start, len);
        for (char *c = name; *c; ++c) {
            *c = (char)apr_tolower(*c);
        }

        const char **slot = (const char **)apr_array_push(arr);
        *slot = name;
    }
}

/* Check if a (lowercased) name exists in an array of (lowercased) names */
static int header_in_list(const apr_array_header_t *arr,
                          const char *lower_name)
{
    if (!arr || !lower_name) return 0;
    const char * const *elts = (const char * const *)arr->elts;
    for (int i = 0; i < arr->nelts; i++) {
        if (!elts[i]) continue;
        if (strcmp(elts[i], lower_name) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Decide if header should be sent given include/exclude lists */
static int should_send_header(const otel_srv_conf *conf,
                              apr_pool_t *p,
                              const char *name)
{
    if (!name || !*name) return 0;

    char *lower_name = lowercase_header_name(p, name);

    /* If include list is non-empty, only send headers that are included */
    if (conf->include_headers && conf->include_headers->nelts > 0) {
        if (!header_in_list(conf->include_headers, lower_name)) {
            return 0;
        }
    }

    /* Always respect exclude list */
    if (header_in_list(conf->exclude_headers, lower_name)) {
        return 0;
    }

    return 1;
}

static char *gen_hex(apr_pool_t *p, int bytes)
{
    unsigned char buf[32]; /* supports up to 32 bytes */
    apr_generate_random_bytes(buf, bytes);

    char *hex = apr_pcalloc(p, bytes * 2 + 1);
    for (int i = 0; i < bytes; i++) {
        sprintf(hex + (i * 2), "%02x", buf[i]);
    }
    return hex;
}

static void extract_or_create_trace_context(request_rec *r, otel_trace_ctx *ctx)
{
    ctx->trace_id = NULL;
    ctx->span_id  = NULL;

    const char *tp = apr_table_get(r->headers_in, "traceparent");
    if (tp && *tp) {
        char *buf = apr_pstrdup(r->pool, tp);
        char *trace = NULL;
        char *span  = NULL;

        /* First '-' after version */
        trace = strchr(buf, '-');
        if (trace) {
            *trace++ = '\0';  /* terminate version */

            /* Second '-' after trace_id */
            span = strchr(trace, '-');
            if (span) {
                *span++ = '\0';  /* terminate trace_id */
            }
        }

        if (trace && span &&
            strlen(trace) == 32 &&
            strlen(span)  == 16) {
            ctx->trace_id = trace;
            ctx->span_id  = span;
            return;
        }
        /* malformed traceparent – we fall through and generate a new context */
    }

    /* 2) No valid traceparent → create new trace + span */
    ctx->trace_id = gen_hex(r->pool, 16); /* 16 bytes = 32 hex chars */
    ctx->span_id  = gen_hex(r->pool, 8);  /*  8 bytes = 16 hex chars */

    /* 3) Add new traceparent to request + response for propagation */
    char *new_tp = apr_psprintf(
        r->pool,
        "00-%s-%s-01",   /* version=00, flags=01 (sampled) */
        ctx->trace_id,
        ctx->span_id
    );

    apr_table_set(r->headers_in,  "traceparent", new_tp);
    apr_table_set(r->headers_out, "traceparent", new_tp);
}

/* Append a string attribute JSON entry to attrs buffer */
static void append_attr_string(apr_pool_t *p,
                               const char *key,
                               const char *value,
                               char **attrs,
                               int *first)
{
    if (!value) return;

    char *escaped_key   = json_escape(p, key);
    char *escaped_value = json_escape(p, value);

    *attrs = apr_pstrcat(
        p,
        *attrs,
        (*first ? "" : ","),
        "{"
          "\"key\":\"", escaped_key, "\","
          "\"value\":{\"stringValue\":\"", escaped_value, "\"}"
        "}",
        NULL
    );
    *first = 0;
}

/* Append an int attribute JSON entry */
static void append_attr_int(apr_pool_t *p,
                            const char *key,
                            long value,
                            char **attrs,
                            int *first)
{
    char *escaped_key = json_escape(p, key);
    *attrs = apr_pstrcat(
        p,
        *attrs,
        (*first ? "" : ","),
        "{"
          "\"key\":\"", escaped_key, "\","
          "\"value\":{\"intValue\":", apr_psprintf(p, "%ld", value), "}"
        "}",
        NULL
    );
    *first = 0;
}

/* Append header attributes like http.request.header.User-Agent */
static void append_header_attributes(request_rec *r,
                                     const apr_table_t *tbl,
                                     otel_srv_conf *conf,
                                     apr_pool_t *p,
                                     const char *prefix,
                                     char **attrs,
                                     int *first)
{
    const apr_array_header_t *hdrs = apr_table_elts(tbl);
    apr_table_entry_t *elts = (apr_table_entry_t *)hdrs->elts;

    for (int i = 0; i < hdrs->nelts; i++) {
        const char *k = elts[i].key;
        const char *v = elts[i].val;
        if (!k || !v) continue;

        if (!should_send_header(conf, p, k)) {
            continue;
        }

        /* Build attribute key: prefix + header name, e.g. http.request.header.User-Agent */
        char *attr_key = apr_pstrcat(p, prefix, k, NULL);
        append_attr_string(p, attr_key, v, attrs, first);
    }
}

/* Build OTLP LogsRequest JSON payload for this HTTP request */
static char *build_log_json(request_rec *r,
                             otel_srv_conf *conf,
                             otel_trace_ctx *tctx,
                             apr_pool_t *p)
{
    const char *scheme   = ap_http_scheme(r);
    const char *host     = apr_table_get(r->headers_in, "Host");
    const char *client_ip =
        r->useragent_ip ? r->useragent_ip :
        (r->connection && r->connection->client_ip ? r->connection->client_ip : "-");

    const char *args = r->args ? r->args : "";

    apr_time_t now = apr_time_now();               /* microseconds since epoch */
    apr_int64_t nanos = (apr_int64_t)now * 1000;   /* convert to nanoseconds */
    char *time_unix_nano = apr_psprintf(p, "%" APR_INT64_T_FMT, nanos);

    apr_interval_time_t diff = now - r->request_time;
    long duration_ms = (long)(diff / 1000);        /* microseconds -> ms */

    /* Human-readable summary for log body */
    char *summary = apr_psprintf(
        p, "%s %s %d (%ld ms)",
        r->method,
        r->uri,
        r->status,
        duration_ms
    );

    /* -------- AppDynamics-friendly severity mapping --------
     *
     * OTEL numbers (recommended mapping):
     *   DEBUG = 5
     *   INFO  = 9
     *   WARN  = 13
     *   ERROR = 17
     *
     * Policy:
     *   2xx / 3xx  -> INFO
     *   4xx        -> WARN
     *   5xx        -> ERROR
     */
    const char *sev_text = "INFO";
    int sev_num = 9;

    if (r->status >= 500) {
        sev_text = "ERROR";
        sev_num  = 17;
    } else if (r->status >= 400) {
        sev_text = "WARN";
        sev_num  = 13;
    }

    /* Build attributes[] payload as a string */
    char *attrs = apr_pstrdup(p, "");
    int first_attr = 1;

    /* Core HTTP attributes */
    append_attr_string(p, "http.method",          r->method,  &attrs, &first_attr);
    append_attr_string(p, "url.scheme",          scheme,     &attrs, &first_attr);
    append_attr_string(p, "url.host",            host ? host : "", &attrs, &first_attr);
    append_attr_string(p, "url.path",            r->uri,     &attrs, &first_attr);
    append_attr_string(p, "url.query",           args,       &attrs, &first_attr);
    append_attr_int   (p, "http.status_code",    r->status,  &attrs, &first_attr);
    append_attr_string(p, "client.address",      client_ip,  &attrs, &first_attr);
    append_attr_int   (p, "http.response.duration_ms", duration_ms, &attrs, &first_attr);

    /* Trace/span as attributes (nice for queries) */
    if (tctx && tctx->trace_id) {
        append_attr_string(p, "trace_id", tctx->trace_id, &attrs, &first_attr);
    }
    if (tctx && tctx->span_id) {
        append_attr_string(p, "span_id", tctx->span_id, &attrs, &first_attr);
    }

    /* Merge response headers from headers_out and err_headers_out */
    apr_table_t *resp_headers = apr_table_overlay(p, r->headers_out, r->err_headers_out);

    /* Request headers: http.request.header.<Header-Name> */
    append_header_attributes(r, r->headers_in,  conf, p,
                             "http.request.header.",  &attrs, &first_attr);

    /* Response headers: http.response.header.<Header-Name> */
    append_header_attributes(r, resp_headers,   conf, p,
                             "http.response.header.", &attrs, &first_attr);

    /* Fields for LogRecord traceId/spanId (top-level, not just attributes) */
    const char *trace_id_field = (tctx && tctx->trace_id) ? tctx->trace_id : "";
    const char *span_id_field  = (tctx && tctx->span_id)  ? tctx->span_id  : "";

    /* service.name for resource (configurable) */
    const char *service_name = conf->service_name ? conf->service_name : "apache-httpd";

    /* Now wrap everything into OTLP LogsRequest JSON */
    char *json = apr_psprintf(
        p,
        "{"
          "\"resourceLogs\":[{"
            "\"resource\":{"
              "\"attributes\":["
                "{"
                  "\"key\":\"service.name\","
                  "\"value\":{\"stringValue\":\"%s\"}"
                "}"
              "]"
            "},"
            "\"scopeLogs\":[{"
              "\"scope\":{"
                "\"name\":\"mod_otel_http\","
                "\"version\":\"1.0.0\""
              "},"
              "\"logRecords\":[{"
                "\"timeUnixNano\":\"%s\","
                "\"severityNumber\":%d,"
                "\"severityText\":\"%s\","
                "\"traceId\":\"%s\","
                "\"spanId\":\"%s\","
                "\"flags\":1,"
                "\"body\":{\"stringValue\":\"%s\"},"
                "\"attributes\":[%s]"
              "}]"
            "}]"
          "}]"
        "}",
        service_name,
        time_unix_nano,
        sev_num,
        sev_text,
        trace_id_field,
        span_id_field,
        json_escape(p, summary),
        attrs
    );

    return json;
}

static char *build_trace_json(request_rec *r,
                              otel_srv_conf *conf,
                              otel_trace_ctx *tctx,
                              apr_pool_t *p)
{
    const char *scheme   = ap_http_scheme(r);
    const char *host     = apr_table_get(r->headers_in, "Host");
    const char *client_ip =
        r->useragent_ip ? r->useragent_ip :
        (r->connection && r->connection->client_ip ? r->connection->client_ip : "-");
    const char *args = r->args ? r->args : "";

    /* Start / end times: APR times are microseconds since epoch */
    apr_time_t start = r->request_time;
    apr_time_t end   = apr_time_now();

    apr_int64_t start_nanos = (apr_int64_t)start * 1000;
    apr_int64_t end_nanos   = (apr_int64_t)end   * 1000;

    char *start_str = apr_psprintf(p, "%" APR_INT64_T_FMT, start_nanos);
    char *end_str   = apr_psprintf(p, "%" APR_INT64_T_FMT, end_nanos);

    /* Span name */
    char *span_name = apr_psprintf(p, "%s %s", r->method, r->uri);

    const char *trace_id = (tctx && tctx->trace_id) ? tctx->trace_id : "";
    const char *span_id  = (tctx && tctx->span_id)  ? tctx->span_id  : "";

    /* Span status: 0=UNSET, 1=OK, 2=ERROR (per OTLP) */
    int status_code = 0; /* default UNSET */

    if (r->status >= 500 && conf->error_5xx) {
        status_code = 2; /* ERROR */
    } else if (r->status >= 400 && r->status < 500 && conf->error_4xx) {
        status_code = 2; /* ERROR */
    } else {
        status_code = 1; /* OK */
    }


    /* Build span attributes */
    char *attrs = apr_pstrdup(p, "");
    int first_attr = 1;

    /* Core HTTP attributes */
    append_attr_string(p, "http.method",       r->method,        &attrs, &first_attr);
    append_attr_string(p, "url.scheme",       scheme,           &attrs, &first_attr);
    append_attr_string(p, "url.host",         host ? host : "", &attrs, &first_attr);
    append_attr_string(p, "url.path",         r->uri,           &attrs, &first_attr);
    append_attr_string(p, "url.query",        args,             &attrs, &first_attr);
    append_attr_int   (p, "http.status_code", r->status,        &attrs, &first_attr);

    /* Network / server attributes */
    append_attr_string(p, "net.peer.ip",      client_ip,        &attrs, &first_attr);

    const char *server_host =
        (r->server && r->server->server_hostname) ? r->server->server_hostname :
        (host ? host : "");
    append_attr_string(p, "server.address",   server_host,      &attrs, &first_attr);

    int server_port = 0;
    if (r->connection && r->connection->local_addr) {
        server_port = r->connection->local_addr->port;
    } else if (r->server) {
        server_port = r->server->port;
    }
    if (server_port > 0) {
        append_attr_int(p, "server.port", server_port, &attrs, &first_attr);
    }

    /* User-Agent on span (single header, very useful) */
    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    if (ua && *ua) {
        append_attr_string(p, "user_agent.original", ua, &attrs, &first_attr);
    }

    /* Trace/span as attributes too (handy for searching) */
    if (tctx && tctx->trace_id) {
        append_attr_string(p, "trace_id", tctx->trace_id, &attrs, &first_attr);
    }
    if (tctx && tctx->span_id) {
        append_attr_string(p, "span_id", tctx->span_id, &attrs, &first_attr);
    }

    /* Resource attributes from config */
    const char *service_name    = conf->service_name ? conf->service_name : "apache-httpd";
    const char *service_version = conf->service_version;
    const char *environment     = conf->environment;

    char *res_attrs = apr_pstrdup(p, "");
    int first_res = 1;

    /* helper macro for resource attributes */
    #define ADD_RES_STR(key, val)                                   \
        do {                                                         \
            if ((val) && *(val)) {                                   \
                res_attrs = apr_pstrcat(                             \
                    p,                                               \
                    res_attrs,                                       \
                    (first_res ? "" : ","),                          \
                    "{",                                             \
                      "\"key\":\"", json_escape(p, (key)), "\","     \
                      "\"value\":{\"stringValue\":\"",               \
                         json_escape(p, (val)), "\"}",               \
                    "}",                                             \
                    NULL                                             \
                );                                                   \
                first_res = 0;                                       \
            }                                                        \
        } while (0)

    ADD_RES_STR("service.name",    service_name);
    ADD_RES_STR("service.version", service_version);
    ADD_RES_STR("deployment.environment", environment);

    #undef ADD_RES_STR

    if (first_res) {
        /* ensure at least service.name is present */
        res_attrs = apr_psprintf(
            p,
            "{"
              "\"key\":\"service.name\","
              "\"value\":{\"stringValue\":\"%s\"}"
            "}",
            json_escape(p, service_name)
        );
    }

    /* Build OTLP TracesRequest JSON */
    char *json = apr_psprintf(
        p,
        "{"
          "\"resourceSpans\":[{"
            "\"resource\":{"
              "\"attributes\":[%s]"
            "},"
            "\"scopeSpans\":[{"
              "\"scope\":{"
                "\"name\":\"mod_otel_http\","
                "\"version\":\"1.0.0\""
              "},"
              "\"spans\":[{"
                "\"traceId\":\"%s\","
                "\"spanId\":\"%s\","
                "\"name\":\"%s\","
                "\"kind\":2,"  /* SERVER */
                "\"startTimeUnixNano\":\"%s\","
                "\"endTimeUnixNano\":\"%s\","
                "\"status\":{\"code\":%d},"
                "\"attributes\":[%s]"
              "}]"
            "}]"
          "}]"
        "}",
        res_attrs,
        trace_id,
        span_id,
        json_escape(p, span_name),
        start_str,
        end_str,
        status_code,
        attrs
    );

    return json;
}

/* Send JSON to OTEL endpoint with libcurl */
static void send_to_otel(request_rec *r, const char *endpoint, const char *json)
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_otel_http: curl_easy_init failed");
        return;
    }

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 200L);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_otel_http: curl_easy_perform failed: %s",
                      curl_easy_strerror(rc));
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
}

/* Decide if this request should be sent based on regex + mode */
static int should_send_request(otel_srv_conf *conf, request_rec *r)
{
    /* If neither logs nor traces are enabled, skip entirely */
    if (!conf->enabled && !conf->traces_enabled) {
        return 0;
    }

    /* No filtering configured → accept all */
    if (!conf->patterns || conf->filter_mode == 0) {
        return 1;
    }

    int matched = 0;
    ap_regex_t **res = (ap_regex_t **)conf->patterns->elts;

    for (int i = 0; i < conf->patterns->nelts; i++) {
        ap_regex_t *re = res[i];
        if (ap_regexec(re, r->uri, 0, NULL, 0) == 0) {
            matched = 1;
            break;
        }
    }

    if (conf->filter_mode == 1) {      /* include */
        return matched ? 1 : 0;
    } else if (conf->filter_mode == 2) /* exclude */
        return matched ? 0 : 1;

    return 1;
}

 
/* -------------------------------------------------------------------------
 * Config handlers
 * ------------------------------------------------------------------------- */
static void *create_otel_server_config(apr_pool_t *p, server_rec *s)
{
    (void)s;
    otel_srv_conf *conf = apr_pcalloc(p, sizeof(*conf));
    conf->enabled = 0;
    conf->endpoint = NULL;

    /* URL filter defaults */
    conf->filter_mode = 0;      /* off */
    conf->patterns    = NULL;   /* no patterns yet */

    /* header filters */
    conf->include_headers = NULL;
    conf->exclude_headers = NULL;

    /* traces */
    conf->traces_enabled  = 0;
    conf->traces_endpoint = NULL;

    /* service metadata */
    conf->service_name    = "apache-httpd";
    conf->service_version = NULL;
    conf->environment     = NULL;

    /* error classification defaults: only 5xx are errors */
    conf->error_4xx = 0;
    conf->error_5xx = 1;

    return conf;
}

static const char *set_otel_enabled(cmd_parms *cmd, void *mconfig, int flag)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);
    conf->enabled = flag ? 1 : 0;
    return NULL;
}

static const char *set_otel_endpoint(cmd_parms *cmd, void *mconfig, const char *arg)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);
    conf->endpoint = arg;
    return NULL;
}

static const char *set_otel_traces_enabled(cmd_parms *cmd, void *mconfig, int flag)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);
    conf->traces_enabled = flag ? 1 : 0;
    return NULL;
}

static const char *set_otel_traces_endpoint(cmd_parms *cmd, void *mconfig, const char *arg)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);
    conf->traces_endpoint = arg;
    return NULL;
}

static const char *set_otel_url_filter_mode(cmd_parms *cmd, void *mconfig, const char *arg)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);

    if (!arg) {
        return "OtelURLFilterMode requires one of: off, include, exclude";
    }

    if (!strcasecmp(arg, "off")) {
        conf->filter_mode = 0;
    } else if (!strcasecmp(arg, "include")) {
        conf->filter_mode = 1;
    } else if (!strcasecmp(arg, "exclude")) {
        conf->filter_mode = 2;
    } else {
        return "OtelURLFilterMode must be one of: off, include, exclude";
    }

    return NULL;
}

static const char *set_otel_header_include(cmd_parms *cmd, void *mconfig, const char *arg)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);

    parse_header_list(cmd->pool, arg, &conf->include_headers);
    return NULL;
}

static const char *set_otel_header_exclude(cmd_parms *cmd, void *mconfig, const char *arg)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);

    parse_header_list(cmd->pool, arg, &conf->exclude_headers);
    return NULL;
}

static const char *set_otel_service_name(cmd_parms *cmd, void *mconfig, const char *arg)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);
    conf->service_name = arg;
    return NULL;
}

static const char *set_otel_service_version(cmd_parms *cmd, void *mconfig, const char *arg)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);
    conf->service_version = arg;
    return NULL;
}

static const char *set_otel_environment(cmd_parms *cmd, void *mconfig, const char *arg)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);
    conf->environment = arg;
    return NULL;
}

static const char *set_otel_error_4xx(cmd_parms *cmd, void *mconfig, int flag)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);
    conf->error_4xx = flag ? 1 : 0;
    return NULL;
}

static const char *set_otel_error_5xx(cmd_parms *cmd, void *mconfig, int flag)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);
    conf->error_5xx = flag ? 1 : 0;
    return NULL;
}

static const char *set_otel_url_pattern(cmd_parms *cmd, void *mconfig, const char *arg)
{
    (void)mconfig;
    otel_srv_conf *conf = ap_get_module_config(cmd->server->module_config,
                                               &otel_http_module);

    if (!arg || !*arg) {
        return "OtelURLFilterPattern requires a non-empty regex pattern";
    }

    if (!conf->patterns) {
        conf->patterns = apr_array_make(cmd->pool, URL_FILTER_PATTERN_COUNT, sizeof(ap_regex_t *));
    }

    ap_regex_t *re = ap_pregcomp(cmd->pool, arg, AP_REG_EXTENDED | AP_REG_NOSUB);
    if (!re) {
        return "OtelURLFilterPattern: failed to compile regex";
    }

    *(ap_regex_t **)apr_array_push(conf->patterns) = re;
    return NULL;
}


static const command_rec otel_cmds[] = {
    AP_INIT_FLAG("OtelEnabled",
                 set_otel_enabled, NULL, RSRC_CONF,
                 "Enable or disable OpenTelemetry HTTP logging (/v1/logs)"),

    AP_INIT_TAKE1("OtelCollectorEndpoint",
                  set_otel_endpoint, NULL, RSRC_CONF,
                  "OpenTelemetry collector HTTP endpoint URL (/v1/logs"),

    AP_INIT_FLAG("OtelTracesEnabled",
                 set_otel_traces_enabled, NULL, RSRC_CONF,
                 "Enable or disable sending OTLP traces (/v1/traces)"),

    AP_INIT_TAKE1("OtelTracesEndpoint",
                  set_otel_traces_endpoint, NULL, RSRC_CONF,
                  "OpenTelemetry collector traces endpoint URL (/v1/traces)"),

    AP_INIT_TAKE1("OtelURLFilterMode",
                  set_otel_url_filter_mode, NULL, RSRC_CONF,
                  "URL filter mode: 'include' or 'exclude' or 'off'"),
    
    AP_INIT_TAKE1("OtelURLFilterPattern",
                  set_otel_url_pattern, NULL, RSRC_CONF,
                  "URL filter regex pattern (can be specified multiple times)"),

    AP_INIT_TAKE1("OtelHeaderInclude",
                  set_otel_header_include, NULL, RSRC_CONF,
                  "Comma-separated list of header names to include (whitelist)"),

    AP_INIT_TAKE1("OtelHeaderExclude",
                  set_otel_header_exclude, NULL, RSRC_CONF,
                  "Comma-separated list of header names to exclude (blacklist)"),
    
    /* NEW service metadata directives */
    AP_INIT_TAKE1("OtelServiceName",
                  set_otel_service_name, NULL, RSRC_CONF,
                  "Service name for OpenTelemetry resource attributes"),

    AP_INIT_TAKE1("OtelServiceVersion",
                  set_otel_service_version, NULL, RSRC_CONF,
                  "Service version for OpenTelemetry resource attributes"),

    AP_INIT_TAKE1("OtelEnvironment",
                  set_otel_environment, NULL, RSRC_CONF,
                  "Deployment environment (e.g. production, staging)"),
    
    AP_INIT_FLAG("OtelError4xxIsError",
                 set_otel_error_4xx, NULL, RSRC_CONF,
                 "Treat 4xx HTTP responses as ERROR spans (On/Off)"),

    AP_INIT_FLAG("OtelError5xxIsError",
                 set_otel_error_5xx, NULL, RSRC_CONF,
                 "Treat 5xx HTTP responses as ERROR spans (On/Off)"),

    { NULL }
};

/* -------------------------------------------------------------------------
 * Hooks
 * ------------------------------------------------------------------------- */

/* Called once per child process – good place to init curl */
static int otel_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp, server_rec *s)
{
    CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_otel_http: curl_global_init failed: %s",
                     curl_easy_strerror(rc));
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Register cleanup when server shuts down */
    apr_pool_cleanup_register(pconf, NULL,
                              (apr_status_t (*)(void *))curl_global_cleanup,
                              apr_pool_cleanup_null);

    return OK;
}


static void otel_child_init(apr_pool_t *p, server_rec *s)
{
    /* nothing now — unless you want per-child init later */
    (void)p;
    (void)s;
}

static int otel_log_transaction(request_rec *r)
{
    otel_srv_conf *conf = ap_get_module_config(r->server->module_config,
                                               &otel_http_module);

    if (!should_send_request(conf, r)) {
        return DECLINED;
    }

    /* Create or extract trace/span ONCE per request */
    otel_trace_ctx tctx;
    extract_or_create_trace_context(r, &tctx);

    /* Logs */
    if (conf->enabled && conf->endpoint) {
        char *log_json = build_log_json(r, conf, &tctx, r->pool);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "mod_otel_http: Log JSON: %s",
                     log_json);
        send_to_otel(r, conf->endpoint, log_json);
    }

    /* Traces */
    if (conf->traces_enabled && conf->traces_endpoint) {
        char *trace_json = build_trace_json(r, conf, &tctx, r->pool);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                     "mod_otel_http: Trace JSON: %s",
                     trace_json);
        send_to_otel(r, conf->traces_endpoint, trace_json);
    }

    return DECLINED;
}

static void otel_register_hooks(apr_pool_t *p)
{
    (void)p;
    ap_hook_post_config(otel_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(otel_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(otel_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

/* -------------------------------------------------------------------------
 * Module definition
 * ------------------------------------------------------------------------- */

module AP_MODULE_DECLARE_DATA otel_http_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                        /* create per-dir config */
    NULL,                        /* merge per-dir config */
    create_otel_server_config,   /* create per-server config */
    NULL,                        /* merge per-server config */
    otel_cmds,                   /* configuration directives */
    otel_register_hooks          /* register hooks */
};

