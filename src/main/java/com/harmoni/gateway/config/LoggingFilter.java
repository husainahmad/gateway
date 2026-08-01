package com.harmoni.gateway.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

@Component
public class LoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(LoggingFilter.class);

    private static final int MAX_CACHE_BYTES = 64 * 1024;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Pattern SENSITIVE_JSON_FIELD_PATTERN = Pattern.compile(
            "(\"([A-Za-z0-9_\\-]*(?:token|password|passwd|secret|apikey|api_key|pin|otp|authorization)"
                    + "[A-Za-z0-9_\\-]*)\"\\s*:\\s*)(.*?)(,|}|$)",
            Pattern.CASE_INSENSITIVE);

    private final int maxLogChars;

    public LoggingFilter(@Value("${harmoni.gateway.logging.max-body-chars:4096}") int maxLogChars) {
        this.maxLogChars = maxLogChars;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        long start = System.currentTimeMillis();
        String uri = requestUriWithQuery(request);

        CachingRequestWrapper requestWrapper = new CachingRequestWrapper(request, MAX_CACHE_BYTES);
        CachingResponseWrapper responseWrapper = new CachingResponseWrapper(response, MAX_CACHE_BYTES);

        log.info("--> {} {} headers={}", request.getMethod(), uri, headers(request));

        Throwable error = null;
        try {
            filterChain.doFilter(requestWrapper, responseWrapper);
        } catch (ServletException | IOException | RuntimeException ex) {
            error = ex;
            throw ex;
        } finally {
            long duration = System.currentTimeMillis() - start;
            String requestBody = bodySummary(requestWrapper.getContentAsByteArray(), requestWrapper.getContentType());
            String responseBody = bodySummary(responseWrapper.getContentAsByteArray(), responseWrapper.getContentType());

            log.info("    {} {} request-body={}", request.getMethod(), uri, requestBody);
            log.info("<-- {} {} status={} headers={} response-body={} ({}ms)",
                    request.getMethod(), uri, responseWrapper.getStatus(),
                    headers(response), responseBody, duration);

            if (error != null) {
                log.error("<-- {} {} failed: {}", request.getMethod(), uri, error.toString());
            }
        }
    }

    private static String requestUriWithQuery(HttpServletRequest request) {
        String query = request.getQueryString();
        return query != null ? request.getRequestURI() + "?" + query : request.getRequestURI();
    }

    private static String headers(HttpServletRequest request) {
        Map<String, String> map = new LinkedHashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            map.put(name, sensitive(name) ? "[MASKED]" : join(request.getHeaders(name)));
        }
        return map.toString();
    }

    private static String headers(HttpServletResponse response) {
        Map<String, String> map = new LinkedHashMap<>();
        for (String name : response.getHeaderNames()) {
            map.put(name, sensitive(name) ? "[MASKED]" : join(response.getHeaders(name)));
        }
        return map.toString();
    }

    private static boolean sensitive(String headerName) {
        String name = headerName.toLowerCase(Locale.ROOT);
        return name.equals("authorization") || name.equals("cookie") || name.equals("set-cookie");
    }

    private static String join(Iterable<String> values) {
        StringBuilder sb = new StringBuilder();
        for (String value : values) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(value);
        }
        return sb.toString();
    }

    private static String join(Enumeration<String> values) {
        StringBuilder sb = new StringBuilder();
        while (values.hasMoreElements()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(values.nextElement());
        }
        return sb.toString();
    }

    private String bodySummary(byte[] content, String contentType) {
        if (content == null || content.length == 0) {
            return "";
        }
        if (!isLoggableContentType(contentType)) {
            return "[binary: " + content.length + " bytes]";
        }
        String body = new String(content, StandardCharsets.UTF_8);
        if (isJson(contentType)) {
            body = maskSensitiveJsonFields(body);
        }
        if (body.length() > maxLogChars) {
            body = body.substring(0, maxLogChars) + "... [truncated " + body.length() + " chars]";
        }
        return body;
    }

    private static boolean isLoggableContentType(String contentType) {
        if (contentType == null) {
            return true;
        }
        String type = contentType.toLowerCase(Locale.ROOT);
        return type.contains("json") || type.contains("text")
                || type.contains("xml") || type.contains("x-www-form-urlencoded");
    }

    private static boolean isJson(String contentType) {
        if (contentType == null) {
            return false;
        }
        return contentType.toLowerCase(Locale.ROOT).contains("json");
    }

    static String maskSensitiveJsonFields(String json) {
        try {
            return MAPPER.writeValueAsString(maskJsonNode(MAPPER.readTree(json)));
        } catch (Exception e) {
            return SENSITIVE_JSON_FIELD_PATTERN.matcher(json)
                    .replaceAll(m -> m.group(1) + "\"[MASKED]\"" + m.group(4));
        }
    }

    private static JsonNode maskJsonNode(JsonNode node) {
        if (node.isObject()) {
            ObjectNode masked = MAPPER.createObjectNode();
            node.fields().forEachRemaining(entry -> {
                String name = entry.getKey();
                if (isSensitiveField(name)) {
                    masked.put(name, "[MASKED]");
                } else {
                    masked.set(name, maskJsonNode(entry.getValue()));
                }
            });
            return masked;
        }
        if (node.isArray()) {
            ArrayNode masked = MAPPER.createArrayNode();
            node.forEach(child -> masked.add(maskJsonNode(child)));
            return masked;
        }
        return node;
    }

    private static boolean isSensitiveField(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        return n.contains("token") || n.contains("password") || n.contains("passwd")
                || n.contains("secret") || n.contains("authorization") || n.contains("apikey")
                || n.contains("api_key") || n.contains("pin") || n.contains("otp");
    }

    private static String charset(HttpServletRequestWrapper request) {
        String encoding = request.getCharacterEncoding();
        return encoding != null ? encoding : StandardCharsets.UTF_8.name();
    }

    private static String charset(HttpServletResponseWrapper response) {
        String encoding = response.getCharacterEncoding();
        return encoding != null ? encoding : StandardCharsets.UTF_8.name();
    }

    private static class CachingRequestWrapper extends HttpServletRequestWrapper {

        private final int maxCacheBytes;
        private final ByteArrayOutputStream cache = new ByteArrayOutputStream();
        private ServletInputStream inputStream;
        private BufferedReader reader;

        CachingRequestWrapper(HttpServletRequest request, int maxCacheBytes) {
            super(request);
            this.maxCacheBytes = maxCacheBytes;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (inputStream == null) {
                inputStream = new ServletInputStream() {
                    private final ServletInputStream delegate = CachingRequestWrapper.super.getInputStream();

                    @Override
                    public int read() throws IOException {
                        int b = delegate.read();
                        if (b != -1) {
                            cacheByte(b);
                        }
                        return b;
                    }

                    @Override
                    public int read(byte[] b, int off, int len) throws IOException {
                        int count = delegate.read(b, off, len);
                        if (count != -1) {
                            cacheBytes(b, off, count);
                        }
                        return count;
                    }

                    @Override
                    public boolean isFinished() {
                        return delegate.isFinished();
                    }

                    @Override
                    public boolean isReady() {
                        return delegate.isReady();
                    }

                    @Override
                    public void setReadListener(ReadListener readListener) {
                        delegate.setReadListener(readListener);
                    }
                };
            }
            return inputStream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            if (reader == null) {
                reader = new BufferedReader(new InputStreamReader(getInputStream(), charset(this)));
            }
            return reader;
        }

        byte[] getContentAsByteArray() {
            return cache.toByteArray();
        }

        private void cacheByte(int b) {
            if (cache.size() < maxCacheBytes) {
                cache.write(b);
            }
        }

        private void cacheBytes(byte[] b, int off, int len) {
            int remaining = maxCacheBytes - cache.size();
            if (remaining > 0) {
                cache.write(b, off, Math.min(remaining, len));
            }
        }
    }

    private static class CachingResponseWrapper extends HttpServletResponseWrapper {

        private final int maxCacheBytes;
        private final ByteArrayOutputStream cache = new ByteArrayOutputStream();
        private ServletOutputStream outputStream;
        private PrintWriter writer;

        CachingResponseWrapper(HttpServletResponse response, int maxCacheBytes) {
            super(response);
            this.maxCacheBytes = maxCacheBytes;
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            if (writer != null) {
                throw new IllegalStateException("getWriter() has already been called on this response");
            }
            if (outputStream == null) {
                outputStream = new ServletOutputStream() {
                    private final ServletOutputStream delegate = CachingResponseWrapper.super.getOutputStream();

                    @Override
                    public void write(int b) throws IOException {
                        delegate.write(b);
                        cacheByte(b);
                    }

                    @Override
                    public void write(byte[] b, int off, int len) throws IOException {
                        delegate.write(b, off, len);
                        cacheBytes(b, off, len);
                    }

                    @Override
                    public void flush() throws IOException {
                        delegate.flush();
                    }

                    @Override
                    public boolean isReady() {
                        return delegate.isReady();
                    }

                    @Override
                    public void setWriteListener(WriteListener writeListener) {
                        delegate.setWriteListener(writeListener);
                    }
                };
            }
            return outputStream;
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            if (outputStream != null) {
                throw new IllegalStateException("getOutputStream() has already been called on this response");
            }
            if (writer == null) {
                writer = new PrintWriter(new OutputStreamWriter(getOutputStream(), charset(this)));
            }
            return writer;
        }

        byte[] getContentAsByteArray() {
            return cache.toByteArray();
        }

        private void cacheByte(int b) {
            if (cache.size() < maxCacheBytes) {
                cache.write(b);
            }
        }

        private void cacheBytes(byte[] b, int off, int len) {
            int remaining = maxCacheBytes - cache.size();
            if (remaining > 0) {
                cache.write(b, off, Math.min(remaining, len));
            }
        }
    }
}
