package ghidraassist;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

/**
 * HTTP client for the YAGMCP server REST API.
 * Sends chat messages with Ghidra context and receives LLM responses.
 */
public class GhidraAssistClient {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(120);

    private final HttpClient httpClient;
    private final Gson gson;

    private String serverUrl;
    private String model;
    private String conversationId;

    public GhidraAssistClient(String serverUrl, String model) {
        this.serverUrl = normalizeUrl(serverUrl);
        this.model = model;
        this.conversationId = UUID.randomUUID().toString();
        this.gson = new Gson();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .build();
    }

    /**
     * Sends a chat message with context to the YAGMCP server asynchronously.
     *
     * @param message the user's message text
     * @param context Ghidra context map (function name, address, decompiled code, etc.)
     * @return CompletableFuture resolving to the assistant's reply text
     */
    public CompletableFuture<ChatResponse> sendMessageAsync(String message,
            Map<String, String> context) {
        JsonObject payload = buildPayload(message, context);
        String jsonBody = gson.toJson(payload);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/chat"))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(REQUEST_TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(this::parseResponse);
    }

    /**
     * Sends a chat message synchronously (blocks until response or timeout).
     */
    public ChatResponse sendMessage(String message, Map<String, String> context) {
        try {
            return sendMessageAsync(message, context).join();
        } catch (Exception e) {
            return ChatResponse.error("Request failed: " + extractRootCause(e));
        }
    }

    /**
     * Tests connectivity to the YAGMCP server.
     *
     * @return CompletableFuture resolving to true if the server is reachable
     */
    public CompletableFuture<Boolean> testConnection() {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/health"))
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> response.statusCode() >= 200 && response.statusCode() < 300)
                .exceptionally(e -> false);
    }

    /**
     * Fetches available models from Ollama server.
     *
     * @return CompletableFuture resolving to a list of available model names
     */
    public CompletableFuture<List<String>> fetchAvailableModels() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Try to fetch from Ollama on localhost:11434
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create("http://localhost:11434/api/tags"))
                        .header("Accept", "application/json")
                        .timeout(Duration.ofSeconds(5))
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
                    List<String> models = new ArrayList<>();

                    if (json.has("models")) {
                        JsonArray modelsArray = json.getAsJsonArray("models");
                        for (JsonElement element : modelsArray) {
                            JsonObject modelObj = element.getAsJsonObject();
                            if (modelObj.has("name")) {
                                models.add(modelObj.get("name").getAsString());
                            }
                        }
                    }

                    return models;
                }
            } catch (Exception e) {
                // Silently fail and return empty list
            }
            return new ArrayList<>();
        });
    }

    /**
     * Resets the conversation, generating a new conversation ID.
     */
    public void resetConversation() {
        this.conversationId = UUID.randomUUID().toString();
    }

    // --- Configuration ---

    public void setServerUrl(String url) {
        this.serverUrl = normalizeUrl(url);
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getModel() {
        return model;
    }

    public String getConversationId() {
        return conversationId;
    }

    // --- Internal helpers ---

    private JsonObject buildPayload(String message, Map<String, String> context) {
        JsonObject payload = new JsonObject();
        payload.addProperty("message", message);
        payload.addProperty("conversation_id", conversationId);
        payload.addProperty("model", model);

        if (context != null && !context.isEmpty()) {
            JsonObject ctxObj = new JsonObject();
            for (Map.Entry<String, String> entry : context.entrySet()) {
                if (entry.getValue() != null) {
                    ctxObj.addProperty(entry.getKey(), entry.getValue());
                }
            }
            payload.add("context", ctxObj);
        }

        return payload;
    }

    private ChatResponse parseResponse(HttpResponse<String> response) {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            return ChatResponse.error("Server returned HTTP " + response.statusCode()
                    + ": " + response.body());
        }

        try {
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();

            String reply = "";
            if (json.has("response")) {
                reply = json.get("response").getAsString();
            } else if (json.has("message")) {
                reply = json.get("message").getAsString();
            } else if (json.has("content")) {
                reply = json.get("content").getAsString();
            }

            String responseModel = model;
            if (json.has("model")) {
                responseModel = json.get("model").getAsString();
            }

            return new ChatResponse(reply, responseModel, false, null);
        } catch (Exception e) {
            return ChatResponse.error("Failed to parse server response: " + e.getMessage());
        }
    }

    private static String normalizeUrl(String url) {
        if (url == null || url.isBlank()) {
            return "http://localhost:8889";
        }
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String extractRootCause(Throwable t) {
        Throwable cause = t;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        String msg = cause.getMessage();
        if (msg == null || msg.isBlank()) {
            msg = cause.getClass().getSimpleName();
        }
        return msg;
    }

    // --- Response DTO ---

    /**
     * Immutable response object from the YAGMCP server.
     */
    public static class ChatResponse {
        private final String content;
        private final String model;
        private final boolean error;
        private final String errorMessage;

        public ChatResponse(String content, String model, boolean error, String errorMessage) {
            this.content = content;
            this.model = model;
            this.error = error;
            this.errorMessage = errorMessage;
        }

        public static ChatResponse error(String message) {
            return new ChatResponse(null, null, true, message);
        }

        public String getContent() {
            return content;
        }

        public String getModel() {
            return model;
        }

        public boolean isError() {
            return error;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        /**
         * Returns the displayable text -- content on success, error message on failure.
         */
        public String getText() {
            return error ? errorMessage : content;
        }
    }
}
