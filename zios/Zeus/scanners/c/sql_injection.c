#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define MAX_PAYLOAD_SIZE 2048
#define MAX_RESPONSE_SIZE 8192

struct Response {
    char *data;
    size_t size;
};

size_t write_callback(void *ptr, size_t size, size_t nmemb, struct Response *response) {
    size_t new_size = response->size + size * nmemb;
    response->data = realloc(response->data, new_size + 1);
    memcpy(response->data + response->size, ptr, size * nmemb);
    response->size = new_size;
    response->data[new_size] = '\0';
    return size * nmemb;
}

int check_sql_injection(const char *url, const char *payload) {
    CURL *curl;
    CURLcode res;
    struct Response response = {0};
    char full_url[MAX_PAYLOAD_SIZE];

    snprintf(full_url, sizeof(full_url), "%s%s", url, payload);
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        res = curl_easy_perform(curl);
        
        if(res == CURLE_OK) {
            if(strstr(response.data, "SQL") || strstr(response.data, "error")) {
                free(response.data);
                curl_easy_cleanup(curl);
                return 1; // Vulnerable
            }
        }
        
        free(response.data);
        curl_easy_cleanup(curl);
    }
    
    return 0; // Not vulnerable
}

int main(int argc, char *argv[]) {
    if(argc != 3) {
        printf("Usage: %s <url> <payload>\n", argv[0]);
        return 1;
    }
    
    const char *url = argv[1];
    const char *payload = argv[2];
    
    int result = check_sql_injection(url, payload);
    printf("{\"vulnerable\": %d}\n", result);
    
    return 0;
} 