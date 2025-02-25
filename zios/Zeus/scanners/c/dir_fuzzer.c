#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <time.h>

#define MAX_THREADS 50
#define MAX_URL_LENGTH 2048
#define CHUNK_SIZE 1000

struct Response {
    char *data;
    size_t size;
};

struct ThreadData {
    char **wordlist;
    int start;
    int end;
    const char *base_url;
    struct json_object *results;
    pthread_mutex_t *mutex;
};

size_t write_callback(void *ptr, size_t size, size_t nmemb, struct Response *response) {
    size_t new_size = response->size + size * nmemb;
    response->data = realloc(response->data, new_size + 1);
    memcpy(response->data + response->size, ptr, size * nmemb);
    response->size = new_size;
    response->data[new_size] = '\0';
    return size * nmemb;
}

void check_directory(const char *url, struct json_object *results, pthread_mutex_t *mutex) {
    CURL *curl;
    CURLcode res;
    long http_code;
    struct Response response = {0};
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        
        res = curl_easy_perform(curl);
        if(res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            
            if(http_code == 200 || http_code == 301 || http_code == 302 || http_code == 403) {
                struct json_object *entry = json_object_new_object();
                json_object_object_add(entry, "url", json_object_new_string(url));
                json_object_object_add(entry, "status", json_object_new_int(http_code));
                
                pthread_mutex_lock(mutex);
                json_object_array_add(results, entry);
                pthread_mutex_unlock(mutex);
            }
        }
        
        free(response.data);
        curl_easy_cleanup(curl);
    }
}

void *thread_function(void *arg) {
    struct ThreadData *data = (struct ThreadData *)arg;
    char url[MAX_URL_LENGTH];
    
    for(int i = data->start; i < data->end; i++) {
        snprintf(url, sizeof(url), "%s/%s", data->base_url, data->wordlist[i]);
        check_directory(url, data->results, data->mutex);
    }
    
    return NULL;
}

char **load_wordlist(const char *filename, int *count) {
    FILE *fp;
    char **wordlist = NULL;
    char line[256];
    int capacity = 1000;
    *count = 0;
    
    fp = fopen(filename, "r");
    if(!fp) {
        fprintf(stderr, "Error opening wordlist file\n");
        return NULL;
    }
    
    wordlist = malloc(capacity * sizeof(char *));
    
    while(fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        if(*count >= capacity) {
            capacity *= 2;
            wordlist = realloc(wordlist, capacity * sizeof(char *));
        }
        wordlist[*count] = strdup(line);
        (*count)++;
    }
    
    fclose(fp);
    return wordlist;
}

int main(int argc, char *argv[]) {
    if(argc != 3) {
        printf("Usage: %s <url> <wordlist>\n", argv[0]);
        return 1;
    }
    
    int wordlist_count;
    char **wordlist = load_wordlist(argv[2], &wordlist_count);
    if(!wordlist) return 1;
    
    struct json_object *root = json_object_new_object();
    struct json_object *results = json_object_new_array();
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    int num_threads = (wordlist_count < MAX_THREADS) ? wordlist_count : MAX_THREADS;
    pthread_t threads[MAX_THREADS];
    struct ThreadData thread_data[MAX_THREADS];
    
    int chunk_size = wordlist_count / num_threads;
    int remainder = wordlist_count % num_threads;
    int start = 0;
    
    for(int i = 0; i < num_threads; i++) {
        thread_data[i].wordlist = wordlist;
        thread_data[i].start = start;
        thread_data[i].end = start + chunk_size + (i < remainder ? 1 : 0);
        thread_data[i].base_url = argv[1];
        thread_data[i].results = results;
        thread_data[i].mutex = &mutex;
        
        pthread_create(&threads[i], NULL, thread_function, &thread_data[i]);
        start = thread_data[i].end;
    }
    
    for(int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    json_object_object_add(root, "directories", results);
    printf("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    
    json_object_put(root);
    for(int i = 0; i < wordlist_count; i++) {
        free(wordlist[i]);
    }
    free(wordlist);
    
    return 0;
} 