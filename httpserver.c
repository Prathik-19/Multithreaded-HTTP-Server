#include "asgn2_helper_funcs.h"
#include "debug.h"
#include "queue.h"
#include "rwlock.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <linux/limits.h>
#include <string.h>
#include <fcntl.h>
#include <regex.h>
#include <errno.h>
#include <sys/socket.h>
#include <pthread.h>

#define MAX_HEADER_LENGTH 2048
#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof((arr)[0]))

static const char *const re = "^([A-Z]{1,8}) +/([a-zA-Z0-9._]{1,63}) "
                              "+(HTTP/([0-9])\\.([0-9]))\r\n((([a-zA-Z0-9.-]{1,128}): "
                              "+(.{0,128})\r\n)*)\r\n(.*)";

static const char *const contentre = "(([a-zA-Z0-9.-]{1,128}): ([a-zA-Z0-9]{0,128})\r\n)";

typedef struct hash_entry {
    char *key; // URI name
    rwlock_t *rwlock; // Pointer to a rwlock
    struct hash_entry *next; // Pointer to the next entry in case of collision
} hash_entry_t;

typedef struct {
    int size; // Size of the hash table
    hash_entry_t **table; // Array of pointers to hash_entry_t (the hash table itself)
} hash_table_t;

queue_t *q = NULL;
pthread_mutex_t mutex;
pthread_mutex_t hashMutex;
pthread_mutex_t termMutex;
char *response;
hash_table_t *hashes = NULL;

int hash_function(const char *key, int size) {
    int hash = 0;
    for (int i = 0; key[i] != '\0'; i++) {
        hash = (hash * 31 + key[i]) % size;
    }
    return hash;
}

hash_table_t *hash_table_create(int size) {
    hash_table_t *ht = (hash_table_t *) malloc(sizeof(hash_table_t));
    if (ht == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    ht->size = size;
    ht->table = (hash_entry_t **) calloc(size, sizeof(hash_entry_t *));
    if (ht->table == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    return ht;
}

void hash_table_insert(hash_table_t *ht, const char *key, rwlock_t *rwlock) {
    int index = hash_function(key, ht->size);
    hash_entry_t *new_entry = (hash_entry_t *) malloc(sizeof(hash_entry_t));
    if (new_entry == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    new_entry->key = strdup(key);
    new_entry->rwlock = rwlock;
    new_entry->next = ht->table[index];
    ht->table[index] = new_entry;
}

void hash_table_remove(hash_table_t *ht, const char *key) {
    int index = hash_function(key, ht->size);
    hash_entry_t *prev = NULL;
    hash_entry_t *entry = ht->table[index];

    while (entry != NULL) {
        if (strcmp(entry->key, key) == 0) {
            if (prev == NULL) {
                ht->table[index] = entry->next;
            } else {
                prev->next = entry->next;
            }
            free(entry->key);
            free(entry);
            return;
        }
        prev = entry;
        entry = entry->next;
    }
}

rwlock_t *hash_table_get(hash_table_t *ht, const char *key) {
    int index = hash_function(key, ht->size);
    hash_entry_t *entry = ht->table[index];
    while (entry != NULL) {
        if (strcmp(entry->key, key) == 0) {
            return entry->rwlock;
        }
        entry = entry->next;
    }
    return NULL;
}

void hash_table_destroy(hash_table_t *ht) {
    for (int i = 0; i < ht->size; i++) {
        hash_entry_t *entry = ht->table[i];
        while (entry != NULL) {
            hash_entry_t *next = entry->next;
            free(entry->key);
            free(entry);
            entry = next;
        }
    }
    free(ht->table);
    free(ht);
}

void get(char *filename, int dst, int requestID) {
    char *response;
    struct stat fileStat;

    pthread_mutex_lock(&hashMutex);
    rwlock_t *lock = hash_table_get(hashes, filename);
    pthread_mutex_unlock(&hashMutex);

    reader_lock(lock);
    if (stat(filename, &fileStat) == -1 && errno == ENOENT) {
        fprintf(stderr, "GET,/%s,404,%d\n", filename, requestID);
        response = "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n";

        pthread_mutex_lock(&mutex);
        write_n_bytes(dst, response, strlen(response));
        pthread_mutex_unlock(&mutex);

        reader_unlock(lock);
        return;
    }

    if (S_ISDIR(fileStat.st_mode)) {
        fprintf(stderr, "GET,/%s,403,%d\n", filename, requestID);
        response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 12\r\n\r\nForbidden\n";

        pthread_mutex_lock(&mutex);
        write_n_bytes(dst, response, strlen(response));
        pthread_mutex_unlock(&mutex);

        reader_unlock(lock);
        return;
    }

    int fd = open(filename, O_RDONLY, 0);
    if (fd == -1 && errno == ENOENT) {
        fprintf(stderr, "GET,/%s,404,%d\n", filename, requestID);
        response = "HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n";
        pthread_mutex_lock(&mutex);
        write_n_bytes(dst, response, strlen(response));
        pthread_mutex_unlock(&mutex);
        reader_unlock(lock);
        return;
    } else if (fd == -1 && (errno == EACCES || errno == EISDIR)) {
        fprintf(stderr, "GET,/%s,403,%d\n", filename, requestID);
        response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 12\r\n\r\nForbidden\n";
        pthread_mutex_lock(&mutex);
        write_n_bytes(dst, response, strlen(response));
        pthread_mutex_unlock(&mutex);
        reader_unlock(lock);
        return;
    } else {
        fprintf(stderr, "GET,/%s,200,%d\n", filename, requestID);

        char *conLen = malloc(10 * sizeof(char));
        sprintf(conLen, "%ld", fileStat.st_size);
        pthread_mutex_lock(&mutex);
        response = "HTTP/1.1 200 OK\r\nContent-Length: ";
        write_n_bytes(dst, response, strlen(response));
        write_n_bytes(dst, conLen, strlen(conLen));
        response = "\r\n\r\n";
        free(conLen);
        int wri = write_n_bytes(dst, response, strlen(response));
        while (wri != 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            wri = pass_n_bytes(fd, dst, PATH_MAX);
        }
        pthread_mutex_unlock(&mutex);
    }
    close(fd);
    reader_unlock(lock);
}

void *worker(void *arg) {
    (void) arg;
    char buffer[PATH_MAX];
    while (1) {
        int fileDesc;
        queue_pop(q, (void **) &fileDesc);

        ssize_t res = read_until(fileDesc, buffer, MAX_HEADER_LENGTH, "\r\n\r\n");
        if (res < 0) {
            response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal "
                       "Server Error\n";
            write_n_bytes(1, response, strlen(response));
        }

        regmatch_t pmatch[50];
        regmatch_t cpMatch[50];
        
        regex_t preg;
        int comp = regcomp(&preg, re, REG_EXTENDED | REG_NEWLINE);
        regex_t contentPreg;
        int contentComp = regcomp(&contentPreg, contentre, REG_EXTENDED | REG_NEWLINE);
        if (contentComp != 0 || comp != 0) {
            response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal "
                       "Server Error\n";
            write_n_bytes(1, response, strlen(response));
        }

        if (res == -1 && errno != ETIME) {
            response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal "
                       "Server Error\n";
            write_n_bytes(fileDesc, response, strlen(response));
            close(fileDesc);
            continue;
        }

        char *s = buffer;
        int length = -1;
        int requestID = 0;
        comp = regexec(&preg, buffer, ARRAY_SIZE(pmatch), pmatch, 0);
        if (comp != 0) {
            response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n";
            write_n_bytes(fileDesc, response, strlen(response));
        } else {
            int header_len = pmatch[6].rm_eo - pmatch[6].rm_so;
            char headers[header_len + 1];
            strncpy(headers, s + pmatch[6].rm_so, header_len);
            headers[header_len] = '\0';
            char *sCon = headers;
            int offset = 0;
            while (regexec(&contentPreg, sCon + offset, ARRAY_SIZE(cpMatch), cpMatch, 0) == 0) {
                int name_len = cpMatch[2].rm_eo - cpMatch[2].rm_so;
                int value_len = cpMatch[3].rm_eo - cpMatch[3].rm_so;

                char header_name[name_len + 1];
                char header_value[value_len + 1];

                strncpy(header_name, sCon + offset + cpMatch[2].rm_so, name_len);
                strncpy(header_value, sCon + offset + cpMatch[3].rm_so, value_len);

                header_name[name_len] = '\0';
                header_value[value_len] = '\0';

                if (strncmp(header_name, "Content-Length", name_len) == 0) {
                    length = atoi(header_value);
                } else if (strncmp(header_name, "Request-Id", name_len) == 0) {
                    requestID = atoi(header_value);
                }

                offset += cpMatch[0].rm_eo;
            }
            regfree(&contentPreg);

            int uri_length = pmatch[2].rm_eo - pmatch[2].rm_so;
            char filename[uri_length + 1];
            strncpy(filename, s + pmatch[2].rm_so, uri_length);
            filename[uri_length] = '\0';

            pthread_mutex_lock(&hashMutex);
            if (hash_table_get(hashes, filename) == NULL) {
                printf("doesnt exist, creating\n");
                rwlock_t *newLock = rwlock_new(N_WAY, 1);
                hash_table_insert(hashes, strndup(filename, strlen(filename)), newLock);
            }
            pthread_mutex_unlock(&hashMutex);

            if (strncmp(s + pmatch[1].rm_so, "GET", 3) == 0) {
                if (strncmp(s + pmatch[3].rm_so, "HTTP/1.1", 8) != 0) {
                    fprintf(stderr, "GET,/%s,505,%d\n", filename, requestID);
                    response = "HTTP/1.1 505 Version Not Supported\r\nContent-Length: "
                               "22\r\n\r\nVersion Not Supported\n";
                    write_n_bytes(fileDesc, response, strlen(response));
                } else {
                    if ((pmatch[10].rm_eo - pmatch[10].rm_so) == 0) {
                        get(filename, fileDesc, requestID);
                    } else {
                        fprintf(stderr, "GET,/%s,400,%d\n", filename, requestID);
                        response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n";
                        write_n_bytes(fileDesc, response, strlen(response));
                    }
                }
            } else if (strncmp(s + pmatch[1].rm_so, "PUT", 3) == 0) {
                if (strncmp(s + pmatch[3].rm_so, "HTTP/1.1", 8) != 0) {
                    fprintf(stderr, "PUT,/%s,505,%d\n", filename, requestID);
                    response = "HTTP/1.1 505 Version Not Supported\r\nContent-Length: "
                               "22\r\n\r\nVersion Not Supported\n";
                    write_n_bytes(fileDesc, response, strlen(response));
                } else {
                    int lenMessage = res - pmatch[10].rm_so;
                    pthread_mutex_lock(&hashMutex);
                    rwlock_t *newLock = hash_table_get(hashes, filename);
                    if (newLock == NULL) {
                        newLock = rwlock_new(N_WAY, 1);
                        hash_table_insert(hashes, strndup(filename, strlen(filename)), newLock);
                    }
                    pthread_mutex_unlock(&hashMutex);
                    if (length == -1) {
                        fprintf(stderr, "PUT,/%s,400,%d\n", filename, requestID);
                        response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\r\nBad Request\n";
                        write_n_bytes(fileDesc, response, strlen(response));
                    } else {
                        char *response;
                        int status_code = 200;
                        pthread_mutex_lock(&hashMutex);
                        rwlock_t *lock = hash_table_get(hashes, filename);
                        pthread_mutex_unlock(&hashMutex);

                        writer_lock(lock);
                        int fd = open(filename, O_WRONLY | O_TRUNC, 0666);
                        if (fd == -1 && errno == ENOENT) {
                            fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
                            status_code = 201;
                            if (fd == -1 && errno == EACCES) {
                                status_code = 403;
                                fprintf(stderr, "PUT,/%s,%d,%d\n", filename, status_code, requestID);
                                response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\n\r\nForbidden\n";
                                write_n_bytes(fileDesc, response, strlen(response));
                                close(fileDesc);
                                writer_unlock(lock);
                                continue;
                            }
                        } else {
                            status_code = 200;
                        }
                        int written = write_n_bytes(fd, s + pmatch[10].rm_so, lenMessage);
                        while (written < length) {
                            written += pass_n_bytes(fileDesc, fd, length - written);
                        }
                        close(fd);
                        if (status_code == 200) {
                            fprintf(stderr, "PUT,/%s,%d,%d\n", filename, status_code, requestID);
                            response = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n";
                            write_n_bytes(fileDesc, response, strlen(response));
                        } else if (status_code == 201) {
                            fprintf(stderr, "PUT,/%s,%d,%d\n", filename, status_code, requestID);
                            response = "HTTP/1.1 201 Created\r\nContent-Length: 8\r\n\r\nCreated\n";
                            write_n_bytes(fileDesc, response, strlen(response));
                        }
                        writer_unlock(lock);
                    }
                }
            } else {
                response = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 16\r\n\r\nNot "
                           "Implemented\n";
                write_n_bytes(fileDesc, response, strlen(response));
            }
        }
        regfree(&preg);
        memset(buffer, 0, sizeof(buffer));
        close(fileDesc);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int ch;
    int port;
    int numThreads = 4;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port> [-t threads]\n", argv[0]);
        exit(1);
    }
    while ((ch = getopt(argc, argv, "t:")) != -1) {
        switch (ch) {
        case 't': numThreads = atoi(optarg); break;
        default: fprintf(stderr, "Usage: %s [-t threads] <port>\n", argv[0]); exit(1);
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Port number is required\n");
        exit(1);
    }
    port = atoi(argv[optind]);
    if (port < 1 || port > 65535) {
        printf("Improper port number\n");
        exit(1);
    }
    q = queue_new(numThreads);
    pthread_t threads[numThreads];
    hashes = hash_table_create(numThreads);
    pthread_mutex_init(&mutex, NULL);
    pthread_mutex_init(&hashMutex, NULL);
    for (int i = 0; i < numThreads; i++) {
        pthread_create(&(threads[i]), NULL, worker, NULL);
    }
    Listener_Socket socket;
    pthread_mutex_lock(&mutex);
    int a = listener_init(&socket, port);
    pthread_mutex_unlock(&mutex);
    if (a == -1) {
        exit(1);
        response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 22\r\n\r\nInternal "
                   "Server Error\n";
        write_n_bytes(1, response, strlen(response));
    }
    while (1) {
        intptr_t fd = listener_accept(&socket);
        queue_push(q, (void *) fd);
    }
    return 0;
}