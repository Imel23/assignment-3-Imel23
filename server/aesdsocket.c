#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/queue.h>
#include <time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "../aesd-char-driver/aesd_ioctl.h"

#define PORT 9000
#ifndef USE_AESD_CHAR_DEVICE
    #define USE_AESD_CHAR_DEVICE 1
#endif

#if USE_AESD_CHAR_DEVICE
    #define DATAFILE "/dev/aesdchar"
#else
    #define DATAFILE "/var/tmp/aesdsocketdata"
#endif

volatile sig_atomic_t stop = 0;

void signal_handler(int signo)
{
    syslog(LOG_INFO, "Caught signal, exiting");
    stop = 1;
}

pthread_mutex_t mutex;

struct slist_data_s
{
    pthread_t thread_id;
    int client_fd;
    int thread_complete_flag;
    struct sockaddr_in addr;
    SLIST_ENTRY(slist_data_s) entries;
};

#if !USE_AESD_CHAR_DEVICE
void *timer_thread_function(void *arg)
{
    (void)arg; // Unused
    while (!stop)
    {
        // Sleep for 10 seconds. 
        // We use nanosleep loop or multiple short sleeps so we can react to 'stop' faster?
        // For simplicity required by assignment description "every 10 seconds", 
        // we can sleep 10s. If we need faster exit, we could loop 10 times 1s.
        // But usually, simplest is best unless tests fail on timeout. 
        // Let's assume standard sleep(10) is acceptable or handling signals handles the interrupt.
        // Actually, sleep() returns early on signal, so if SIGTERM/SIGINT comes, it wakes up.
        // But we handle signal in a handler that sets stop=1.
        // The sleep will likely return remaining time if interrupted.
        // We will just loop sleep.
        
        struct timespec ts;
        ts.tv_sec = 10;
        ts.tv_nsec = 0;
        while(nanosleep(&ts, &ts) == -1 && errno == EINTR) {
             if(stop) break;
        }
        if(stop) break;

        time_t t;
        struct tm *tmp;
        char t_str[200];
        
        t = time(NULL);
        tmp = localtime(&t);
        if (tmp == NULL) {
             perror("localtime");
             continue;
        }

        // RFC 2822 format: e.g., "Mon, 15 Aug 2005 15:52:01 +0000"
        if (strftime(t_str, sizeof(t_str), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", tmp) == 0) {
             syslog(LOG_ERR, "strftime returned 0");
             continue;
        }

        pthread_mutex_lock(&mutex);
        FILE *file = fopen(DATAFILE, "a");
        if (file == NULL)
        {
            perror("fopen");
            syslog(LOG_ERR, "fopen(%s, \"a\") failed in timer: %s", DATAFILE, strerror(errno));
            pthread_mutex_unlock(&mutex);
            continue;
        }
        
        if (fputs(t_str, file) == EOF)
        {
             syslog(LOG_ERR, "fputs failed in timer");
        }
        
        fclose(file);
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}
#endif

void *thread_function(void *thread_param)
{
    struct slist_data_s *thread_func_args = (struct slist_data_s *)thread_param;
    int client_fd = thread_func_args->client_fd;
    struct sockaddr_in client_addr = thread_func_args->addr;

    syslog(LOG_INFO, "Accepted connection from %s", inet_ntoa(client_addr.sin_addr));

    char buffer[1024];
    ssize_t bytes_read;
    
    int aesd_fd = open(DATAFILE, O_RDWR);
    if (aesd_fd < 0) {
        perror("open " DATAFILE);
        syslog(LOG_ERR, "open(%s) failed: %s", DATAFILE, strerror(errno));
        close(client_fd);
        thread_func_args->thread_complete_flag = 1;
        return NULL;
    }

    char *full_message_buffer = NULL;
    size_t full_message_size = 0;
    char temp_read_buffer[1024];
    ssize_t bytes_received;

    while ((bytes_received = recv(client_fd, temp_read_buffer, sizeof(temp_read_buffer), 0)) > 0) {
        char *newline_found = memchr(temp_read_buffer, '\n', bytes_received);
        size_t current_chunk_size = bytes_received;
        
        char *new_full_buffer = realloc(full_message_buffer, full_message_size + current_chunk_size);
        if (!new_full_buffer) {
            syslog(LOG_ERR, "realloc failed");
            free(full_message_buffer);
            close(aesd_fd);
            close(client_fd);
            thread_func_args->thread_complete_flag = 1;
            return NULL;
        }
        full_message_buffer = new_full_buffer;
        memcpy(full_message_buffer + full_message_size, temp_read_buffer, current_chunk_size);
        full_message_size += current_chunk_size;

        if (newline_found) {
            break; 
        }
    }

    if (bytes_received < 0) {
        syslog(LOG_ERR, "recv failed: %s", strerror(errno));
    }

    if (full_message_buffer && full_message_size > 0) {
        const char *ioctl_prefix = "AESDCHAR_IOCSEEKTO:";
        struct aesd_seekto seek_to_cmd;
        pthread_mutex_lock(&mutex);

        if (strncmp(full_message_buffer, ioctl_prefix, strlen(ioctl_prefix)) == 0) {
            if (sscanf(full_message_buffer + strlen(ioctl_prefix), "%u,%u", 
                       &seek_to_cmd.write_cmd_num, &seek_to_cmd.write_cmd_offset) == 2) {
                
                syslog(LOG_DEBUG, "IOCTL command: seek to %u,%u", seek_to_cmd.write_cmd_num, seek_to_cmd.write_cmd_offset);
                if (ioctl(aesd_fd, AESDCHAR_IOCSEEKTO, &seek_to_cmd)) {
                    perror("ioctl failed");
                }
            } else {
                syslog(LOG_ERR, "Malformed IOCTL command: %.*s", (int)full_message_size, full_message_buffer);
            }
        } else {
            if (write(aesd_fd, full_message_buffer, full_message_size) < 0) {
                perror("write to " DATAFILE " failed");
            }
        }
        
        pthread_mutex_unlock(&mutex);
    }
    
    free(full_message_buffer); 

    char read_back_buffer[1024];
    ssize_t bytes_read_from_driver;

    pthread_mutex_lock(&mutex);
    while ((bytes_read_from_driver = read(aesd_fd, read_back_buffer, sizeof(read_back_buffer))) > 0) {
        if (send(client_fd, read_back_buffer, bytes_read_from_driver, 0) < 0) {
            perror("send failed");
            break;
        }
    }
    pthread_mutex_unlock(&mutex);

    if (bytes_read_from_driver < 0) {
        perror("read from " DATAFILE " failed");
    }

    // Send entire file, handling partial sends
    ssize_t bytes_sent = 0;
    while (bytes_sent < file_size)
    {
        ssize_t sent = send(client_fd,
                            file_buffer + bytes_sent,
                            (size_t)(file_size - bytes_sent),
                            0);
        if (sent < 0)
        {
            if (errno == EINTR)
                continue;

            perror("send");
            syslog(LOG_ERR, "send failed: %s", strerror(errno));
            break;
        }
        if (sent == 0)
        {
            // Peer closed
            break;
        }
        bytes_sent += sent;
    }

    if (file_buffer)
        free(file_buffer);

    close(aesd_fd);
    close(client_fd);
    thread_func_args->thread_complete_flag = 1;
    return thread_param;
}

int main(int argc, char *argv[])
{
    SLIST_HEAD(slisthead, slist_data_s) head;
    SLIST_INIT(&head);


    pthread_mutex_init(&mutex, NULL);
    
    int server_fd = -1, client_fd = -1;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    openlog("aesdsocket", LOG_PID, LOG_USER);

    // Create listening socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket");
        syslog(LOG_ERR, "socket failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        syslog(LOG_WARNING, "setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
    }

    // Bind to 0.0.0.0:9000
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        syslog(LOG_ERR, "bind failed: %s", strerror(errno));
        close(server_fd);
        exit(EXIT_FAILURE);
    }

#if !USE_AESD_CHAR_DEVICE
    remove(DATAFILE);
#endif

    // Daemon mode if "-d" given
    if (argc > 1 && strcmp(argv[1], "-d") == 0)
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork");
            syslog(LOG_ERR, "fork failed: %s", strerror(errno));
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        if (pid > 0)
        {
            // Parent exits
            exit(EXIT_SUCCESS);
        }

        // Child continues: become session leader
        if (setsid() < 0)
        {
            perror("setsid");
            syslog(LOG_ERR, "setsid failed: %s", strerror(errno));
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        // Redirect stdio to /dev/null
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
    }


    if (listen(server_fd, 10) < 0)
    {
        perror("listen");
        syslog(LOG_ERR, "listen failed: %s", strerror(errno));
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);
    syslog(LOG_INFO, "Server listening on port %d", PORT);

    // Install signal handlers (no SA_RESTART so accept() is interrupted)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // important: do not restart syscalls
    if (sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0)
    {
        syslog(LOG_ERR, "sigaction failed: %s", strerror(errno));
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Start timer thread
#if !USE_AESD_CHAR_DEVICE
    pthread_t timer_thread;
    if (pthread_create(&timer_thread, NULL, timer_thread_function, NULL) != 0)
    {
        perror("pthread_create timer");
        syslog(LOG_ERR, "Failed to create timer thread");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
#endif
    while (!stop)
    {
        addr_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0)
        {
            if (errno == EINTR && stop)
            {
                // Interrupted by signal and we should exit
                break;
            }
            perror("accept");
            syslog(LOG_ERR, "accept failed: %s", strerror(errno));
            continue;
        }

        // Allocate memory for thread data
        struct slist_data_s *datap = malloc(sizeof(struct slist_data_s));
        if (datap == NULL)
        {
            perror("malloc");
            syslog(LOG_ERR, "malloc failed");
            close(client_fd);
            continue;
        }

        datap->client_fd = client_fd;
        datap->addr = client_addr;
        datap->thread_complete_flag = 0;

        if (pthread_create(&datap->thread_id, NULL, thread_function, datap) != 0)
        {
            perror("pthread_create");
            syslog(LOG_ERR, "pthread_create failed: %s", strerror(errno));
            free(datap);
            close(client_fd);
            continue;
        }

        SLIST_INSERT_HEAD(&head, datap, entries);

        // Check for completed threads and join them
        struct slist_data_s *entry = NULL;
        struct slist_data_s *next_entry = NULL;
        
        // Manual safe traversal
        entry = SLIST_FIRST(&head);
        while (entry != NULL)
        {
            next_entry = SLIST_NEXT(entry, entries);
            if (entry->thread_complete_flag)
            {
                pthread_join(entry->thread_id, NULL);
                SLIST_REMOVE(&head, entry, slist_data_s, entries);
                free(entry);
                // We restart traversal or continue? 
                // Since SLIST_REMOVE is correct, next_entry is still valid (it was entry->next).
                // However, SLIST_REMOVE might be O(N).
            }
            entry = next_entry;
        }
    }

    // Clean up all resources
    if (server_fd >= 0)
        close(server_fd);

    // Join any remaining threads
    while (!SLIST_EMPTY(&head))
    {
        struct slist_data_s *entry = SLIST_FIRST(&head);
        pthread_join(entry->thread_id, NULL);
        SLIST_REMOVE_HEAD(&head, entries);
        free(entry);
    }

#if !USE_AESD_CHAR_DEVICE
    // Join timer thread
    pthread_cancel(timer_thread);
    pthread_join(timer_thread, NULL);
    remove(DATAFILE);
#endif

    syslog(LOG_INFO, "Server exiting");
    closelog();

    pthread_mutex_destroy(&mutex);

    return 0;
}
