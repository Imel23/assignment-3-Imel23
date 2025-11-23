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

#define PORT 9000
#define DATAFILE "/var/tmp/aesdsocketdata"

volatile sig_atomic_t stop = 0;

void signal_handler(int signo)
{
    syslog(LOG_INFO, "Caught signal, exiting");
    stop = 1;
}

int main(int argc, char *argv[])
{
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

    remove(DATAFILE);

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

        syslog(LOG_INFO, "Accepted connection from %s",
               inet_ntoa(client_addr.sin_addr));

        // Append incoming data to DATAFILE until newline seen
        FILE *file = fopen(DATAFILE, "a");
        if (file == NULL)
        {
            perror("fopen");
            syslog(LOG_ERR, "fopen(%s, \"a\") failed: %s", DATAFILE, strerror(errno));
            close(client_fd);
            continue;
        }

        char buffer[1024];
        ssize_t bytes_read;

        while ((bytes_read = read(client_fd, buffer, sizeof(buffer))) > 0)
        {
            char *newline = memchr(buffer, '\n', bytes_read);
            size_t to_write = bytes_read;

            if (newline)
                to_write = (size_t)(newline - buffer) + 1;

            if (fwrite(buffer, 1, to_write, file) != to_write)
            {
                syslog(LOG_ERR, "fwrite failed");
                break;
            }

            if (newline)
                break;
        }

        if (bytes_read < 0)
        {
            syslog(LOG_ERR, "read failed: %s", strerror(errno));
        }

        fclose(file);

        // Now send back entire file contents to the client
        file = fopen(DATAFILE, "r");
        if (file == NULL)
        {
            perror("fopen");
            syslog(LOG_ERR, "fopen(%s, \"r\") failed: %s", DATAFILE, strerror(errno));
            close(client_fd);
            continue;
        }

        if (fseek(file, 0, SEEK_END) != 0)
        {
            syslog(LOG_ERR, "fseek failed: %s", strerror(errno));
            fclose(file);
            close(client_fd);
            continue;
        }

        long file_size = ftell(file);
        if (file_size < 0)
        {
            syslog(LOG_ERR, "ftell failed: %s", strerror(errno));
            fclose(file);
            close(client_fd);
            continue;
        }

        rewind(file);

        char *file_buffer = NULL;
        if (file_size > 0)
        {
            file_buffer = malloc((size_t)file_size);
            if (!file_buffer)
            {
                syslog(LOG_ERR, "malloc(%ld) failed", file_size);
                fclose(file);
                close(client_fd);
                continue;
            }

            size_t bytes_read_file = fread(file_buffer, 1, (size_t)file_size, file);
            if (bytes_read_file != (size_t)file_size)
            {
                syslog(LOG_ERR, "fread mismatch: read %zu expected %ld",
                       bytes_read_file, file_size);
                free(file_buffer);
                fclose(file);
                close(client_fd);
                continue;
            }
        }

        fclose(file);

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

        close(client_fd);
        client_fd = -1;
    }

    // Clean up all resources
    if (server_fd >= 0)
        close(server_fd);

    remove(DATAFILE);
    syslog(LOG_INFO, "Server exiting");
    closelog();

    return 0;
}
