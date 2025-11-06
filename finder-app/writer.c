#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

int write_data_to_file(const char *filepath, const char *data)
{
    FILE *file = fopen(filepath, "w");
    if (file == NULL)
    {
        syslog(LOG_ERR, "Failed to open file for writing");
        return -1;
    }

    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}

int main(int argc, char *argv[])
{

    openlog("finder-app", LOG_PID | LOG_CONS, LOG_USER);

    if (argc != 3)
    {
        syslog(LOG_ERR, "Usage: %s <writefile> <writestr>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *writefile = argv[1];
    const char *writestr = argv[2];

    if (write_data_to_file(writefile, writestr) != 0)
    {
        syslog(LOG_ERR, "Error writing data to file\n");
        return EXIT_FAILURE;
    }

    syslog(LOG_DEBUG, "Writing %s to %s\n", writestr, writefile);
    return EXIT_SUCCESS;
}