#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

#define MAX_PATH_LENGTH 1024

typedef struct
{
    char name[MAX_PATH_LENGTH];
    mode_t mode;
    off_t size;
    time_t mtime;
} FileMetadata;

// Function to update a snapshot file with file metadata
void update_snapshot_file(const char *snapshot_path, const char *path, const FileMetadata *metadata)
{
    // Open the snapshot file for writing or create it if it doesn't exist
    int snapshot_file = open(snapshot_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (snapshot_file != -1)
    {
        FileMetadata snapshot_metadata;
        // Read existing metadata from the snapshot file
        read(snapshot_file, &snapshot_metadata, sizeof(FileMetadata));
        close(snapshot_file);

        // Check if metadata has changed since the last snapshot
        if (metadata->mode != snapshot_metadata.mode ||
            metadata->size != snapshot_metadata.size ||
            metadata->mtime != snapshot_metadata.mtime)
        {
            // Write metadata to the snapshot file
            snapshot_file = open(snapshot_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (snapshot_file != -1)
            {

                dprintf(snapshot_file, "File: %s\n", metadata->name);
                dprintf(snapshot_file, "Size: %ld bytes\n", (long)metadata->size);
                dprintf(snapshot_file, "Last modified time: %s", ctime(&metadata->mtime));
                dprintf(snapshot_file, "Path: %s\n", path);
                dprintf(snapshot_file, "st_mode: %d\n\n\n", metadata->mode);
                close(snapshot_file);
                // printf("Modifications detected in file: %s\n", path);
            }
            else
            {
                perror("Error updating snapshot file");
            }
        }
    }
    else
    {
        // If the snapshot file doesn't exist, create it and write metadata
        int snapshot_file = open(snapshot_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (snapshot_file != -1)
        {
            // Write metadata to the snapshot file
            write(snapshot_file, metadata, sizeof(FileMetadata));
            close(snapshot_file);
        }
    }
}

// Function to retrieve metadata of a file specified by path
void file_metadata(const char *path, FileMetadata *metadata)
{
    struct stat file_stat;
    if (stat(path, &file_stat) == -1)
    {
        perror("Error getting file metadata");
        exit(EXIT_FAILURE);
    }

    strncpy(metadata->name, path, MAX_PATH_LENGTH);
    metadata->mode = file_stat.st_mode;
    metadata->size = file_stat.st_size;
    metadata->mtime = file_stat.st_mtime;
}

// Function to monitor a directory for potentially malicious files, update snapshots, and count corrupt files
void monitor_check_directory(const char *dir_path, const char *output_dir, const char *isolated_dir, int *corrupt_count)
{
    DIR *dir;
    struct dirent *entry;

    // Open the directory for reading
    if ((dir = opendir(dir_path)) == NULL)
    {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    // Iterate over each entry in the directory
    while ((entry = readdir(dir)) != NULL)
    {
        // Skip special directories "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        // Construct the full path of the current file or directory
        char path[MAX_PATH_LENGTH];
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        FileMetadata metadata;
        // Get metadata for the current file or directory
        file_metadata(path, &metadata);

        // Check if file permissions are unsafe (not fully restricted)
        if ((metadata.mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != (S_IRWXU | S_IRWXG | S_IRWXO))
        {
            int pipe_fd[2];
            // Create a pipe for communication with the child process
            if (pipe(pipe_fd) == -1)
            {
                perror("Error creating pipe");
                exit(EXIT_FAILURE);
            }

            // Create a child process to execute the malware verification script
            pid_t child_pid = fork();
            if (child_pid == -1)
            {
                perror("Error creating child process");
                exit(EXIT_FAILURE);
            }
            else if (child_pid == 0)
            {
                close(pipe_fd[0]); // Close reading end of the pipe in the child process

                // Execute the malware verification script
                execlp("./verify_for_malicious.sh", "verify_for_malicious.sh", path, isolated_dir, "corrupted", "dangerous", "risk", "attack", "malware", "malicious", NULL);
                perror("Error executing script");
                exit(EXIT_FAILURE);
            }
            else
            {
                close(pipe_fd[1]); // Close writing end of the pipe in the parent process

                char buffer[20]; // Buffer for reading from the pipe
                ssize_t bytes_read;

                // Read from the pipe
                bytes_read = read(pipe_fd[0], buffer, sizeof(buffer) - 1);
                if (bytes_read == -1)
                {
                    perror("Error reading from pipe");
                    exit(EXIT_FAILURE);
                }

                buffer[bytes_read] = '\0';
                close(pipe_fd[0]);

                // Check the result of the malware verification
                if (strcmp(buffer, "SAFE") == 0)
                {
                    printf("File %s is safe\n", metadata.name);
                }
                else
                {
                    printf("File %s is potentially malicious\n", metadata.name);
                    (*corrupt_count)++;
                }
            }
        }

        // Update the snapshot file with metadata for the current file
        char snapshot_path[MAX_PATH_LENGTH];
        snprintf(snapshot_path, sizeof(snapshot_path), "%s/%s.txt", output_dir, entry->d_name);
        update_snapshot_file(snapshot_path, path, &metadata);
        printf("Snapshot for Directory %s updated successfully.\n", dir_path);
    }

    // Wait for all child processes to terminate
    while (wait(NULL) > 0)
        ;

    closedir(dir); // Close the directory
}

int main(int argc, char *argv[])
{

    // Check for the correct number of command-line arguments
    if (argc < 5 || argc > 15)
    {
        printf("Error: Invalid number of arguments. Usage: %s -o output_dir -s isolated_space_dir dir1 dir2 ...\n", argv[0]);
        return 1;
    }

    // Check if the first argument is "-o" for specifying the output directory
    if (strcmp(argv[1], "-o") != 0)
    {
        printf("Error: First argument must be -o for specifying the output directory.\n");
        return 1;
    }

    // Check if the third argument is "-s" for specifying the safe directory
    if (strcmp(argv[3], "-s") != 0)
    {
        printf("Error: Third argument must be -s for specifying the safe directory.\n");
        return 1;
    }

    const char *output_dir = argv[2];
    const char *isolated_space_dir = argv[4];

    struct stat st;
    // Verify the existence of the output directory
    if (stat(output_dir, &st) == -1)
    {
        printf("Error: Output directory does not exist.\n");
        return 1;
    }
    // Verify the existence of the isolated space directory
    if (stat(isolated_space_dir, &st) == -1)
    {
        printf("Error: Isolated space directory does not exist.\n");
        return 1;
    }

    int corrupt_count = 0; // Initialize count of potentially malicious files
    int i;
    pid_t child_pid;

    // Iterate over directories specified as arguments
    for (i = 5; i < argc; i++)
    {
        struct stat st2;
        // Verify if the argument is a directory and accessible
        if (stat(argv[i], &st2) == -1)
        {
            printf("Error: Cannot access %s\n", argv[i]);
            continue;
        }

        if (!S_ISDIR(st2.st_mode))
        {
            printf("Error: %s is not a directory. Ignored.\n", argv[i]);
            continue;
        }

        child_pid = fork();
        if (child_pid == -1)
        {
            perror("Error creating child process");
            return 1;
        }
        else if (child_pid == 0)
        {
            // Child process: monitor the directory and count potentially malicious files
            printf("Child process with PID %d started.\n", getpid());
            monitor_check_directory(argv[i], output_dir, isolated_space_dir, &corrupt_count);
            exit(corrupt_count);
        }
    }

    int status;
    pid_t pid;
    int total_corrupt = 0;

    // Wait for all child processes to terminate and collect their results
    while ((pid = wait(&status)) != -1)
    {
        if (WIFEXITED(status))
        {
            total_corrupt += WEXITSTATUS(status);
            printf("Child process terminated with PID %d and %d files potentially malicious.\n", pid, WEXITSTATUS(status));
        }
        else
        {
            printf("Child process terminated abnormally.\n");
        }
    }

    // Print the total number of potentially malicious files found
    printf("Total number of potentially malicious files found: %d\n", total_corrupt);

    // Wait for any remaining child processes to terminate
    while (wait(NULL) > 0)
        ;

    return 0;
}
