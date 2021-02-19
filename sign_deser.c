#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hyperscan/src/hs_runtime.h"

#define SIGN_MAX_LEN 500
#define LINES 173
#define PATH_TO_DB "/home/doughnuty/Desktop/CS/NGINX/hprscn/db"

static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx) {
    printf("Match of the pattern %d at offset %llu\n", id, to);
    return 0;
}

static char *read_input(const char *inputFN, unsigned int *length) {
    FILE *f = fopen(inputFN, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: unable to open file \"%s\": %s\n", inputFN,
                strerror(errno));
        return NULL;
    }

    /* We use fseek/ftell to get our data length, in order to keep this example
     * code as portable as possible. */
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }
    long dataLen = ftell(f);
    if (dataLen < 0) {
        fprintf(stderr, "ERROR: ftell() failed: %s\n", strerror(errno));
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }

    /* Hyperscan's hs_scan function accepts length as an unsigned int, so we
     * limit the size of our buffer appropriately. */
    if ((unsigned long)dataLen > UINT_MAX) {
        dataLen = UINT_MAX;
        printf("WARNING: clipping data to %ld bytes\n", dataLen);
    } else if (dataLen == 0) {
        fprintf(stderr, "ERROR: input file \"%s\" is empty\n", inputFN);
        fclose(f);
        return NULL;
    }

    char *inputData = malloc(dataLen);
    if (!inputData) {
        fprintf(stderr, "ERROR: unable to malloc %ld bytes\n", dataLen);
        fclose(f);
        return NULL;
    }

    char *p = inputData;
    size_t bytesLeft = dataLen;
    while (bytesLeft) {
        size_t bytesRead = fread(p, 1, bytesLeft, f);
        bytesLeft -= bytesRead;
        p += bytesRead;
        if (ferror(f) != 0) {
            fprintf(stderr, "ERROR: fread() failed\n");
            free(inputData);
            fclose(f);
            return NULL;
        }
    }

    fclose(f);

    *length = (unsigned int)dataLen;
    return inputData;
}

int main(int argc, char *argv[]) 
{   
    clock_t start = clock();
    if (argc != 2) 
    {
        printf("Invalid Input\nUsage ./prog scan_filename\n");
        return 1;
    }
    char *input_fn = argv[1];


    // read data from file
    unsigned db_data_length;
    char *db_data = read_input(PATH_TO_DB, &db_data_length);

    // deserealize db
    hs_database_t *db;
    hs_error_t err = hs_deserialize_database(db_data, db_data_length, &db);
    free(db_data);
    if (err != HS_SUCCESS)
    {
        printf("deserialize failed\n");
        hs_free_database(db);
        return -1;
    }

    // check info 
    char *info;
    err = hs_database_info(db, &info);
    printf("Hyperscan database info: %s\n", info);
    free(info);

    // read input file into buffer
    unsigned size;
    char *input_data = read_input(input_fn, &size);
    if (!input_data) {
        hs_free_database(db);
        return -2;
    }

    // allocating scratch mem for patterns scanning
    hs_scratch_t *scratch = NULL;
    if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to allocate scratch space. Exiting.\n");
        free(input_data);
        hs_free_database(db);
        return -1;
    }

    // scanning file for patterns
    printf("Start Scanning of %s with hyperscan. Size: %d bytes\n", input_fn, size/1024);
    
    if (hs_scan(db, input_data, size, 0, scratch, eventHandler, 0) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
        hs_free_scratch(scratch);
        free(input_data);
        hs_free_database(db);
        return -1;
    }

    int msec = (clock() - start) * 1000 / CLOCKS_PER_SEC;
    printf("From the scan start elapsed %d seconds %d milliseconds\n", msec/1000, msec%1000);

    // cleaning and exiting
    hs_free_scratch(scratch);
    free(input_data);
    hs_free_database(db);

    return 0;
}