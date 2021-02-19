// 		Given an array of 10 regexp compile them into one and scan input line
//      1. handle the input
//      2. hs_compile_multi()
//      3. 

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <hs.h>

// 32, 88, 172 - unsupported/ 
// 123 - unmatched parentheses after (? at ind 107
// 173, 174 \u not supported
// 177 unmatched parentheses
// %c0%ae[\/\\\]
// ([^*\\s\\w,.\\\/?+-]\\s*)
// (?:(select|.)\\s+(?i:benchmark|if|sleep)\\s*?\\(\\s*\\(?\\s*\\w+)
// (?:#@~\\^\\w+)|(?:\\w+script:|@import[^\\w]|;base64|base64,)|(?:\\w\\s*\\([\\w\\s]+,[\\w\\s]+,[\\w\\s]+,[\\w\\s]+,[\\w\\s]+,[\\w\\s]+\\))
// ([^*:\\s\\w,.\\\/?+-]\\s*)?(?<![a-z]\\s)(?<![a-z\\\/_@\\-\\|])(\\s*return\\s*)?(?:create(?:element|attribute|textnode)|[a-z]+events?|setattribute|getelement\\w+|appendchild|createrange|createcontextualfragment|removenode|parentnode|decodeuricomponent|\\wettimeout|(?:ms)?setimmediate|option|useragent)(?(1)[^\\w%\"]|(?:\\s*[^@\\s\\w%\",.+\\-]))
#define SIGN_MAX_LEN 500
#define LINES 172
#define PATH_TO_DB "/home/doughnuty/Desktop/CS/NGINX/hprscn/db"

char** parse_patterns(const char *filename) 
{
    char ** patterns;


    printf("Scanning file for patterns\n");
    // open file
    FILE *f = fopen(filename, "rb");    
    if (!f) {
        printf("ERROR: unable to open file \"%s\": %s\n", filename,
                strerror(errno));
        return NULL;
    }

    // get the number of lines
    int num_lines = LINES;

    // allocate memory for patterns, ids and flags
        // patterns
    printf("DEBUG: allocating memory\n");
    patterns = malloc(num_lines*sizeof(char*));
    
    for(int i = 0, j = 0; i < num_lines; j++) 
    {
        //printf("DEBUG: allocating memory for each element. Completed: %d/20 Character num: %d\n", i, j);
        if (j == 0) patterns[i] = malloc(SIGN_MAX_LEN);
        char p;
        fread(&p, 1, 1, f);
        if(p != '\n')
        {
            patterns[i][j] = p;
        }
        else {

            patterns[i][j] = '\0';
            i++;
            j = -1;
            printf("DEBUG: Found new line. Completed %d signature: %s\n", i, patterns[i-1]);
        }

        if (feof(f)) 
        {
            printf("Reached the end of a file!\n");
            break;
        }

        if (ferror(f) != 0) 
        {
            printf("ERROR: bad read\n");
        }
    }

    printf("DEBUG: allocation finished\n");
    // go through the file, parse & fill vars
   
    // close the file
    fclose(f);

    // return number of meaningful lines
    return patterns;
}

static hs_database_t *build_database(const char **patterns, unsigned mode)
{
    hs_database_t *db;
    hs_compile_error_t *compile_err;
    hs_error_t err;

    int num_lines = LINES;
    unsigned ids[num_lines];
    for (int i = 0; i < num_lines; i++) 
    {
        ids[i] = i;
    }
    err = hs_compile_multi(patterns, NULL, ids, num_lines, mode, NULL, &db, &compile_err);
    printf("DEBUG: Compilation finished\n");
    
    if (err != HS_SUCCESS) {
        if (compile_err->expression < 0) 
        {
            // The error does not refer to a particular expression.
            printf("ERROR: %s\n", compile_err->message);
        }
        else 
        { 
            printf("ERROR: Pattern '%s' failed compilation with error %s\n", patterns[compile_err->expression], compile_err->message);
        }

        // release err memory
        hs_free_compile_error(compile_err);
        return NULL;
    }

    printf("Hyperscan database successfully compiled\n");

    return db;
}


int main(int argc, char *argv[]) 
{
    if(argc != 2) 
    {
        printf("Invalid Input\nUsage ./prog pattern_filename\n");
        return 1;
    }

    char *pattern_fn = argv[1];

    hs_database_t *db;

    // parse pattern file 
    char **patterns = parse_patterns(pattern_fn);
    if (patterns == NULL) {
        printf("ERROR: invalid signature file parse\n");
        return -1;
    }

    // compile them into database
    printf("Compiling Hyperscan databases with %d patterns.\n", LINES);
    db = build_database((const char**)patterns, HS_MODE_BLOCK);
    if (db == NULL) {
        printf("Error compiling database\n");
        return -1;
    }

    // serialize db
    char *bytes = NULL;
    size_t length = 0;
    hs_error_t err = hs_serialize_database(db, &bytes, &length);
    if (err != HS_SUCCESS)
    {
        printf("deserialize failed\n");
        hs_free_database(db);
        return -1;
    }

    // write to a file
    FILE *f = fopen(PATH_TO_DB, "w+");
    fwrite(bytes, sizeof(char), length, f);
    fclose(f); 

    hs_free_database(db);

    for (int i = 0; i < LINES; i++) 
    {
        free(patterns[i]);
    }

    free(patterns);


    return 0;

}
