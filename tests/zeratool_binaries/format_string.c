// Zeratool's tests/format_string.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * compiled with:
 * gcc -O0 -fno-stack-protector -o hard -z execstack -z norelro hard.c
 * run with:
 * socat TCP4-LISTEN:7803,tcpwrap=script,reuseaddr,fork EXEC:./hard
 */

#define SECRET "---BEGIN PRIVATE KEY---"

#ifdef MEDIUM
/*
 * Test for point to win
 */
void secret_function(void)
{
    puts(SECRET);
}
#endif

int main(int argc, char *argv[])
{
    int i = 0;

#ifdef EASY
    char buf[1024];
    fgets(buf, 1024, stdin);
    /*
     * Test for stack reading
     */
    char key[64] = {};
    strcpy(key, SECRET);
#endif

#ifdef MEDIUM
    char buf[256];
    read(0, buf, 256);
#endif

#ifdef HARD
    char buf[1024];
    /* read user input securely */
    fgets(buf, 1024, stdin);
    /*
     * Test for point to shellcode AND
     * satisfy constraints
     */
    /* convert string to lowercase */
    for (i = 0; i < strlen(buf); i++)
        if (buf[i] >= 'A' && buf[i] <= 'Z')
            buf[i] = buf[i] ^ 0x20;
#endif

    /* print out our nice and new lowercase string */
    printf(buf);

    exit(EXIT_SUCCESS);
    return EXIT_FAILURE;
}