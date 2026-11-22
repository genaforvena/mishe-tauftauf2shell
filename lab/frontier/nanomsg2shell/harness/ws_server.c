#include <nn.h>
#include <pair.h>
#include <stdio.h>
#include <unistd.h>

int main (void)
{
    int s = nn_socket (AF_SP, NN_PAIR);
    if (s < 0) { fprintf (stderr, "socket failed %d\n", nn_errno ()); return 1; }
    int rc = nn_bind (s, "ws://127.0.0.1:28765");
    printf ("bound rc=%d\n", rc); fflush (stdout);
    sleep (3);
    nn_close (s);
    return 0;
}
