/* Lab-only benign marker for the live _session_ticket() control experiment.
 * Writes one line and exits 42. No files, no commands, no external traffic. */
#include <unistd.h>

void benign_marker(void)
{
	static const char msg[] = "R4L-LIVE-BENIGN-MARKER\n";
	ssize_t ignored = write(1, msg, sizeof(msg) - 1);
	(void)ignored;
	_exit(42);
}
