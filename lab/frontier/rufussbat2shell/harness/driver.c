#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int BOOL;
typedef struct {
	char* product;
	uint32_t version;
} sbat_entry_t;

#include SBAT_SOURCE

typedef struct {
	char* prefix;
	void (*callback)(void);
	uint64_t guard;
} victim_t;

#define VICTIM_GUARD UINT64_C(0x1122334455667788)
static victim_t* g_victim;

void benign_marker(void)
{
	puts("BENIGN_MARKER");
}

void not_called(void)
{
	puts("NOT_CALLED");
}

#ifdef WRAP_CALLOC
void* __real_calloc(size_t nmemb, size_t size);

void* __wrap_calloc(size_t nmemb, size_t size)
{
	if (size != 0 && nmemb > SIZE_MAX / size)
		return NULL;
	size_t bytes = nmemb * size;
	if (bytes > SIZE_MAX - sizeof(victim_t))
		return NULL;
	unsigned char* raw = __real_calloc(1, bytes + sizeof(victim_t));
	if (raw == NULL)
		return NULL;
	g_victim = (victim_t*)(raw + bytes);
	g_victim->prefix = (char*)(uintptr_t)UINT64_C(0x1111111111111111);
	g_victim->callback = not_called;
	g_victim->guard = VICTIM_GUARD;
	return raw;
}
#endif

static char* read_input(const char* path, size_t* len_out)
{
	FILE* f = fopen(path, "rb");
	if (f == NULL) {
		perror(path);
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		perror("fseek");
		fclose(f);
		return NULL;
	}
	long n = ftell(f);
	if (n < 0 || n > 4096) {
		fprintf(stderr, "input length out of lab range: %ld\n", n);
		fclose(f);
		return NULL;
	}
	rewind(f);
	char* data = malloc((size_t)n + 2);
	if (data == NULL) {
		perror("malloc");
		fclose(f);
		return NULL;
	}
	size_t got = fread(data, 1, (size_t)n, f);
	if (got != (size_t)n || ferror(f)) {
		fprintf(stderr, "short read: %zu != %ld\n", got, n);
		free(data);
		fclose(f);
		return NULL;
	}
	fclose(f);
	data[got] = '\0';
	data[got + 1] = '\0';
	*len_out = got;
	return data;
}

int main(int argc, char** argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <sbat_level.txt> <iterate|marker>\n", argv[0]);
		return 2;
	}
	size_t len = 0;
	char* data = read_input(argv[1], &len);
	if (data == NULL)
		return 2;
	sbat_entry_t* list = GetSbatEntries(data);
	printf("BYTES=%zu LIST=%s\n", len, list != NULL ? "nonnull" : "null");
	if (list == NULL)
		return 3;

	if (strcmp(argv[2], "iterate") == 0) {
		size_t count = 0;
		while (count < 10000 && list[count].product != NULL)
			count++;
		printf("ENTRIES=%zu\n", count);
		free(list);
		free(data);
		return 0;
	}

	if (strcmp(argv[2], "marker") == 0) {
#ifdef WRAP_CALLOC
		if (g_victim == NULL) {
			fputs("missing wrapped victim\n", stderr);
			return 4;
		}
		uintptr_t prefix = (uintptr_t)g_victim->prefix;
		uintptr_t base = (uintptr_t)data;
		int prefix_in_input = prefix >= base &&
			prefix - base < (uintptr_t)len;
		const char* callback_name = g_victim->callback == benign_marker ?
			"benign_marker" : g_victim->callback == not_called ?
			"not_called" : "unexpected";
		printf("PREFIX_IN_INPUT=%d CALLBACK=%s GUARD=%016" PRIx64 "\n",
			prefix_in_input, callback_name, g_victim->guard);
		if (g_victim->guard != VICTIM_GUARD) {
			fputs("victim guard changed\n", stderr);
			return 5;
		}
		if (g_victim->callback == benign_marker)
			g_victim->callback();
		else if (g_victim->callback == not_called)
			g_victim->callback();
		else {
			fputs("unexpected callback target\n", stderr);
			return 6;
		}
		free(list);
		free(data);
		return 0;
#else
		fputs("marker mode requires WRAP_CALLOC\n", stderr);
		return 7;
#endif
	}

	fputs("unknown mode\n", stderr);
	return 2;
}
