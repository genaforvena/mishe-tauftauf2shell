/* Verbatim bytes of src/DS/sds.c lines 853-887 at fix commit
 * 5f1f2bccd4b5f85e44a21a0ce3c854fbb65a2163, see pins/sds.c.fixed.
 * Only libc malloc/strlen are used by this function. */
#include <stdlib.h>
#include <string.h>

#line 853 "src/DS/sds.c"
char* ds_sds_mangle_filepath(const char* filepath)
{
	if (filepath == NULL)
		return NULL;

	// the string will grow 2x the size in the worst case (every char is /)
	// TODO: We can do better than this by counting the slashes
	char* ret = malloc((strlen(filepath) * sizeof(char) * 2) + 1);

	const char* src_it = filepath;
	char* dst_it = ret;

	while (*src_it)
	{
		if (*src_it == '/')
		{
			*dst_it++ = '-';
			*dst_it++ = '-';
		}
		else if (*src_it == '@') {
			*dst_it++ = '-';
			*dst_it++ = '-';
		}
		else
		{
			*dst_it++ = *src_it;
		}

		src_it++;
	}

	*dst_it = '\0';

	return ret;
}
