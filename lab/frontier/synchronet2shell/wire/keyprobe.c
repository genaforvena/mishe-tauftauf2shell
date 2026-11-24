#include <stdio.h>
#include "cryptlib.h"
int main(void) {
	CRYPT_CONTEXT key = CRYPT_UNUSED;
	int status;
	cryptInit();
	status = cryptCreateContext(&key, CRYPT_UNUSED, CRYPT_ALGO_RSA);
	printf("create=%d\n", status);
	status = cryptSetAttributeString(key, CRYPT_CTXINFO_LABEL, "ssh-host", 8);
	printf("label=%d\n", status);
	status = cryptSetAttribute(key, CRYPT_CTXINFO_KEYSIZE, 256);
	printf("keysize=%d\n", status);
	status = cryptGenerateKey(key);
	printf("generate=%d\n", status);
	cryptDestroyContext(key);
	cryptEnd();
	return 0;
}
