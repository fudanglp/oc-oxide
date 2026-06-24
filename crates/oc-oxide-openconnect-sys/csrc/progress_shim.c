/* Variadic trampoline for libopenconnect's progress callback.
 *
 * Rust stable cannot implement C variadic functions. This shim has the
 * printf-style callback signature expected by libopenconnect, formats the
 * message, and forwards it to a plain Rust callback.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

extern void oc_oxide_progress_sink(void *privdata, int level, const char *msg);

void oc_oxide_progress_trampoline(void *privdata, int level, const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0) {
        buf[0] = '\0';
    }

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    oc_oxide_progress_sink(privdata, level, buf);
}
