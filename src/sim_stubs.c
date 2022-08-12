// stubs for eip712 simulator

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>

#include "keepkey/board/confirm_sm.h"

static char strbuf[352];
static bool button_request_acked = false;
unsigned end;

bool review(ButtonRequestType type, const char *request_title, const char *request_body,
            ...)
{
    button_request_acked = false;
    va_list vl;
    va_start(vl, request_body);
    vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
    va_end(vl);

		printf("kk review message: Title->%s, %s\n", request_title, strbuf);

    return true;
}
