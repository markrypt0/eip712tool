/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CONFIRM_SM_H
#define CONFIRM_SM_H

#include <stdbool.h>
#include "keepkey/board/layout.h"
typedef enum _FailureType {
    FailureType_Failure_UnexpectedMessage = 1,
    FailureType_Failure_ButtonExpected = 2,
    FailureType_Failure_SyntaxError = 3,
    FailureType_Failure_ActionCancelled = 4,
    FailureType_Failure_PinExpected = 5,
    FailureType_Failure_PinCancelled = 6,
    FailureType_Failure_PinInvalid = 7,
    FailureType_Failure_InvalidSignature = 8,
    FailureType_Failure_Other = 9,
    FailureType_Failure_NotEnoughFunds = 10,
    FailureType_Failure_NotInitialized = 11,
    FailureType_Failure_PinMismatch = 12,
    FailureType_Failure_FirmwareError = 99
} FailureType;

typedef enum {
    ButtonRequestType_ButtonRequest_Other = 1
} ButtonRequestType;

bool review(ButtonRequestType type, const char *request_title, const char *request_body,
            ...);
bool review_with_icon(ButtonRequestType type, IconType iconNum, const char *request_title, const char *request_body,
            ...);

void fsm_sendFailure(FailureType code, const char *text);

#define DEBUG_DISPLAY_VAL(TITLE,VALNAME,SIZE,BYTES) \
{\
  char str[SIZE+1];\
  int ctr;\
  for (ctr=0; ctr<SIZE/2; ctr++) {\
    snprintf(&str[2*ctr], 3, "%02x", BYTES);\
  }\
  printf("\n%s\n%s %s\n", TITLE, VALNAME, str);\
  /*(void)review(ButtonRequestType_ButtonRequest_Other, TITLE,*/\
  /*             VALNAME, str);*/\
}

#endif
