
/*
 * Copyright (c) 2022 markrypto  (cryptoakorn@gmail.com)
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


/* 
    This tool produces hashes based on the metamask v4 rules. This is different from the EIP-712 spec
    in how arrays of structs are hashed but is compatable with metamask.
    See https://github.com/MetaMask/eth-sig-util/pull/107

    eip712 data rules:
    Parser wants to see C strings, not javascript strings:
        requires all complete json message strings to be enclosed by braces, i.e., { ... }
        Cannot have entire json string quoted, i.e., "{ ... }" will not work.
        Remove all quote escape chars, e.g., {"types":  not  {\"types\":
    int values must be hex. Negative sign indicates negative value, e.g., -5, -8a67 
        Note: Do not prefix ints or uints with 0x
    All hex and byte strings must be big-endian
    Byte strings and address should be prefixed by 0x
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./colors.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/tiny-json.h"

#define _(X) (X)

// eip712tool specific defines
//#define DISPLAY_INTERMEDIATES 1     // define this to display intermediate hash results
#define BUFSIZE             4000
#define PRIMETYPE_BUFSIZE    80
#define DOMAIN_BUFSIZE      300
#define MESSAGE_BUFSIZE     2000
#define TYPES_BUFSIZE       2000                    // This will be used as the types,values concatenated string
// Example
// DEBUG_DISPLAY_VAL("sig", "sig %s", 65, resp->signature.bytes[ctr]);


int evp_parse(const unsigned char *tokenVals) {
  json_t memTV[5] = {0};
  json_t const* jsonTV, *obTest;
  const char *tokenAddrStr, *ticker, *chainIdStr, *decimalStr;
  uint32_t chainId, decimals;
  uint16_t tokCtr;

  jsonTV = json_create((char *)tokenVals, memTV, sizeof memTV / sizeof *memTV );
  if (!jsonTV) {
    fsm_sendFailure(FailureType_Failure_Other, _("Malformed token data json string"));
    return MV_TDERR;
  }

  if (NULL == (obTest = json_getProperty(jsonTV, "address"))) {
    fsm_sendFailure(FailureType_Failure_Other, _("Token data address property error"));
    return MV_TDERR;
  }
  if (0 == (tokenAddrStr = json_getValue(obTest))) {
    fsm_sendFailure(FailureType_Failure_Other, _("Token data address value error"));
    return MV_TDERR;
  }
  if (NULL == (obTest = json_getProperty(jsonTV, "ticker"))) {
    fsm_sendFailure(FailureType_Failure_Other, _("Token data ticker property error"));
    return MV_TDERR;
  }
  if (0 == (ticker = json_getValue(obTest))) {
    fsm_sendFailure(FailureType_Failure_Other, _("Token data ticker value error"));
    return MV_TDERR;
  }
  if (NULL == (obTest = json_getProperty(jsonTV, "chainId"))) {
    fsm_sendFailure(FailureType_Failure_Other, _("Token data chainId property error"));
    return MV_TDERR;
  }
  if (0 == (chainIdStr = json_getValue(obTest))) {
    fsm_sendFailure(FailureType_Failure_Other, _("Token data chainId value error"));
    return MV_TDERR;
  }
  sscanf((char *)chainIdStr, "%ld", &chainId);

  if (NULL == (obTest = json_getProperty(jsonTV, "decimals"))) {
    fsm_sendFailure(FailureType_Failure_Other, _("Token data decimals property error"));
    return MV_TDERR;
  }
  if (0 == (decimalStr = json_getValue(obTest))) {
    fsm_sendFailure(FailureType_Failure_Other, _("Token data decimals value error"));
    return MV_TDERR;
  }
  sscanf((char *)decimalStr, "%ld", &decimals);

  // Is this the token list reset token?
  if ((0 == strncmp(tokenAddrStr, "00000000000000000000", 20)) && (0 == strncmp(ticker, "RESET", 5)) && (0 == chainId) && (0 == decimals)) {
    for (tokCtr=0; tokCtr<TOKENS_COUNT; tokCtr++) {
      memzero(&tokens[tokCtr], sizeof(TokenType));
    }
    return MV_TRESET;
  }

  // determine where token should go in token list
  for (tokCtr=0; tokCtr<TOKENS_COUNT; tokCtr++) {
    if (!tokens[tokCtr].validToken) {
        // fill in this slot
        break;
    }
  }

  if (tokCtr == TOKENS_COUNT) {
    return MV_TLISTFULL;
  } else {
    // add token to tokCtr position
    tokens[tokCtr].validToken = true;

    const char *pos = tokenAddrStr;
    for (int cctr=0; cctr<20; cctr++) {
      sscanf(pos, "%2hhx", &tokens[tokCtr].address[cctr]);
      pos += 2;
    }

    strcpy(tokens[tokCtr].ticker, " ");
    strncat(tokens[tokCtr].ticker, json_getValue(json_getProperty(jsonTV, "ticker")), 9);
    tokens[tokCtr].chain_id = (uint8_t)chainId;
    tokens[tokCtr].decimals = (uint8_t)decimals;

    //DEBUG_DISPLAY_VAL("addr", "%s", 21, hash[_ctr+12]);
    // char bf[41] = {0};
    // DEBUG_DISPLAY(tokens[tokCtr].address);
    // DEBUG_DISPLAY(tokens[tokCtr].ticker);
    // snprintf(bf, 40, "indx %3d chain %3d dec %3d", tokCtr, tokens[tokCtr].chain_id, tokens[tokCtr].decimals);
    // DEBUG_DISPLAY(bf);

    }

  return MV_STOKOK;
}

int main(int argc, char *argv[]) {
  const unsigned char tokStr[128] = "{\"address\": \"E41d2489571d322189246DaFA5ebDe1F4699F498\", \"ticker\": \"ZRX\", \"chainId\": 1, \"decimals\": 18}";
  evp_parse((const unsigned char *)tokStr);
  const TokenType *zrx = tokenByChainAddress(1, (const uint8_t*)"\xE4\x1d\x24\x89\x57\x1d\x32\x21\x89\x24\x6D\xaF\xA5\xeb\xDe\x1F\x46\x99\xF4\x98");
  printf("%s", zrx->ticker);

return EXIT_SUCCESS;
}
