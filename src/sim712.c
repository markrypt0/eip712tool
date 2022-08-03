
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
#include "keepkey/firmware/eip712.h"
#include "keepkey/firmware/tiny-json.h"

// eip712tool specific defines
//#define DISPLAY_INTERMEDIATES 1     // define this to display intermediate hash results
#define BUFSIZE             4000
#define PRIMETYPE_BUFSIZE    80
#define DOMAIN_BUFSIZE      300
#define MESSAGE_BUFSIZE     2000
#define TYPES_BUFSIZE       2000                    // This will be used as the types,values concatenated string
// Example
// DEBUG_DISPLAY_VAL("sig", "sig %s", 65, resp->signature.bytes[ctr]);


int parseJsonName(char *name, char *jsonMsg, char *parsedJson, unsigned maxParsedSize) {
    char *secStart, *brack, *brackTest, *typeEnd;
    unsigned brackLevel, parsedSize;
    
    if (NULL == (secStart = strstr(jsonMsg, name))) {
        printf("%s not found!\n", name);
        return 0;
    }

    if (0 != strncmp(name, "\"primaryType\"", strlen(name))) {
        brackLevel = 1;
        brack = strstr(secStart, "{");
        while (brackLevel > 0) {
            brackTest = strpbrk(brack+1, "{}");
            if ('{' == *brackTest) {
                brackLevel++;
            } else if ('}' == *brackTest) {
                brackLevel--;
            } else if (0 == brackTest) {
                printf("can't parse %s value!\n", name);
                return 0;
            }
            brack = brackTest;
        }

        parsedSize = brack-secStart+1;
        if (parsedSize+2 > maxParsedSize) {
            printf("parsed size is %u, larger than max allowed %u\n", parsedSize, maxParsedSize);
            return 0;
        }

        // json parser wants to see string json string enclosed in braces, i.e., "{ ... }"
        strcat(parsedJson, "{\0");
        strncpy(&parsedJson[strlen(parsedJson)], secStart, parsedSize);
        strcat(parsedJson, "}\0");

    } else {
        // primary type parsing is different
        typeEnd = strpbrk(secStart, ",\n");
        if (typeEnd == NULL) {
            printf("parsed size of primaryType is NULL!\n");
            return 0;
        }
        if (PRIMETYPE_BUFSIZE < (parsedSize = typeEnd-secStart)) {
            printf("primaryType parsed size is %u, greater than max size allowed %u\n", parsedSize, PRIMETYPE_BUFSIZE);
            return 0;
        }
        // json parser wants to see string json string enclosed in braces, i.e., "{ ... }"

        strcat(parsedJson, "{\0");
        strncpy(&parsedJson[strlen(parsedJson)], secStart, parsedSize);
        if (parsedJson[parsedSize] == ',') {
            parsedJson[parsedSize-1] = 0;
        }
        strcat(parsedJson, "}\0");
    }
    return 1;
}



int main(int argc, char *argv[]) {

    json_t const* json;
    json_t const* jsonT;
    json_t const* jsonV;
    json_t const* jsonPT;

    static char jsonStr[BUFSIZE] = {'\0'};
    static char typesJsonStr[TYPES_BUFSIZE] = {'\0'};
    static char primaryTypeJsonStr[PRIMETYPE_BUFSIZE] = {'\0'};
    static char domainJsonStr[DOMAIN_BUFSIZE] = {'\0'};
    static char messageJsonStr[MESSAGE_BUFSIZE] = {'\0'};
    int chr, ctr;
    FILE *f; 

    // get file from cmd line or open default
    if (NULL == (f = fopen(argv[1], "r"))) {
        printf("USAGE: ./sim712.exe <filename>\n  Where <filename> is a properly formatted EIP-712 message.\n");
        return 0;
    }

    // read in the json file
    ctr=0;
    chr = fgetc(f);
    while (chr != EOF && ctr < BUFSIZE-1) {
        jsonStr[ctr++] = chr;
        chr = fgetc(f);
    }
    
    // parse out the 4 sections
    parseJsonName("\"types\"", jsonStr, typesJsonStr, TYPES_BUFSIZE);
    //printf("%s\n\n", typesJsonStr);
    parseJsonName("\"domain\"", jsonStr, domainJsonStr, DOMAIN_BUFSIZE);
    //printf("%s\n\n", domainJsonStr);
    parseJsonName("\"message\"", jsonStr, messageJsonStr, MESSAGE_BUFSIZE);
    //printf("%s\n\n", messageJsonStr);
    parseJsonName("\"primaryType\"", jsonStr, primaryTypeJsonStr, MESSAGE_BUFSIZE);
    //printf("%s\n\n", primaryTypeJsonStr);

    json_t mem[JSON_OBJ_POOL_SIZE];
    json = json_create(jsonStr, mem, sizeof mem / sizeof *mem );
    if ( !json ) {
        printf("Error json create json, errno = %d.", errno);
        return EXIT_FAILURE;
    }

    const json_t *respair = json_getProperty(json, "results");
    if (0 != respair) {
        respair = json_getChild(respair);
        const char *resval = json_getValue(respair);
        while (0 != strncmp(json_getName(respair), "test_data", strlen(json_getName(respair)))) {
            respair = json_getSibling(respair);
            if (respair == 0) {
                resval = "NO TEST DATA FILE NAME";
                break;
            } else {
                resval = json_getValue(respair);
            }
        }
        printf(BOLDRED "\nTest data file %s.json\n" RESET, resval);
    } else {
        printf(BOLDRED "\nNo \"results\" entry in json file" RESET);
    }

    // encode domain separator

    json_t memTypes[JSON_OBJ_POOL_SIZE];
    json_t memVals[JSON_OBJ_POOL_SIZE];
    json_t memPType[4];
    jsonT = json_create(typesJsonStr, memTypes, sizeof memTypes / sizeof *memTypes );
    jsonV = json_create(domainJsonStr, memVals, sizeof memVals / sizeof *memVals );
    if ( !jsonT ) {
        printf("Error json create jsonT, errno = %d.", errno);
        return EXIT_FAILURE;
    }
    if ( !jsonV ) {
        printf("Error json create jsonV, errno = %d.", errno);
        return EXIT_FAILURE;
    }

    uint8_t domainSeparator[32];
    encode(jsonT, jsonV, "EIP712Domain", domainSeparator);
    DEBUG_DISPLAY_VAL(BOLDGREEN "domainSeparator" RESET, "hash %s    ", 65, domainSeparator[ctr]);

    respair = json_getProperty(json, "results");
    if (0 != respair) {
        respair = json_getChild(respair);
        const char *resval = json_getValue(respair);
        while (0 != strncmp(json_getName(respair), "domain_separator_hash", strlen(json_getName(respair)))) {
            respair = json_getSibling(respair);
            if (respair == 0) {
                resval = "NOT FOUND IN TEST VECTOR FILE";
                break;
            } else {
                resval = json_getValue(respair);
            }
        }
        printf("Should be %s\n", resval);
    }

    // encode primaryType type

    jsonV = json_create(messageJsonStr, memVals, sizeof memVals / sizeof *memVals );
    jsonPT = json_create(primaryTypeJsonStr, memPType, sizeof memPType / sizeof *memPType );
    if ( !jsonV ) {
        printf("Error json create second jsonV, errno = %d.", errno);
        return EXIT_FAILURE;
    }
    if ( !jsonPT) {
        printf("Error json create jsonPT, errno = %d.", errno);
        return EXIT_FAILURE;
    }

    uint8_t msgHash[32];
    const char *primeType = json_getValue(json_getProperty(jsonPT, "primaryType"));

    if (0 == strncmp(primeType, "EIP712Domain", strlen(primeType))) {
        printf("primary type is EIP712Domain, message hash is NULL\n");
    } else if (2 == encode(jsonT, jsonV, primeType, msgHash)) {
        printf("message hash is NULL\n");
    } else {
        DEBUG_DISPLAY_VAL(BOLDGREEN "message" RESET, "hash %s    ", 65, msgHash[ctr]);
    }
    respair = json_getProperty(json, "results");
    if (0 != respair) {
        respair = json_getChild(respair);
        const char *resval = json_getValue(respair);
        while (0 != strncmp(json_getName(respair), "message_hash", strlen(json_getName(respair)))) {
            respair = json_getSibling(respair);
            if (respair == 0) {
                resval = "NOT FOUND IN TEST VECTOR FILE";
                break;
            } else {
                resval = json_getValue(respair);
            }
        }
        printf("Should be %s\n", resval);
    }

    return EXIT_SUCCESS;
}
