
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


/* eip712 data rules:
    int values must be hex. Negative sign indicates negative value, e.g., -5, -8a67 
        Note: Do not prefix ints or uints with 0x
    All hex and byte strings must be big-endian
    Byte strings and address should be prefixed by 0x
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./tiny-json.h"
#define USE_KECCAK 1
#include "./sha3.h"
#include "./memzero.h"

#define BUFSIZE             4000
#define JSON_OBJ_POOL_SIZE  128
#define STRBUFSIZE          511
#define MAX_USERDEF_TYPES   10      // This is max number of user defined type allowed

// Example
// DEBUG_DISPLAY_VAL("sig", "sig %s", 65, resp->signature.bytes[ctr]);
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

/*
encodable types
bytes1 to bytes32
uint8 to uint256 
bool 
address

bytes 
string 

arrays 
structs 
*/

typedef enum {
    NOT_ENCODABLE = 0,
    ADDRESS,
    STRING,
    UINT,
    INT,
    BYTES,
    BYTES_N,
    BOOL,
    UDEF_TYPE,
    PREV_USERDEF,
    TOO_MANY_UDEFS
} basicType;

static int entryLevel = 0;
json_t const* json;
const char *udefList[MAX_USERDEF_TYPES] = {0};

int encodableType(const char *typeStr) {
    int ctr;

    if (0 == strncmp(typeStr, "address", sizeof("address")-1)) {
        return ADDRESS;
    }
    if (0 == strncmp(typeStr, "string", sizeof("string")-1)) {
        return STRING;
    }
    if (0 == strncmp(typeStr, "int", sizeof("int")-1)) {
        // This could be 'int8', 'int16', ..., 'int256'
        return INT;
    }
    if (0 == strncmp(typeStr, "uint", sizeof("uint")-1)) {
        // This could be 'uint8', 'uint16', ..., 'uint256'
        return UINT;
    }
    if (0 == strncmp(typeStr, "bytes", sizeof("bytes")-1)) {
        // This could be 'bytes', 'bytes1', ..., 'bytes32'
        if (0 == strcmp(typeStr, "bytes")) {
            return BYTES;
        } else {
            // parse out the length val
            uint8_t byteTypeSize = (uint8_t)(strtol((typeStr+5), NULL, 10));
            if (byteTypeSize > 32) {
                return NOT_ENCODABLE;
            } else {
                return BYTES_N;
            }
        }
    }
    if (0 == strcmp(typeStr, "bool")) {
        return BOOL;
    }

    // See if type already defined. If so, skip, otherwise add it to list
    for(ctr=0; ctr<MAX_USERDEF_TYPES; ctr++) {
        char typeNoArrTok[33] = {0};

        strncpy(typeNoArrTok, typeStr, sizeof(typeNoArrTok)-1);
        strtok(typeNoArrTok, "[");  // eliminate the array tokens if there

        if (udefList[ctr] != 0) {
            if (0 == strncmp(udefList[ctr], typeNoArrTok, strlen(udefList[ctr])-strlen(typeNoArrTok))) {
                return PREV_USERDEF;
            }
            else;

        } else {
            udefList[ctr] = typeStr;
            return UDEF_TYPE;
        }
    }
    if (ctr == MAX_USERDEF_TYPES) {
        printf("could not add %d %s\n", ctr, typeStr);
        return TOO_MANY_UDEFS;
    }

    return NOT_ENCODABLE; // not encodable
}

/*
    Entry: 
            jType points to eip712 json type structure to parse
            typeStr points to caller allocated, zeroized string buffer of size STRBUFSIZE+1
    Exit:  
            typeStr points to hashable type string

    NOTE: reentrant!
*/
int parseType(const json_t *jType, char *typeStr) {
    json_t const *tarray, *pairs;
    char append[STRBUFSIZE+1] = {0};
    int encTest;
    const char *typeType = NULL;

    strncat(typeStr, json_getName(jType), STRBUFSIZE - strlen((const char *)typeStr));
    strncat(typeStr, "(", STRBUFSIZE - strlen((const char *)typeStr));

    tarray = json_getChild(jType);
    while (tarray != 0) {
        pairs = json_getChild(tarray);
        // should be type JSON_TEXT
        if (pairs->type != JSON_TEXT) {
            printf("type %d not printable\n", pairs->type);
        } else {
            typeType = json_getValue(json_getSibling(pairs));
            encTest = encodableType(typeType);
            if (encTest == UDEF_TYPE) {
                printf("user defined type %s\n", typeType);
                //This is a user-defined type, parse it and append later
                if (']' == typeType[strlen(typeType)-1]) {
                    // array of structs. To parse name, remove array tokens.
                    char typeNoArrTok[33] = {0};
                    strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok)-1);
                    if (strlen(typeNoArrTok) < strlen(typeType)) {
                        printf("ERROR: UDEF array type name is >32: %s, %lu\n", typeType, strlen(typeType));
                        return 0;
                    }
                    printf("udef basic type %s\n", strtok(typeNoArrTok, "["));
                    parseType(json_getProperty(json_getProperty(json, "types"), strtok(typeNoArrTok, "]")), append);
                } else {
                parseType(json_getProperty(json_getProperty(json, "types"), typeType), append);
                }
            } else if (encTest == TOO_MANY_UDEFS) {
                printf ("too many user defined types!");
                return 0;
            }             
            strncat(typeStr, json_getValue(json_getSibling(pairs)), STRBUFSIZE - strlen((const char *)typeStr));
            strncat(typeStr, " ", STRBUFSIZE - strlen((const char *)typeStr));
            strncat(typeStr, json_getValue(pairs), STRBUFSIZE - strlen((const char *)typeStr));
            strncat(typeStr, ",", STRBUFSIZE - strlen((const char *)typeStr));
            
        }
        tarray = json_getSibling(tarray);
    }
    // typeStr ends with a ',' unless there are no parameters to the type.
    if (typeStr[strlen(typeStr)-1] == ',') {
        // replace last comma with a paren
        typeStr[strlen(typeStr)-1] = ')';
    } else {
        // append paren, there are no parameters
        strncat(typeStr, ")", STRBUFSIZE - 1);
    }
    if (strlen(append) >= 0) {
        strncat(typeStr, append, STRBUFSIZE - strlen((const char *)append));
    }

    return 1;
}

#define ADDRESS_SIZE    42
int encAddress(const char *string, uint8_t *encoded) {
    unsigned ctr;
    char byteStrBuf[3] = {0};

    if (ADDRESS_SIZE < strlen(string)) {
        printf("ERROR: Address string too big %lu\n", strlen(string));
        return 0;
    }

    for (ctr=0; ctr<12; ctr++) {
        encoded[ctr] = '\0';
    }
    for (ctr=12; ctr<32; ctr++) {
        strncpy(byteStrBuf, &string[2*((ctr-12))+2], 2);
        encoded[ctr] = (uint8_t)(strtol(byteStrBuf, NULL, 16));
    }
    DEBUG_DISPLAY_VAL("address", "addr %s", 65, encoded[ctr]);
    return 1;
}

int encString(const char *string, uint8_t *encoded) {
    struct SHA3_CTX strCtx;

    printf("string to be hashed: %s\n", string);
    sha3_256_Init(&strCtx);
    sha3_Update(&strCtx, (const unsigned char *)string, (size_t)strlen(string));
    keccak_Final(&strCtx, encoded);
    DEBUG_DISPLAY_VAL("string", "hash %s", 65, encoded[ctr]);
    return 1;
}

int encodeBytes(const char *string, uint8_t *encoded) {
    struct SHA3_CTX byteCtx;
    const char *valStrPtr = string+2;
    uint8_t valByte[1];
    char byteStrBuf[3] = {0};

    sha3_256_Init(&byteCtx);
    while (*valStrPtr != '\0') {
        strncpy(byteStrBuf, valStrPtr, 2);
        valByte[0] = (uint8_t)(strtol(byteStrBuf, NULL, 16));
        sha3_Update(&byteCtx, 
                    (const unsigned char *)valByte, 
                    (size_t)sizeof(uint8_t));
        valStrPtr+=2;
    }
    keccak_Final(&byteCtx, encoded);
    DEBUG_DISPLAY_VAL("bytes", "hash %s", 65, encoded[ctr]);
    return 1;
}

#define MAX_ENCBYTEN_SIZE   66
int encodeBytesN(const char *typeT, const char *string, uint8_t *encoded) {
    char byteStrBuf[3] = {0};
    unsigned ctr;

    if (MAX_ENCBYTEN_SIZE < strlen(string)) {
        printf("ERROR: bytesN string too big %lu\n", strlen(string));
        return 0;
    }

    // parse out the length val
    uint8_t byteTypeSize = (uint8_t)(strtol((typeT+5), NULL, 10));
    if (32 < byteTypeSize) {
        printf("byteN size error, N>32:%u/n", byteTypeSize);
        return(0);
    }
    for (ctr=0; ctr<32; ctr++) {
        // zero padding
        encoded[ctr] = 0;
    }
    unsigned zeroFillLen = 32 - ((strlen(string)-2/* skip '0x' */)/2);
    printf("bytes%u: %s, zf=%u\n", byteTypeSize, string, zeroFillLen);
    // bytesN are zero padded on the right
    for (ctr=zeroFillLen; ctr<32; ctr++) {
        strncpy(byteStrBuf, &string[2+2*(ctr-zeroFillLen)], 2);
        encoded[ctr-zeroFillLen] = (uint8_t)(strtol(byteStrBuf, NULL, 16));
    }
    DEBUG_DISPLAY_VAL("bytesN", "val  %s", 65, encoded[ctr]);

    return 1;
}

/*
    Entry: 
            jType points to eip712 json type structure to parse
            nextVal points to the next value to encode
            msgCtx points to caller allocated hash context to hash encoded values into.
    Exit:  
            msgCtx points to current final hash context

    NOTE: reentrant!
*/
int parseVals(const json_t *jType, const json_t *nextVal, struct SHA3_CTX *msgCtx) {
    json_t const *tarray, *pairs, *walkVals;
    int ctr;
    const char *typeName = NULL, *typeType = NULL;
    uint8_t encBytes[32] = {0};     // holds the encrypted bytes for the message
    const char *valStr;
    char byteStrBuf[3] = {0};
    struct SHA3_CTX valCtx = {0};   // local hash context

    tarray = json_getChild(jType);
    while (tarray != 0) {
        pairs = json_getChild(tarray);
        // should be type JSON_TEXT
        if (pairs->type != JSON_TEXT) {
            printf("type %d not printable\n", pairs->type);
        } else {
            typeName = json_getValue(pairs);
            typeType = json_getValue(json_getSibling(pairs));
            walkVals = nextVal;
            while (0 != walkVals) {
                if (0 == strcmp(json_getName(walkVals), typeName)) {
                    valStr = json_getValue(walkVals);
                    break;
                } else {
                    // keep looking for val
                    walkVals = json_getSibling(walkVals);
                }
            }
            if (walkVals == 0) {
                printf("error: value for \"%s\" not found!\n", typeName);

            } else {

                if (0 == strncmp("address", typeType, strlen("address")-1)) {
                    if (']' == typeType[strlen(typeType)-1]) {
                        // array of addresses
                        json_t const *addrVals = json_getChild(walkVals);
                        sha3_256_Init(&valCtx);     // hash of concatenated encoded strings
                        while (0 != addrVals) {
                            // just walk the string values assuming, for fixed sizes, all values are there.
                            printf("  address ");
                            encAddress(json_getValue(addrVals), encBytes);
                            sha3_Update(&valCtx, (const unsigned char *)encBytes, 32);
                            addrVals = json_getSibling(addrVals);
                        }
                        keccak_Final(&valCtx, encBytes);
                    } else {
                        encAddress(valStr, encBytes);
                    }
                    DEBUG_DISPLAY_VAL("address final", "hash %s", 65, encBytes[ctr]);



                } else if (0 == strncmp("string", typeType, strlen("string")-1)) {
                    if (']' == typeType[strlen(typeType)-1]) {
                        // array of strings
                        json_t const *stringVals = json_getChild(walkVals);
                        uint8_t strEncBytes[32];
                        sha3_256_Init(&valCtx);     // hash of concatenated encoded strings
                        while (0 != stringVals) {
                            // just walk the string values assuming, for fixed sizes, all values are there.
                            printf("  array ");
                            encString(json_getValue(stringVals), strEncBytes);
                            sha3_Update(&valCtx, (const unsigned char *)strEncBytes, 32);
                            stringVals = json_getSibling(stringVals);
                        }
                        keccak_Final(&valCtx, encBytes);
                    } else {
                        encString(valStr, encBytes);
                    }
                    DEBUG_DISPLAY_VAL("string final", "hash %s", 65, encBytes[ctr]);

                } else if ((0 == strncmp("uint", typeType, strlen("uint")-1)) ||
                           (0 == strncmp("int", typeType, strlen("int")-1))) {

                    if (']' == typeType[strlen(typeType)-1]) {
                        printf("ERROR: INT and UINT arrays not yet implemented\n");
                        return 0;
                    } else {
                        uint8_t intType = 0;    // 0 is uint, 1 is int
                        uint8_t negInt = 0;     // 0 is positive, 1 is negative
                        if (0 == strncmp("int", typeType, strlen("int")-1)) {
                            intType = 1;
                            if (*valStr == '-') {
                                negInt = 1;
                            }
                        }
                        // parse out the length val
                        uint16_t intuTypeSize = (uint16_t)(strtol((typeType+4-intType), NULL, 10));

                        printf("intu%u: %s typeType %s, intType %u, negint %u, typesizstr %s\n", intuTypeSize, valStr, typeType, intType, negInt, (typeType+4-intType));
                            for (ctr=0; ctr<32; ctr++) {
                                if (negInt) {
                                    // sign extend negative values
                                    encBytes[ctr] = 0xFF;
                                } else {
                                    // zero padding for positive
                                    encBytes[ctr] = 0;
                                }
                            }
                        unsigned zeroFillLen = 32 - ((strlen(valStr)-negInt)/2+1);
                        //unsigned zeroFillLen = 32 - intuTypeSize/8;
                        printf("intu%u: valstr %s, zf=%u\n", intuTypeSize, valStr, zeroFillLen);
                        for (ctr=zeroFillLen; ctr<32; ctr++) {
                            strncpy(byteStrBuf, &valStr[2*(ctr-(zeroFillLen))], 2);
                            encBytes[ctr] = (uint8_t)(strtol(byteStrBuf, NULL, 16));
                        }

                        DEBUG_DISPLAY_VAL("uintN", "val  %s", 65, encBytes[ctr]);
                    }

                } else if (0 == strncmp("bytes", typeType, strlen("bytes"))) {
                    if (']' == typeType[strlen(typeType)-1]) {
                        printf("ERROR: bytesN arrays not yet implemented\n");
                        return 0;
                    } else {
                        // This could be 'bytes', 'bytes1', ..., 'bytes32'
                        if (0 == strcmp(typeType, "bytes")) {
                            printf("bytes to be hashed: %s\n", valStr+2);
                            encodeBytes(valStr, encBytes);

                        } else {
                            encodeBytesN(typeType, valStr, encBytes);
                        }
                    }

                } else if (0 == strncmp("bool", typeType, strlen(typeType))) {
                    if (']' == typeType[strlen(typeType)-1]) {
                        printf("ERROR: bool arrays not yet implemented\n");
                        return 0;
                    } else {
                        printf("bool: %s\n", valStr);
                        for (ctr=0; ctr<32; ctr++) {
                            // leading zeros in bool
                            encBytes[ctr] = 0;
                        }
                        if (0 == strncmp(valStr, "true", sizeof("true"))) {
                            encBytes[31] = 0x01;
                        }
                        DEBUG_DISPLAY_VAL("bool", "val  %s", 65, encBytes[ctr]);
                    }
 
                } else {
                    // encode user defined type
                    char encSubTypeStr[STRBUFSIZE+1] = {0};
                    // clear out the user-defined types list
                    for(ctr=0; ctr<MAX_USERDEF_TYPES; ctr++) {
                        udefList[ctr] = NULL;
                    }  
                                            
                    char typeNoArrTok[33] = {0};
                    // need to get typehash of type first
                    if (']' == typeType[strlen(typeType)-1]) {
                        // array of structs. To parse name, remove array tokens.
                        strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok)-1);
                        if (strlen(typeNoArrTok) < strlen(typeType)) {
                            printf("ERROR: UDEF array type name is >32: %s, %lu\n", typeType, strlen(typeType));
                            return 0;
                        }
                        printf("udef basic type %s\n", strtok(typeNoArrTok, "["));
                        parseType(json_getProperty(json_getProperty(json, "types"), strtok(typeNoArrTok, "]")), encSubTypeStr);
                    } else {
                        parseType(json_getProperty(json_getProperty(json, "types"), typeType), encSubTypeStr);
                    }
                    printf("udef typehash string %s\n", encSubTypeStr);
                    sha3_256_Init(&valCtx);
                    sha3_Update(&valCtx, (const unsigned char *)encSubTypeStr, (size_t)strlen(encSubTypeStr));
                    keccak_Final(&valCtx, encBytes);
                    DEBUG_DISPLAY_VAL(typeType, "hash %s", 65, encBytes[ctr]);


                    if (']' == typeType[strlen(typeType)-1]) {



                        // array of udefs
                        struct SHA3_CTX eleCtx = {0};   // local hash context
                        struct SHA3_CTX arrCtx = {0};   // array elements hash context
                        uint8_t eleHashBytes[32];
                        uint8_t typeHashBytes[32];

                        sha3_256_Init(&valCtx);
                        sha3_Update(&valCtx, (const unsigned char *)typeHashBytes, (size_t)sizeof(typeHashBytes));

                        sha3_256_Init(&arrCtx);

                        json_t const *udefVals = json_getChild(walkVals);
                        while (0 != udefVals) {
                            printf("  udef array ");
                            sha3_256_Init(&eleCtx);
                            sha3_Update(&eleCtx, (const unsigned char *)encBytes, 32);
                            parseVals(
                                  json_getProperty(json_getProperty(json, "types"), strtok(typeNoArrTok, "]")),
                                  json_getChild(udefVals),                // where to get the values
                                  &eleCtx                                 // encode hash happens in parse, this is the return
                                  );  
                            keccak_Final(&eleCtx, eleHashBytes);
                            DEBUG_DISPLAY_VAL(typeType, " array element hash %s", 65, eleHashBytes[ctr]);

                            sha3_Update(&arrCtx, (const unsigned char *)eleHashBytes, 32);
                            // just walk the udef values assuming, for fixed sizes, all values are there.
                            udefVals = json_getSibling(udefVals);
                        } 
                        keccak_Final(&arrCtx, encBytes);
                        DEBUG_DISPLAY_VAL(typeType, "array hash %s", 65, encBytes[ctr]);

                    } else {
                        sha3_256_Init(&valCtx);
                        sha3_Update(&valCtx, (const unsigned char *)encBytes, (size_t)sizeof(encBytes));
                        if (!(JSON_OBJ == json_getType(nextVal) || JSON_ARRAY == json_getType(nextVal))) {
                            printf("json type error %u in udef type %s\n", json_getType(nextVal), typeType);
                    }
                        parseVals(
                                  json_getProperty(json_getProperty(json, "types"), typeType),
                                  json_getChild(walkVals),                // where to get the values
                                  &valCtx           // val hash happens in parse, this is the return
                                  );    
                        keccak_Final(&valCtx, encBytes);
                        DEBUG_DISPLAY_VAL(typeType, "hash %s", 65, encBytes[ctr]);
                    }                         
                }
            }
            // hash encoded bytes to final context
            sha3_Update(msgCtx, (const unsigned char *)encBytes, 32);
        }
        printf("\n");
        tarray = json_getSibling(tarray); 
    }
    return 1;
}


int encode(const json_t *eip712Json, const char *typeS, uint8_t *hashRet) {
    int ctr;
    char encTypeStr[STRBUFSIZE+1] = {0};
    uint8_t typeHash[32];
    struct SHA3_CTX finalCtx = {0};

    // clear out the user-defined types list
    for(ctr=0; ctr<MAX_USERDEF_TYPES; ctr++) {
        udefList[ctr] = NULL;
    }  

    parseType(json_getProperty(json_getProperty(eip712Json, "types"), typeS),   // e.g., "EIP712Domain"
              encTypeStr                                                        // will return with typestr
              );                                                            
    printf("%lu %s\n", strlen(encTypeStr), encTypeStr);

    sha3_256_Init(&finalCtx);
    sha3_Update(&finalCtx, (const unsigned char *)encTypeStr, (size_t)strlen(encTypeStr));
    keccak_Final(&finalCtx, typeHash);
    DEBUG_DISPLAY_VAL(typeS, "hash %s", 65, typeHash[ctr]);

    // They typehash must be the first message of the final hash, this is the start 
    sha3_256_Init(&finalCtx);
    sha3_Update(&finalCtx, (const unsigned char *)typeHash, (size_t)sizeof(typeHash));

    if (0 == strncmp(typeS, "EIP712Domain", sizeof("EIP712Domain"))) {
        parseVals(json_getProperty(json_getProperty(eip712Json, "types"), typeS),   // e.g., "EIP712Domain" 
              json_getChild(json_getProperty( json, "domain" )),                // where to get the values
              &finalCtx                                                         // val hash happens in parse, this is the return
              );
    } else {
        // This is the message value encoding
        // printf ("null message type %u\n", json_getType(json_getChild(json_getProperty( json, "message" ))));
        if (NULL == json_getChild(json_getProperty( json, "message" ))) {
            // return 2 for null message hash (this is a legal value)
            return 2;
        }
        parseVals(json_getProperty(json_getProperty(eip712Json, "types"), typeS),   // e.g., "EIP712Domain" 
              json_getChild(json_getProperty( json, "message" )),                // where to get the values
              &finalCtx                                                         // val hash happens in parse, this is the return
              );
    }

    keccak_Final(&finalCtx, hashRet);
    // clear typeStr
    memzero(encTypeStr, sizeof(encTypeStr));

    return 1;
}

int parseJson(const json_t *curProp) {
    entryLevel++;
    printf("RECURSE LEVEL %d\n", entryLevel);
    while (curProp != 0) {
        printf("type: %s, ", json_getName(curProp));
        if (curProp->type == JSON_OBJ || curProp->type == JSON_ARRAY) {
            parseJson(json_getChild(curProp));
        }

        if (curProp->type == JSON_TEXT || curProp->type == JSON_INTEGER) {
            printf("value: %s\n", json_getValue(curProp));
        } else {
            printf("value %d not printable\n", curProp->type);
        }
        curProp = json_getSibling(curProp);
    }

    entryLevel--;
    return 1;
}

int main(int argc, char *argv[]) {
    static char jsonStr[BUFSIZE] = {'\0'};
    int chr, ctr;
    FILE *f; 



    // get file from cmd line or open default
    if (NULL == (f = fopen(argv[1], "r"))) {
        f = fopen("typed_data.json", "r");
    }

    ctr=0;
    chr = fgetc(f);
    while (chr != EOF && ctr < BUFSIZE-1) {
        jsonStr[ctr++] = chr;
        chr = fgetc(f);
    }
    jsonStr[ctr] = '\0';

    json_t mem[JSON_OBJ_POOL_SIZE];
    json = json_create(jsonStr, mem, sizeof mem / sizeof *mem );
    if ( !json ) {
        printf("Error json create, errno = %d.", errno);
        return EXIT_FAILURE;
    }

    // encode domain separator
    // uint8_t domainSeparator[32];
    // encode(json, "EIP712Domain", domainSeparator);
    // DEBUG_DISPLAY_VAL("domainSeparator", "hash %s", 65, domainSeparator[ctr]);

    // encode primaryType type
    uint8_t msgHash[32];
    const char *primeType = json_getValue(json_getProperty(json, "primaryType"));
    if (0 == strncmp(primeType, "EIP712Domain", strlen(primeType))) {
        printf("primary type is EIP712Domain, message hash is NULL\n");
    } else if (2 == encode(json, primeType, msgHash)) {
        printf("message hash is NULL\n");
    } else {
        DEBUG_DISPLAY_VAL("message", "hash %s", 65, msgHash[ctr]);
    }

    return EXIT_SUCCESS;
}
