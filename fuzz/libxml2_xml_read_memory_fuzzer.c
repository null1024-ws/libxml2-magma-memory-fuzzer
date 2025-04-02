/* Copyright 2015 The Chromium Authors.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libxml/parser.h"
#include "libxml/xmlsave.h"

void ignore(void* ctx, const char* msg, ...) {
    // Error handler to suppress libxml error messages.
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSetGenericErrorFunc(NULL, &ignore);

    // Convert data to a string.
    char* data_string = (char*)malloc(size + 1);
    if (!data_string) {
        return 0;
    }
    memcpy(data_string, data, size);
    data_string[size] = '\0';

    // Compute a hash-based option value.
    size_t data_hash = 0;
    for (size_t i = 0; i < size; i++) {
        data_hash = data_hash * 31 + data[i];
    }
    int max_option_value = 2147483647; // INT_MAX
    int random_option_value = data_hash % max_option_value;

    // Disable XML_PARSE_HUGE to avoid stack overflow.
    random_option_value &= ~XML_PARSE_HUGE;
    int options[] = {0, random_option_value};

    for (size_t i = 0; i < 2; i++) {
        int option_value = options[i];
        
        xmlDocPtr doc = xmlReadMemory(data_string, size, "noname.xml", NULL, option_value);
        if (doc) {
            xmlBufferPtr buf = xmlBufferCreate();
            assert(buf);
            xmlSaveCtxtPtr ctxt = xmlSaveToBuffer(buf, NULL, 0);
            xmlSaveDoc(ctxt, doc);
            xmlSaveClose(ctxt);
            xmlFreeDoc(doc);
            xmlBufferFree(buf);
        }
    }

    free(data_string);
    return 0;
}

