#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "FuzzedDataProvider.h"
#include "fuzzer_temp_file.h"
#include "libxml/xmlreader.h"

void ignore(void* ctx, const char* msg, ...) {
    // Error handler to avoid spam of error messages from libxml parser.
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSetGenericErrorFunc(NULL, &ignore);

    FuzzedDataProvider provider;
    FuzzedDataProvider_Init(&provider, data, size);

    const int options = FuzzedDataProvider_ConsumeIntegralInRange(&provider, INT_MIN, INT_MAX);

    size_t encoding_size;
    char* encoding = FuzzedDataProvider_ConsumeRandomLengthString(&provider, 128, &encoding_size);

    size_t file_contents_size;
    uint8_t* file_contents = FuzzedDataProvider_ConsumeRemainingBytes(&provider, &file_contents_size);

    char* filename = fuzzer_get_tmpfile(file_contents, file_contents_size);

    xmlTextReaderPtr xmlReader = xmlReaderForFile(filename, encoding, options);

    const int kReadSuccessful = 1;
    while (xmlTextReaderRead(xmlReader) == kReadSuccessful) {
        xmlTextReaderNodeType(xmlReader);
        xmlTextReaderConstValue(xmlReader);
    }

    xmlFreeTextReader(xmlReader);
    fuzzer_release_tmpfile(filename);
    free(encoding);
    free(file_contents);

    return EXIT_SUCCESS;
}