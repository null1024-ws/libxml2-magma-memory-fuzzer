#ifndef LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_
#define LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <float.h>

typedef struct {
    const uint8_t *data_ptr_;
    size_t remaining_bytes_;
} FuzzedDataProvider;

void FuzzedDataProvider_Init(FuzzedDataProvider *provider, const uint8_t *data, size_t size);
void FuzzedDataProvider_Advance(FuzzedDataProvider *provider, size_t num_bytes);
uint8_t* FuzzedDataProvider_ConsumeBytes(FuzzedDataProvider *provider, size_t num_bytes, size_t *out_size);
char* FuzzedDataProvider_ConsumeBytesAsString(FuzzedDataProvider *provider, size_t num_bytes);
int FuzzedDataProvider_ConsumeIntegralInRange(FuzzedDataProvider *provider, int min, int max);
char* FuzzedDataProvider_ConsumeRandomLengthString(FuzzedDataProvider *provider, size_t max_length, size_t *out_size);
uint8_t* FuzzedDataProvider_ConsumeRemainingBytes(FuzzedDataProvider *provider, size_t *out_size);
char* FuzzedDataProvider_ConsumeRemainingBytesAsString(FuzzedDataProvider *provider, size_t *out_size);
int FuzzedDataProvider_ConsumeIntegral(FuzzedDataProvider *provider);
bool FuzzedDataProvider_ConsumeBool(FuzzedDataProvider *provider);
double FuzzedDataProvider_ConsumeProbability(FuzzedDataProvider *provider);
double FuzzedDataProvider_ConsumeFloatingPoint(FuzzedDataProvider *provider);
double FuzzedDataProvider_ConsumeFloatingPointInRange(FuzzedDataProvider *provider, double min, double max);

#endif // LLVM_FUZZER_FUZZED_DATA_PROVIDER_H_