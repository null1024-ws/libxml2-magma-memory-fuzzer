#include "FuzzedDataProvider.h"

void FuzzedDataProvider_Init(FuzzedDataProvider *provider, const uint8_t *data, size_t size) {
    provider->data_ptr_ = data;
    provider->remaining_bytes_ = size;
}

void FuzzedDataProvider_Advance(FuzzedDataProvider *provider, size_t num_bytes) {
    if (num_bytes > provider->remaining_bytes_)
        abort();

    provider->data_ptr_ += num_bytes;
    provider->remaining_bytes_ -= num_bytes;
}

uint8_t* FuzzedDataProvider_ConsumeBytes(FuzzedDataProvider *provider, size_t num_bytes, size_t *out_size) {
    num_bytes = (num_bytes < provider->remaining_bytes_) ? num_bytes : provider->remaining_bytes_;
    uint8_t* result = (uint8_t*)malloc(num_bytes);
    if (!result) abort();

    memcpy(result, provider->data_ptr_, num_bytes);
    FuzzedDataProvider_Advance(provider, num_bytes);

    *out_size = num_bytes;
    return result;
}

char* FuzzedDataProvider_ConsumeBytesAsString(FuzzedDataProvider *provider, size_t num_bytes) {
    size_t out_size;
    uint8_t* bytes = FuzzedDataProvider_ConsumeBytes(provider, num_bytes, &out_size);
    char* result = (char*)malloc(out_size + 1);
    if (!result) abort();

    memcpy(result, bytes, out_size);
    result[out_size] = '\0';
    free(bytes);
    return result;
}

int FuzzedDataProvider_ConsumeIntegralInRange(FuzzedDataProvider *provider, int min, int max) {
    if (min > max)
        abort();

    uint64_t range = (uint64_t)max - min;
    uint64_t result = 0;
    size_t offset = 0;

    while (offset < sizeof(int) * CHAR_BIT && (range >> offset) > 0 && provider->remaining_bytes_ != 0) {
        --provider->remaining_bytes_;
        result = (result << CHAR_BIT) | provider->data_ptr_[provider->remaining_bytes_];
        offset += CHAR_BIT;
    }

    if (range != UINT64_MAX)
        result = result % (range + 1);

    return (int)(min + result);
}

char* FuzzedDataProvider_ConsumeRandomLengthString(FuzzedDataProvider *provider, size_t max_length, size_t *out_size) {
    char* result = (char*)malloc(max_length + 1);
    if (!result) abort();

    size_t i = 0;
    for (; i < max_length && provider->remaining_bytes_ != 0; ++i) {
        char next = (char)provider->data_ptr_[0];
        FuzzedDataProvider_Advance(provider, 1);
        if (next == '\\' && provider->remaining_bytes_ != 0) {
            next = (char)provider->data_ptr_[0];
            FuzzedDataProvider_Advance(provider, 1);
            if (next != '\\')
                break;
        }
        result[i] = next;
    }

    result[i] = '\0';
    *out_size = i;
    return result;
}

uint8_t* FuzzedDataProvider_ConsumeRemainingBytes(FuzzedDataProvider *provider, size_t *out_size) {
    return FuzzedDataProvider_ConsumeBytes(provider, provider->remaining_bytes_, out_size);
}

char* FuzzedDataProvider_ConsumeRemainingBytesAsString(FuzzedDataProvider *provider, size_t *out_size) {
    return FuzzedDataProvider_ConsumeBytesAsString(provider, provider->remaining_bytes_);
}

int FuzzedDataProvider_ConsumeIntegral(FuzzedDataProvider *provider) {
    return FuzzedDataProvider_ConsumeIntegralInRange(provider, INT_MIN, INT_MAX);
}

bool FuzzedDataProvider_ConsumeBool(FuzzedDataProvider *provider) {
    return FuzzedDataProvider_ConsumeIntegralInRange(provider, 0, 1) == 1;
}

double FuzzedDataProvider_ConsumeProbability(FuzzedDataProvider *provider) {
    uint32_t value = (uint32_t)FuzzedDataProvider_ConsumeIntegralInRange(provider, 0, UINT32_MAX);
    return (double)value / (double)UINT32_MAX;
}

double FuzzedDataProvider_ConsumeFloatingPoint(FuzzedDataProvider *provider) {
    return FuzzedDataProvider_ConsumeFloatingPointInRange(provider, -DBL_MAX, DBL_MAX);
}

double FuzzedDataProvider_ConsumeFloatingPointInRange(FuzzedDataProvider *provider, double min, double max) {
    if (min > max)
        abort();

    double range = max - min;
    double result = min + range * FuzzedDataProvider_ConsumeProbability(provider);
    return result;
}