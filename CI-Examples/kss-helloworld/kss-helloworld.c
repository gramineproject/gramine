#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "sgx_arch.h"

#define MAX_DIGITS (256ULL) // Should be more than enough to contain all buffers

static void blob2hex(const void* input, size_t len, char* output) {
    static const char digits[] = "0123456789abcdef";
    for(size_t i=0;i<len;i++) {
        uint8_t byte = *((uint8_t *) input + i);
        output[2*i] = digits[byte >> 4];
        output[2*i+1] = digits[byte & 0xf];
    }
    output[2*len + 1] = 0;
}

int main(void) {
    char print_buffer[MAX_DIGITS];
    FILE* attestation_type_fd = NULL;
    FILE* report_fd = NULL;
    sgx_report_t report;

    attestation_type_fd = fopen("/dev/attestation/attestation_type", "rb");
    if(attestation_type_fd == NULL) {
        fprintf(stderr, "Failed to open attestation type handle\n");
        return 1;
    }
    if(fread(print_buffer, 1, sizeof(print_buffer), attestation_type_fd) < 0) {
        fprintf(stderr, "Failed to read attestation type\n");
        return 2;
    }
    if(strcmp(print_buffer, "none") == 0) {
        fprintf(stderr, "Must be built with remote attestation\n");
        return 3;
    }
    fclose(attestation_type_fd);

    // We only care about this enclave's attributes, so we omit report data and target info
    report_fd = fopen("/dev/attestation/report", "rb");
    if(report_fd == NULL) {
        fprintf(stderr, "Failed to open report handle\n");
        return 4;
    }
    if(fread(&report, sizeof(report), 1, report_fd) <= 0) {
        fprintf(stderr, "Failed to read report\n");
        return 5;
    }
    fclose(report_fd);

    printf("isvprodid = %04x\n", report.body.isv_prod_id);
    printf("isvsvn = %d\n", report.body.isv_svn);
    blob2hex(report.body.isv_ext_prod_id, sizeof(report.body.isv_ext_prod_id), print_buffer);
    printf("isvextprodid = %s\n", print_buffer);
    blob2hex(report.body.isv_family_id, sizeof(report.body.isv_family_id), print_buffer);
    printf("isvfamilyid = %s\n", print_buffer);
    blob2hex(report.body.config_id, sizeof(report.body.config_id), print_buffer);
    printf("configid = %s\n", print_buffer);
    printf("configsvn = %d\n", report.body.config_svn);
    return 0;
}
