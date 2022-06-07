// Copyright (c) 2022 The MobileCoin Foundation

#include <sgx_report.h>
#include <sgx_trts.h>
#include <sgx_utils.h>

/*
 * A basic function that just adds 2 to its input
 */
void ecall_add_2(int input, int *sum) {
    *sum = input + 2;
}

/*
 * Create the report for this enclave instance
 *
 * \param target_info The target info to use for creating the report
 * \param report the report to be filled out.  This is only valid if
 *      this returns `SGX_SUCCESS`.
 * \returns The result of `sgx_create_report()`
 */
sgx_status_t ecall_create_report(const sgx_target_info_t* target_info, sgx_report_t* report){
    sgx_report_data_t report_data = { 0 };
    return sgx_create_report(target_info, &report_data, report);
}
