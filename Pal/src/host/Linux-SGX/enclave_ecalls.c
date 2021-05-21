#include "enclave_ecalls.h"

#include <stdalign.h>

#include "api.h"

#include "pal_crypto.h"

#include "ecall_types.h"
#include "ocall_types.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_security.h"
#include "rpc_queue.h"
#include "sgx_arch.h"


#include <linux/un.h>
/* WL: Length should be finalized when DH is imported. */
#define MAX_SEND_BUF 1024
#define MAX_RECV_BUF 1024
#define SGX_AESGCM_KEY_SIZE 16
typedef uint8_t sgx_aes_gcm_128bit_key_t[SGX_AESGCM_KEY_SIZE];

#define SGX_CAST(type, item) ((type)(item))

extern void* g_enclave_base;
extern void* g_enclave_top;

static struct atomic_int g_enclave_start_called = ATOMIC_INIT(0);


/* returns 0 if rpc_queue is valid/not requested, otherwise -1 */
static int verify_and_init_rpc_queue(rpc_queue_t* untrusted_rpc_queue) {
    g_rpc_queue = NULL;

    if (!untrusted_rpc_queue) {
        /* user app didn't request RPC queue (i.e., the app didn't request exitless syscalls) */
        return 0;
    }

    if (!sgx_is_completely_outside_enclave(untrusted_rpc_queue, sizeof(*untrusted_rpc_queue))) {
        /* malicious RPC queue object, return error */
        return -1;
    }

    g_rpc_queue = untrusted_rpc_queue;
    return 0;
}

static void my_print_report(sgx_report_t* r) {
    log_error("Printing report...\n");
    log_error("  cpu_svn:     %s\n", ALLOCA_BYTES2HEXSTR(r->body.cpu_svn.svn));
    log_error("  mr_enclave:  %s\n", ALLOCA_BYTES2HEXSTR(r->body.mr_enclave.m));
    log_error("  mr_signer:   %s\n", ALLOCA_BYTES2HEXSTR(r->body.mr_signer.m));
    log_error("  attr.flags:  %016lx\n", r->body.attributes.flags);
    log_error("  attr.xfrm:   %016lx\n", r->body.attributes.xfrm);
    log_error("  isv_prod_id: %02x\n", r->body.isv_prod_id);
    log_error("  isv_svn:     %02x\n", r->body.isv_svn);
    log_error("  report_data: %s\n", ALLOCA_BYTES2HEXSTR(r->body.report_data.d));
    log_error("  key_id:      %s\n", ALLOCA_BYTES2HEXSTR(r->key_id.id));
    log_error("  mac:         %s\n", ALLOCA_BYTES2HEXSTR(r->mac));
}

int report_match(char *a, char *b) {
    //if we verify mr_signer, n=64
    if (strncmp(a, b, 64) == 0) {
        return 0;
    }
    else {
        return -1;
    }
}


int dh_init(PAL_SESSION_KEY* key) {

    uint8_t pub[DH_SIZE]   __attribute__((aligned(DH_SIZE)));
    uint8_t agree[DH_SIZE] __attribute__((aligned(DH_SIZE)));
    PAL_NUM pubsz, agreesz;
    LIB_DH_CONTEXT context;
    int64_t bytes;
    int64_t ret;

    ret = lib_DhInit(&context);
    if (ret < 0) {
        log_error("Key Exchange: DH Init failed: %ld\n", ret);
        goto out_no_final;
    }

    pubsz = sizeof pub;
    ret = lib_DhCreatePublic(&context, pub, &pubsz);
    if (ret < 0) {
        log_error("Key Exchange: DH CreatePublic failed: %ld\n", ret);
        goto out;
    }

    assert(pubsz > 0 && pubsz <= DH_SIZE);
    if (pubsz < DH_SIZE) {
        /* Insert leading zero bytes if necessary. These values are big-
         * endian, so we either need to know the length of the bignum or
         * zero-pad at the beginning instead of the end. This code chooses
         * to do the latter. */
        memmove(pub + (DH_SIZE - pubsz), pub, pubsz);
        memset(pub, 0, DH_SIZE - pubsz);
    }

    for (bytes = 0, ret = 0; bytes < DH_SIZE; bytes += ret) {
        //WL: write the socket
        // ret = _DkStreamWrite(stream, 0, DH_SIZE - bytes, pub + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            log_error("Failed to exchange the secret key via RPC: %ld\n", ret);
            goto out;
        }
    }

    for (bytes = 0, ret = 0; bytes < DH_SIZE; bytes += ret) {
        //WL: read from socket
        // ret = _DkStreamRead(stream, 0, DH_SIZE - bytes, pub + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            log_error("Failed to exchange the secret key via RPC: %ld\n", ret);
            goto out;
        }
    }

    agreesz = sizeof agree;
    ret = lib_DhCalcSecret(&context, pub, DH_SIZE, agree, &agreesz);
    if (ret < 0) {
        log_error("Key Exchange: DH CalcSecret failed: %ld\n", ret);
        goto out;
    }

    assert(agreesz > 0 && agreesz <= sizeof agree);

    /*
     * Using SHA256 as a KDF to convert the 128-byte DH secret to a 256-bit AES key.
     * According to the NIST recommendation:
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf,
     * a key derivation function (KDF) can be a secure hash function (e.g., SHA-256),
     * HMAC, or KMAC.
     */
    LIB_SHA256_CONTEXT sha;
    if ((ret = lib_SHA256Init(&sha)) < 0 ||
        (ret = lib_SHA256Update(&sha, agree, agreesz)) < 0 ||
        (ret = lib_SHA256Final(&sha, (uint8_t*)key)) < 0) {
        log_error("Failed to derive the session key: %ld\n", ret);
        goto out;
    }

    log_debug("Key exchange succeeded: %s\n", ALLOCA_BYTES2HEXSTR(*key));
    ret = 0;
out:
    lib_DhFinal(&context);
out_no_final:
    return ret;
}

int la_init(void) {

    log_error("Connecting LAS...\n");
    //WL: the following address should be configurable
    struct sockaddr_un addr = {AF_UNIX, "/home/box/LA.socket"};

    struct sockopt sock_options;
    unsigned int addrlen = sizeof(struct sockaddr_un);
    int fd_ret = ocall_connect(AF_UNIX, SOCK_STREAM, 0, /*ipv6_v6only=*/0,
                        (const struct sockaddr*)&addr, addrlen, NULL, NULL, &sock_options);
    if (fd_ret < 0) {
        log_error("ocall_connect failed: fd_ret = %d)\n", fd_ret);
        return -6;
    }

    PAL_SESSION_KEY key = {0};
    int dh_rv = dh_init(&key);
    if (dh_rv != 0) {
        log_error("DH init failed\n");
    }
    else {
        log_error("key 15th: %d\n", key[15]);
        // return -7;
    }

    //WL: proceed with LA protocol
    /* Send: targetinfo[A] */
    log_error("Sending msg0...\n");

    __sgx_mem_aligned sgx_target_info_t target_info;
    memset(&target_info, 0, sizeof(target_info));
    memcpy(&target_info.mr_enclave, &g_pal_sec.mr_enclave, sizeof(sgx_measurement_t));
    memcpy(&target_info.attributes, &g_pal_sec.enclave_attributes, sizeof(sgx_attributes_t));

    alignas(128) char report_data[64] = {0};
    __sgx_mem_aligned sgx_report_t report;
    memset(&report, 0, sizeof(report));

    sgx_aes_gcm_128bit_key_t recv_key;
    memset(&recv_key, 0, sizeof(recv_key));

    // We use MAX_RECV_BUF as every packet length. 
    // This value should be synced between the sender and the receiver.
    ssize_t bytes;
    int len = sizeof(sgx_target_info_t);
    char send_buf[MAX_SEND_BUF] = {0};
    memcpy(&send_buf, &target_info, len);
    // log_error("Msg0 actual length: %d\n", len);
    // log_error("target_info's mr_enclave: %s\n", ALLOCA_BYTES2HEXSTR(target_info.mr_enclave.m));
    // log_error("target_info's attr.flag: %016lx\n", target_info.attributes.flags);
    // log_error("target_info's attr.xfrm: %016lx\n", target_info.attributes.xfrm);
  
    bytes = ocall_send(fd_ret, send_buf, MAX_SEND_BUF, NULL, 0, NULL, 0);
    if (bytes < 0) {
        log_error("ocall_send failed: bytes = %d)\n", bytes);
        return -1;
    }
    else {
        log_error("Msg0 sent.\n");
    }
    // clean up
    memset(&send_buf, 0, sizeof(send_buf));

    /* Receive: report[B -> A] */

    char recv_buf[MAX_RECV_BUF] = {0};
    bytes = ocall_recv(fd_ret, recv_buf, MAX_RECV_BUF, NULL, NULL, NULL, NULL);

    // assume here we only recv a sgx_report_t
    sgx_report_t recv_report;
    memcpy(&recv_report, &recv_buf, sizeof(sgx_report_t));

    if (bytes < 0) {
        log_error("ocall_recv failed: bytes = %d)\n", bytes);
        return -2;
    }
    else {
        log_error("Msg1 received...\n");
        log_error("Received local report (mr_signer = %s)\n",
              ALLOCA_BYTES2HEXSTR(recv_report.body.mr_signer.m));
        log_error("Received local report (mr_enclave = %s)\n",
              ALLOCA_BYTES2HEXSTR(recv_report.body.mr_enclave.m));
    }

    log_error("Verifying report...\n");

    /* Verify report[B -> A] */

    int ret = sgx_report(&target_info, &report_data, &report);
    if (ret) {
        log_error("sgx_report failed: ret = %d)\n", ret);
        //We return here since something inside SGX is wrong...
        return -PAL_ERROR_DENIED;
    }
    my_print_report(&report);
    if (report_match(ALLOCA_BYTES2HEXSTR(recv_report.body.mr_signer.m), 
            ALLOCA_BYTES2HEXSTR(report.body.mr_signer.m))) {
        log_error("Not match! Reject!\n");
        return -3;
    }
    else {
        log_error("Mr_signer Verified!\n");
    }

    /* Send: report[A -> B] */

    log_error("Sending msg2...\n");
    memcpy(&send_buf, &report, sizeof(sgx_report_t));

    bytes = ocall_send(fd_ret, send_buf, MAX_SEND_BUF, NULL, 0, NULL, 0);
    if (bytes < 0) {
        log_error("ocall_send failed: bytes = %d)\n", bytes);
        return -4;
    }
    else {
        log_error("Msg2 sent. This side of attestation, done.\n");
    }

    /* Receive: key[A -> B] */

    log_error("Receiving msg3...\n");
    // clean up
    memset(&recv_buf, 0, sizeof(recv_buf));
    bytes = ocall_recv(fd_ret, recv_buf, MAX_RECV_BUF, NULL, NULL, NULL, NULL);

    memcpy(&recv_key, &recv_buf, sizeof(sgx_aes_gcm_128bit_key_t));
    if (bytes < 0) {
        log_error("ocall_recv failed: bytes = %d)\n", bytes);
        return -5;
    }
    else {
        log_error("Msg3 received...\n");
        log_error("Key: %s\n", ALLOCA_BYTES2HEXSTR(recv_key));
    }

    ocall_close(fd_ret);
    log_error("LA finished.\n");
    return 0;

};

/*
 * Called from enclave_entry.S to execute ecalls.
 *
 * During normal operation handle_ecall will not return. The exception is that
 * it will return if invalid parameters are passed. In this case
 * enclave_entry.S will go into an endless loop since a clean return to urts is
 * not easy in all cases.
 *
 * Parameters:
 *
 *  ecall_index:
 *      Number of requested ecall. Untrusted.
 *
 *  ecall_args:
 *      Pointer to arguments for requested ecall. Untrusted.
 *
 *  exit_target:
 *      Address to return to after EEXIT. Untrusted.
 *
 *  enclave_base_addr:
 *      Base address of enclave. Calculated dynamically in enclave_entry.S.
 *      Trusted.
 */
void handle_ecall(long ecall_index, void* ecall_args, void* exit_target, void* enclave_base_addr) {
    if (ecall_index < 0 || ecall_index >= ECALL_NR)
        return;

    if (!g_enclave_top) {
        g_enclave_base = enclave_base_addr;
        g_enclave_top  = enclave_base_addr + GET_ENCLAVE_TLS(enclave_size);
    }

    /* disallow malicious URSP (that points into the enclave) */
    void* ursp = (void*)GET_ENCLAVE_TLS(gpr)->ursp;
    if (g_enclave_base <= ursp && ursp <= g_enclave_top)
        return;

    SET_ENCLAVE_TLS(exit_target, exit_target);
    SET_ENCLAVE_TLS(ustack, ursp);
    SET_ENCLAVE_TLS(ustack_top, ursp);
    SET_ENCLAVE_TLS(clear_child_tid, NULL);
    SET_ENCLAVE_TLS(untrusted_area_cache.in_use, 0UL);

    int la_rv = la_init();
    if (la_rv < 0) {
        //WL: could check the return value for debugging
        log_error("LA init failed!\n");
    }

    int64_t t = 0;
    if (__atomic_compare_exchange_n(&g_enclave_start_called.counter, &t, 1, /*weak=*/false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)) {
        // ENCLAVE_START not yet called, so only valid ecall is ENCLAVE_START.
        if (ecall_index != ECALL_ENCLAVE_START) {
            // To keep things simple, we treat an invalid ecall_index like an
            // unsuccessful call to ENCLAVE_START.
            return;
        }

        ms_ecall_enclave_start_t* ms = (ms_ecall_enclave_start_t*)ecall_args;

        if (!ms || !sgx_is_completely_outside_enclave(ms, sizeof(*ms))) {
            return;
        }

        if (verify_and_init_rpc_queue(READ_ONCE(ms->rpc_queue)))
            return;

        struct pal_sec* pal_sec = READ_ONCE(ms->ms_sec_info);
        if (!pal_sec || !sgx_is_completely_outside_enclave(pal_sec, sizeof(*pal_sec)))
            return;

        /* xsave size must be initialized early, from a trusted source (EREPORT result) */
        // TODO: This eats 1KB of a stack frame which lives for the whole lifespan of this enclave.
        //       We should move it somewhere else and deallocate right after use.
        __sgx_mem_aligned sgx_target_info_t target_info;
        alignas(128) char report_data[64] = {0};
        __sgx_mem_aligned sgx_report_t report;
        memset(&report, 0, sizeof(report));
        memset(&target_info, 0, sizeof(target_info));
        sgx_report(&target_info, &report_data, &report);
        init_xsave_size(report.body.attributes.xfrm);

        /* pal_linux_main is responsible to check the passed arguments */
        pal_linux_main(READ_ONCE(ms->ms_libpal_uri), READ_ONCE(ms->ms_libpal_uri_len),
                       READ_ONCE(ms->ms_args), READ_ONCE(ms->ms_args_size), READ_ONCE(ms->ms_env),
                       READ_ONCE(ms->ms_env_size), pal_sec);
    } else {
        // ENCLAVE_START already called (maybe successfully, maybe not), so
        // only valid ecall is THREAD_START.
        if (ecall_index != ECALL_THREAD_START) {
            return;
        }

        // Only allow THREAD_START after successful enclave initialization.
        if (!(g_pal_enclave_state.enclave_flags & PAL_ENCLAVE_INITIALIZED)) {
            return;
        }

        pal_start_thread();
    }
    // pal_linux_main and pal_start_thread should never return.
}
