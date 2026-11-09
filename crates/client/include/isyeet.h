#ifndef ISYEET_H
#define ISYEET_H
#ifdef __cplusplus
extern "C" {
#endif
/* Pure state transition. Caller MUST durably save returned state before send/ACK.
 * Input: NUL-terminated UTF-8 JSON, <=8MiB; output caller frees exactly once.
 * Schema 7 init requires account_id (canonical UUIDv4) and username. Protocol
 * addresses and contact operation IDs are account IDs, never display names.
 * Earlier email-based states are rejected, never silently migrated.
 * Secrets and plaintext are in state: store with OS-protected local storage.
 * No network, disk, logging, or global mutable protocol state. */
char *isyeet_call(const char *request_json);
void isyeet_free_string(char *response_json);
void isyeet_free(char *response_json);
#ifdef __cplusplus
}
#endif
#endif
