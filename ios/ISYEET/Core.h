#ifndef ISYEET_IOS_CORE_H
#define ISYEET_IOS_CORE_H
// The stable JSON C ABI from isyeet-backend/crates/client/include/isyeet.h.
// A response is owned by this caller and must be freed exactly once.
char *isyeet_call(const char *request_json);
void isyeet_free_string(char *response_json);
#endif
