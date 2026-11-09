#!/usr/bin/env python3
"""Exercise the real C ABI with synthetic state; never contacts the relay or Keychain.

Build the host library in the backend repository:
    cargo build --locked -p isyeet-client --lib --no-default-features --features device-linking
Then from the iOS repository:
    python3 scripts/test-device-authority-ffi.py /absolute/path/to/target/debug/libisyeet_client.dylib

No private keys, messages, candidate state or public approval codes are printed.
All test state exists only in process memory. Cryptographic checks use the actual
bundled core; deterministic expiry/allocation tests also run in the Rust suite.
"""
import base64, copy, ctypes, json, sys, time, uuid
if len(sys.argv) != 2:
    raise SystemExit("Usage: scripts/test-device-authority-ffi.py /absolute/path/to/libisyeet_client.dylib")
library=ctypes.CDLL(sys.argv[1])
library.isyeet_call.argtypes=[ctypes.c_char_p]
library.isyeet_call.restype=ctypes.c_void_p
library.isyeet_free_string.argtypes=[ctypes.c_void_p]
def invoke(op, state=None, ok=True, **fields):
    req=dict(op=op,**fields)
    if state is not None: req['state']=state
    pointer=library.isyeet_call(json.dumps(req,separators=(',',':')).encode())
    assert pointer
    try: response=json.loads(ctypes.string_at(pointer))
    finally: library.isyeet_free_string(pointer)
    assert response['ok'] is ok, (op,response.get('error'))
    if not ok: assert 'state' not in response and 'candidate' not in response
    return response
now=lambda:int(time.time())
origin='https://api-staging.isyeet.io'
account=str(uuid.uuid4())
state=invoke('init',account_id=account,username='ffi_test')['state']
root_fingerprint=invoke('snapshot',state)['data']['fingerprint']
state=invoke('device_authority_observe',state,origin=origin,authority=None,server_time=now())['state']
bootstrap=invoke('device_authority_prepare',state,origin=origin,server_time=now())
state=bootstrap['state']
initial=bootstrap['data']['pending']['change']['roster']
assert bootstrap['data']['approval_code'] is None and bootstrap['data']['messaging_available'] is False
# Reconcile a successful server publication with its receipt lost.
published=invoke('device_authority_observe',state,origin=origin,authority=initial,server_time=now())
state=published['state']
assert published['data']['pending'] is None
candidate=invoke('device_candidate_create',roster=initial,label='FFI desktop',root_fingerprint=root_fingerprint)
private_candidate=candidate['candidate']; code=candidate['data']['code']
inspection=invoke('device_authority_inspect',state,code=code,server_time=now())['data']
assert inspection['account_id']==account and inspection['identity_fingerprint']==candidate['data']['status']['identity_fingerprint']
assert inspection['request_hash']==candidate['data']['status']['request_hash']
invoke('device_authority_approve',state,ok=False,code=code,expected_request_hash='0'*64,server_time=now())
for malicious in [code+'\n',code+'=',code.replace('ISYEET-LINK-1:','ISYEET-APPROVAL-1:'),'ISYEET-LINK-1:'+base64.urlsafe_b64encode(b'{"unexpected":true}').decode().rstrip('=')]:
    invoke('device_authority_inspect',state,ok=False,code=malicious,server_time=now())
invoke('device_authority_inspect',state,ok=False,code=code,server_time=now()+301)
approved=invoke('device_authority_approve',state,code=code,expected_request_hash=inspection['request_hash'],server_time=now())
state=approved['state']; pending=approved['data']['pending']; roster=pending['change']['roster']
assert len(roster['roster']['devices'])==2 and approved['data']['approval_code'] is None
# Disk round-trip models native persistence before sending the signed intent.
state=json.loads(json.dumps(state))
recovered=invoke('device_authority_observe',state,origin=origin,authority=roster,server_time=now())
assert recovered['data']['approval_code'] is not None
# Form a synthetic server receipt using the digest computed by an independently
# verified observation on a separate branch. This fixture-only read of opaque
# state avoids implementing the signed transcript hash again in Python.
receipt=dict(operation_id=pending['change']['operation_id'], roster_version=roster['roster']['version'],
             roster_hash=recovered['state']['device_authority']['observed_hash'], messaging_available=False)
committed=invoke('device_authority_commit',state,receipt=receipt)
assert committed['data']['pending'] is None and committed['data']['approval_code'] is None
assert invoke('device_authority_snapshot',committed['state'])['data']['approval_code'] is None
# A valid receipt alone must never release a code. Require the current GET too.
recovered=invoke('device_authority_observe',json.loads(json.dumps(committed['state'])),origin=origin,authority=roster,server_time=now())
state=recovered['state']; approval=recovered['data']['approval_code']
assert recovered['data']['pending'] is None and approval.startswith('ISYEET-APPROVAL-1:')
accepted=invoke('device_candidate_accept',candidate=private_candidate,code=approval)
assert accepted['data']['approved'] is True and accepted['data']['messaging_available'] is False
invoke('device_authority_observe',state,ok=False,origin=origin,authority=initial,server_time=now())
invoke('device_authority_observe',state,ok=False,origin='https://api.isyeet.io',authority=roster,server_time=now())
invoke('device_authority_revoke',state,ok=False,device_id=1,server_time=now())
revocation=invoke('device_authority_revoke',state,device_id=inspection['device_id'],server_time=now())
revoked_roster=revocation['data']['pending']['change']['roster']
revoked=invoke('device_authority_observe',revocation['state'],origin=origin,authority=revoked_roster,server_time=now())
assert len(revoked['data']['authority']['roster']['devices'])==1 and revoked['data']['approval_code'] is None
assert revoked['data']['allocated_device_id']==inspection['device_id']
invoke('device_authority_inspect',revoked['state'],ok=False,code=code,server_time=now())
assert library is not None
print('PASS real C ABI bootstrap, candidate key proof, exact fingerprint/hash binding, durable pending state, lost-reply reconciliation, receipt-only approval withholding, companion acceptance, rollback/origin rejection, revocation, and no messaging grant')
