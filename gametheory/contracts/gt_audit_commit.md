# gt_audit.bas commit formulas (R32a)

The commits are hashed over the exact bytes of the strings below. There is no padding and no encoding other than
UTF-8. `:` is the single byte 0x3a. The result is the lowercase hex of the 32-byte SHA-256 digest, so it is 64
characters long. In the contract, `HEX(SHA256(s))` is `hex.EncodeToString(sha256.Sum256([]byte(s)))`
(dvm/dvm_functions.go `dvm_sha256`, `dvm_hex`).

- Sponsor (`Post` commit, checked by `RevealSponsor`): `sha256(answer + ":" + salt)`
- Auditor (`Enter` commit, checked by `Reveal`): `sha256(answer + ":" + salt + ":" + address_string)`

R33 (GT-A03): `answer` must be 1 to 256 bytes long, or `Reveal` and `RevealSponsor` refuse it. The playbook
answers are 64-hex digests, so this changes nothing for them. The commit formulas themselves are unchanged in R33.

`address_string` is what `ADDRESS_STRING(SIGNER())` returns: the auditor's address in its **mainnet** encoding
(`dero1...`). `dvm_address_string` builds it with `rpc.NewAddressFromKeys`, which sets `Mainnet: true`
(rpc/address.go `NewAddressFromKeys`). On a testnet or simulator chain it is therefore still `dero1...`, not
`deto1...`. It is the plain address, not an integrated one with a payment id.

```python
import hashlib

def sponsor_commit(answer: str, salt: str) -> str:
    return hashlib.sha256((answer + ":" + salt).encode()).hexdigest()

def auditor_commit(answer: str, salt: str, address_string: str) -> str:
    return hashlib.sha256((answer + ":" + salt + ":" + address_string).encode()).hexdigest()
```

## Worked example (printed by `TestR32aAuditHonestRound`, dvm/r32a_audit_test.go)

The auditor key is test key "A" from `gtNew`. This is a test-only key, not a funded wallet.

| input | value |
|---|---|
| sponsor answer, salt | `d1g3st`, `pepper` |
| sponsor commit | `aea6b74b942b1ff10ca57a7e19746ec646a5052fb09e8b6682315fb3a8723d0c` |
| auditor address_string | `dero1qytvxapwej9x08rsk7eclpaxxw4l9uwnmuhl6l7axqxvhrgt6g8lgqqtjgzva` |
| auditor answer, salt | `d1g3st`, `s-A` |
| auditor commit | `4aa77e10e03cd9cff6ac6eeb9e6aef400f2709dc0211e97aa5590a4528df4ae3` |

```python
A = "dero1qytvxapwej9x08rsk7eclpaxxw4l9uwnmuhl6l7axqxvhrgt6g8lgqqtjgzva"
assert sponsor_commit("d1g3st", "pepper") == "aea6b74b942b1ff10ca57a7e19746ec646a5052fb09e8b6682315fb3a8723d0c"
assert auditor_commit("d1g3st", "s-A", A) == "4aa77e10e03cd9cff6ac6eeb9e6aef400f2709dc0211e97aa5590a4528df4ae3"
```

Both asserts were run with `python3 -I` and passed.
