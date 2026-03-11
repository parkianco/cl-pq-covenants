# cl-pq-covenants

Post-quantum covenant script patterns for blockchain transactions.

## Overview

cl-pq-covenants provides quantum-resistant covenant implementations for restricting how blockchain outputs can be spent. It uses Dilithium signatures (NIST FIPS 204 ML-DSA) for post-quantum security.

## Features

- **PQ Vaults**: Multi-stage spending with hot/cold key separation and recovery mechanisms
- **Time-Locked Recovery**: Dead-man switches and inheritance planning with PQ security
- **Recursive Covenants**: Self-enforcing spending constraints using CTV-style templates
- **Emergency Migration**: Quantum-safe migration paths for key compromise scenarios
- **Custom Script Opcodes**: New PQ-aware introspection opcodes (0xD0-0xDA range)

## Installation

```lisp
;; Load the system
(asdf:load-system :cl-pq-covenants)
```

## Usage

### Creating a PQ Vault

```lisp
(let* ((hot-kp (make-dilithium-keypair))
       (cold-kp (make-dilithium-keypair))
       (recovery-kp (make-dilithium-keypair))
       (vault (create-pq-vault hot-kp cold-kp
                               :recovery-keypair recovery-kp
                               :unvault-delay 288  ; ~2 days
                               :max-hot-spend 100000000)))
  (create-vault-deposit-script vault))
```

### Time-Locked Recovery

```lisp
(let* ((primary-key (dilithium-keypair-public-key primary-kp))
       (recovery-key (dilithium-keypair-public-key recovery-kp))
       (covenant (create-timelocked-recovery primary-key recovery-key
                                             :delay-blocks 52560)))  ; ~1 year
  (create-recovery-script covenant))
```

### Emergency Migration

```lisp
(let ((covenant (create-emergency-migration-covenant
                 old-pubkey new-pubkey
                 :delay 4320)))  ; ~30 days
  (when (migration-eligible-p covenant current-height)
    (trigger-emergency-migration covenant old-privkey new-pubkey)))
```

## PQ Opcodes

| Opcode | Hex | Description |
|--------|-----|-------------|
| OP_PQ_CHECKSIG | 0xD0 | Verify Dilithium signature |
| OP_PQ_CHECKSIGVERIFY | 0xD1 | OP_PQ_CHECKSIG + OP_VERIFY |
| OP_PQ_CHECKMULTISIG | 0xD2 | M-of-N Dilithium multisig |
| OP_PQ_CHECKTEMPLATEVERIFY | 0xD3 | CTV-style template verification |
| OP_PQ_INSPECTOUTPUTVALUE | 0xD4 | Push output value at index |
| OP_PQ_INSPECTOUTPUTSCRIPT | 0xD5 | Push output script at index |

## Security Considerations

The Dilithium implementation included is a **stub** for API compatibility. Production deployments must use a verified Dilithium implementation (e.g., liboqs bindings).

All covenants use:
- Dilithium3 (NIST security level 3)
- Tagged hashes with domain separation
- Minimal push encoding for script numbers

## Testing

```lisp
(asdf:load-system :cl-pq-covenants/test)
(cl-pq-covenants/test:run-tests)
```

## License

MIT License. See LICENSE file.
