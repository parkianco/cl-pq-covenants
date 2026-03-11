;;;; package.lisp - Package definitions for cl-pq-covenants

(in-package #:cl-user)

(defpackage #:cl-pq-covenants
  (:use #:cl)
  (:documentation
   "Post-quantum covenant implementations for blockchain transactions.

Implements:
- PQ introspection opcodes for transaction analysis
- Quantum-safe vault constructions with timelocks
- Recursive covenant patterns with PQ verification
- Emergency migration covenants for key compromise scenarios

All covenants use Dilithium signatures (NIST FIPS 204) for quantum resistance.")

  (:export
   ;; ============================================================================
   ;; Constants
   ;; ============================================================================
   #:+covenant-version+
   #:+max-covenant-depth+
   #:+min-vault-delay-blocks+
   #:+max-recovery-window-blocks+
   #:+emergency-migration-delay+

   ;; ============================================================================
   ;; PQ Introspection Opcodes
   ;; ============================================================================
   #:+op-pq-checksig+
   #:+op-pq-checksigverify+
   #:+op-pq-checkmultisig+
   #:+op-pq-checktemplateverify+
   #:+op-pq-inspectoutputvalue+
   #:+op-pq-inspectoutputscript+
   #:+op-pq-inspectinputvalue+
   #:+op-pq-inspecttxversion+
   #:+op-pq-inspecttxlocktime+
   #:+op-pq-inspectinputcount+
   #:+op-pq-inspectoutputcount+

   ;; ============================================================================
   ;; Covenant Structures
   ;; ============================================================================
   #:pq-covenant
   #:make-pq-covenant
   #:pq-covenant-p
   #:pq-covenant-version
   #:pq-covenant-type
   #:pq-covenant-spending-conditions
   #:pq-covenant-recovery-key
   #:pq-covenant-timelock
   #:pq-covenant-recursive-p

   #:pq-vault
   #:make-pq-vault
   #:pq-vault-p
   #:pq-vault-hot-key
   #:pq-vault-cold-key
   #:pq-vault-recovery-key
   #:pq-vault-unvault-delay
   #:pq-vault-recovery-delay
   #:pq-vault-max-hot-spend

   #:spending-condition
   #:make-spending-condition
   #:spending-condition-p
   #:spending-condition-type
   #:spending-condition-pubkey
   #:spending-condition-timelock
   #:spending-condition-max-amount

   ;; ============================================================================
   ;; Vault Operations
   ;; ============================================================================
   #:create-pq-vault
   #:create-vault-deposit-script
   #:create-vault-unvault-script
   #:create-vault-recovery-script
   #:verify-vault-spend
   #:compute-vault-hash
   #:vault-state
   #:advance-vault-state

   ;; ============================================================================
   ;; Time-Locked Recovery
   ;; ============================================================================
   #:create-timelocked-recovery
   #:create-recovery-script
   #:verify-recovery-spend
   #:compute-recovery-hash
   #:recovery-eligible-p

   ;; ============================================================================
   ;; Recursive Covenants
   ;; ============================================================================
   #:create-recursive-covenant
   #:verify-recursive-covenant
   #:compute-covenant-template-hash
   #:enforce-output-constraints
   #:validate-covenant-chain

   ;; ============================================================================
   ;; Emergency Migration
   ;; ============================================================================
   #:create-emergency-migration-covenant
   #:trigger-emergency-migration
   #:verify-migration-signature
   #:compute-migration-commitment
   #:migration-eligible-p

   ;; ============================================================================
   ;; Script Generation
   ;; ============================================================================
   #:generate-pq-covenant-script
   #:generate-spending-witness
   #:serialize-covenant
   #:deserialize-covenant

   ;; ============================================================================
   ;; Crypto Utilities (standalone PQ primitives)
   ;; ============================================================================
   #:sha256
   #:tagged-hash
   #:dilithium-keypair
   #:make-dilithium-keypair
   #:dilithium-keypair-public-key
   #:dilithium-keypair-private-key
   #:dilithium-sign
   #:dilithium-verify
   #:dilithium-serialize-public-key
   #:dilithium-deserialize-public-key
   #:dilithium-serialize-signature
   #:dilithium-deserialize-signature
   #:p2pq-pubkey-hash))
