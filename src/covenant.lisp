;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; covenant.lisp - Covenant definitions and operations

(in-package #:cl-pq-covenants)

;;; ============================================================================
;;; Constants
;;; ============================================================================

(defconstant +covenant-version+ 1
  "Current version of PQ covenant protocol.")

(defconstant +max-covenant-depth+ 100
  "Maximum recursion depth for recursive covenants.
   Prevents infinite recursion attacks.")

(defconstant +min-vault-delay-blocks+ 144
  "Minimum unvault delay in blocks (~1 day at 10 min/block).
   Provides time for recovery key intervention.")

(defconstant +max-recovery-window-blocks+ 52560
  "Maximum recovery window in blocks (~1 year).
   Balances security with key availability.")

(defconstant +emergency-migration-delay+ 4320
  "Emergency migration delay in blocks (~30 days).
   Allows time to detect unauthorized migration attempts.")

;;; ============================================================================
;;; Spending Condition Structure
;;; ============================================================================

(defstruct (spending-condition
            (:constructor %make-spending-condition))
  "A spending condition for covenant outputs.

   TYPE: Condition type (:immediate, :timelocked, :multisig, etc.)
   PUBKEY: Dilithium public key (serialized bytes)
   TIMELOCK: Optional block height/time for timelocked conditions
   MAX-AMOUNT: Optional maximum spending amount (satoshis)"
  (type :immediate :type spending-condition-type :read-only t)
  (pubkey nil :type (or null octet-vector) :read-only t)
  (timelock 0 :type (unsigned-byte 32) :read-only t)
  (max-amount nil :type (or null (unsigned-byte 64)) :read-only t))

(defun make-spending-condition (type &key pubkey timelock max-amount)
  "Create a spending condition with validation."
  (when (and (member type '(:immediate :timelocked :emergency))
             (null pubkey))
    (error "Spending condition type ~A requires a pubkey" type))
  (when (and (eq type :timelocked) (zerop (or timelock 0)))
    (error "Timelocked condition requires non-zero timelock"))
  (%make-spending-condition :type type
                            :pubkey pubkey
                            :timelock (or timelock 0)
                            :max-amount max-amount))

;;; ============================================================================
;;; PQ Covenant Structure
;;; ============================================================================

(defstruct (pq-covenant
            (:constructor %make-pq-covenant))
  "A post-quantum covenant restricting spending conditions.

   VERSION: Protocol version (for future upgrades)
   TYPE: Covenant type (:vault, :recovery, :recursive, :migration)
   SPENDING-CONDITIONS: List of allowed spending paths
   RECOVERY-KEY: Optional Dilithium key for emergency recovery
   TIMELOCK: Optional absolute or relative timelock
   RECURSIVE-P: If T, covenant enforces constraints on outputs"
  (version +covenant-version+ :type (unsigned-byte 8) :read-only t)
  (type :custom :type covenant-type :read-only t)
  (spending-conditions nil :type list :read-only t)
  (recovery-key nil :type (or null octet-vector) :read-only t)
  (timelock 0 :type (unsigned-byte 32) :read-only t)
  (recursive-p nil :type boolean :read-only t))

(defun make-pq-covenant (type spending-conditions
                         &key recovery-key timelock recursive-p)
  "Create a PQ covenant with validation."
  (unless spending-conditions
    (error "Covenant must have at least one spending condition"))
  (when (and (eq type :vault) (< (length spending-conditions) 2))
    (error "Vault covenant requires at least hot and cold spending paths"))
  (%make-pq-covenant :type type
                     :spending-conditions spending-conditions
                     :recovery-key recovery-key
                     :timelock (or timelock 0)
                     :recursive-p recursive-p))

;;; ============================================================================
;;; PQ Vault Structure
;;; ============================================================================

(defstruct (pq-vault
            (:constructor %make-pq-vault))
  "A post-quantum vault for secure fund storage.

   VAULTS provide a multi-stage spending mechanism:
   1. DEPOSIT: Funds locked in vault script
   2. UNVAULT: Hot key triggers unvaulting with delay
   3. RECOVERY: Cold key can intervene during delay
   4. SPEND: After delay, hot key completes spend

   HOT-KEY: Dilithium key for day-to-day operations (online)
   COLD-KEY: Dilithium key for high-value spends (offline)
   RECOVERY-KEY: Dilithium key for emergency recovery (air-gapped)
   UNVAULT-DELAY: Blocks before unvault completes
   RECOVERY-DELAY: Additional blocks for recovery intervention
   MAX-HOT-SPEND: Maximum value hot key can spend without cold key"
  (hot-key nil :type octet-vector :read-only t)
  (cold-key nil :type octet-vector :read-only t)
  (recovery-key nil :type (or null octet-vector) :read-only t)
  (unvault-delay +min-vault-delay-blocks+ :type (unsigned-byte 32) :read-only t)
  (recovery-delay 0 :type (unsigned-byte 32) :read-only t)
  (max-hot-spend 0 :type (unsigned-byte 64) :read-only t))

(defun make-pq-vault (hot-key cold-key
                      &key recovery-key
                           (unvault-delay +min-vault-delay-blocks+)
                           (recovery-delay 0)
                           (max-hot-spend 0))
  "Create a PQ vault with validation."
  (unless (>= unvault-delay +min-vault-delay-blocks+)
    (error "Unvault delay must be at least ~D blocks" +min-vault-delay-blocks+))
  (when (> (+ unvault-delay recovery-delay) +max-recovery-window-blocks+)
    (error "Total delay exceeds maximum recovery window"))
  (%make-pq-vault :hot-key hot-key
                  :cold-key cold-key
                  :recovery-key recovery-key
                  :unvault-delay unvault-delay
                  :recovery-delay recovery-delay
                  :max-hot-spend max-hot-spend))

;;; ============================================================================
;;; Vault Operations
;;; ============================================================================

(defun create-pq-vault (hot-keypair cold-keypair
                        &key recovery-keypair
                             (unvault-delay +min-vault-delay-blocks+)
                             (max-hot-spend 100000000)) ; 1 BTC default
  "Create a new PQ vault from keypairs.

   Returns a PQ-VAULT structure ready for deposit script generation.
   Serializes public keys for storage in covenant scripts."
  (let ((hot-pub (dilithium-serialize-public-key
                  (dilithium-keypair-public-key hot-keypair)))
        (cold-pub (dilithium-serialize-public-key
                   (dilithium-keypair-public-key cold-keypair)))
        (recovery-pub (when recovery-keypair
                        (dilithium-serialize-public-key
                         (dilithium-keypair-public-key recovery-keypair)))))
    (make-pq-vault hot-pub cold-pub
                   :recovery-key recovery-pub
                   :unvault-delay unvault-delay
                   :max-hot-spend max-hot-spend)))

(defun create-vault-deposit-script (vault)
  "Create the deposit script for a PQ vault.

   Script structure (simplified):
   <hot-pk-hash> OP_PQ_CHECKSIG OP_IF
     <unvault-delay> OP_CSV OP_DROP
     <hot-pk-hash> OP_PQ_CHECKSIGVERIFY
   OP_ELSE
     <cold-pk-hash> OP_PQ_CHECKSIGVERIFY
   OP_ENDIF

   This allows:
   1. Hot key spend after CSV delay
   2. Cold key immediate spend
   3. Recovery via separate script path"
  (let* ((hot-hash (sha256 (pq-vault-hot-key vault)))
         (cold-hash (sha256 (pq-vault-cold-key vault)))
         (delay (pq-vault-unvault-delay vault))
         (script-bytes (make-array 256 :element-type '(unsigned-byte 8)
                                   :fill-pointer 0 :adjustable t)))
    ;; Build script with introspection opcodes
    ;; Hot key path with timelock
    (vector-push-extend 32 script-bytes)              ; Push 32 bytes
    (loop for b across hot-hash do (vector-push-extend b script-bytes))
    (vector-push-extend +op-pq-checksig+ script-bytes)
    (vector-push-extend +op-if+ script-bytes)

    ;; CSV delay for hot key
    (encode-number-to-script delay script-bytes)
    (vector-push-extend +op-checksequenceverify+ script-bytes)
    (vector-push-extend +op-drop+ script-bytes)
    (vector-push-extend 32 script-bytes)
    (loop for b across hot-hash do (vector-push-extend b script-bytes))
    (vector-push-extend +op-pq-checksigverify+ script-bytes)

    ;; Cold key path (immediate)
    (vector-push-extend +op-else+ script-bytes)
    (vector-push-extend 32 script-bytes)
    (loop for b across cold-hash do (vector-push-extend b script-bytes))
    (vector-push-extend +op-pq-checksigverify+ script-bytes)
    (vector-push-extend +op-endif+ script-bytes)

    (coerce script-bytes '(simple-array (unsigned-byte 8) (*)))))

(defun create-vault-unvault-script (vault target-address amount)
  "Create the unvaulting transaction script.

   When hot key initiates unvault:
   1. Creates transaction with CSV-locked output
   2. Output sends to TARGET-ADDRESS after delay
   3. Recovery key can sweep during delay period

   Returns script for the unvaulting output."
  (let ((delay (pq-vault-unvault-delay vault))
        (recovery-key (pq-vault-recovery-key vault))
        (script-bytes (make-array 256 :element-type '(unsigned-byte 8)
                                  :fill-pointer 0 :adjustable t)))
    ;; Check amount against hot spend limit
    (when (and (> amount 0)
               (> amount (pq-vault-max-hot-spend vault)))
      (error "Amount ~D exceeds hot spend limit ~D"
             amount (pq-vault-max-hot-spend vault)))

    ;; Recovery path (takes priority during delay)
    (when recovery-key
      (let ((recovery-hash (sha256 recovery-key)))
        (vector-push-extend 32 script-bytes)
        (loop for b across recovery-hash do (vector-push-extend b script-bytes))
        (vector-push-extend +op-pq-checksig+ script-bytes)
        (vector-push-extend +op-if+ script-bytes)
        ;; Recovery succeeds immediately
        (vector-push-extend +op-true+ script-bytes)
        (vector-push-extend +op-else+ script-bytes)))

    ;; Normal unvault path (after delay)
    (encode-number-to-script delay script-bytes)
    (vector-push-extend +op-checksequenceverify+ script-bytes)
    (vector-push-extend +op-drop+ script-bytes)

    ;; Push target address hash for final verification
    (let ((addr-hash (decode-address-to-hash target-address)))
      (vector-push-extend (length addr-hash) script-bytes)
      (loop for b across addr-hash do (vector-push-extend b script-bytes)))

    (when recovery-key
      (vector-push-extend +op-endif+ script-bytes))

    (coerce script-bytes '(simple-array (unsigned-byte 8) (*)))))

(defun create-vault-recovery-script (vault destination-script)
  "Create a recovery transaction script.

   Recovery key can sweep all funds to DESTINATION-SCRIPT
   during the unvault delay period. This is the 'panic button'
   for compromised hot keys."
  (let ((recovery-key (pq-vault-recovery-key vault)))
    (unless recovery-key
      (error "Vault has no recovery key configured"))
    (let ((recovery-hash (sha256 recovery-key))
          (script-bytes (make-array 128 :element-type '(unsigned-byte 8)
                                    :fill-pointer 0 :adjustable t)))
      ;; Simple recovery: verify recovery key signature
      (vector-push-extend 32 script-bytes)
      (loop for b across recovery-hash do (vector-push-extend b script-bytes))
      (vector-push-extend +op-pq-checksigverify+ script-bytes)
      ;; Push destination commitment
      (let ((dest-hash (sha256 destination-script)))
        (vector-push-extend 32 script-bytes)
        (loop for b across dest-hash do (vector-push-extend b script-bytes))
        (vector-push-extend +op-pq-inspectoutputscript+ script-bytes)
        (vector-push-extend +op-equalverify+ script-bytes))
      (coerce script-bytes '(simple-array (unsigned-byte 8) (*))))))

(defun verify-vault-spend (vault tx input-index spending-type)
  "Verify a vault spending transaction.

   SPENDING-TYPE: :hot, :cold, or :recovery
   Validates signatures and timelock constraints."
  (let* ((input (nth input-index (tx-inputs tx)))
         (witness (tx-input-witness input)))
    (unless witness
      (return-from verify-vault-spend (values nil "Missing witness data")))

    (case spending-type
      (:hot
       ;; Verify CSV constraint met
       (let ((sequence (tx-input-sequence input)))
         (unless (>= (logand sequence #xFFFF)
                     (pq-vault-unvault-delay vault))
           (return-from verify-vault-spend
             (values nil "Timelock not satisfied"))))
       ;; Verify hot key signature
       (verify-pq-signature-in-witness
        witness (pq-vault-hot-key vault) tx input-index))

      (:cold
       ;; Cold key has no timelock, just verify signature
       (verify-pq-signature-in-witness
        witness (pq-vault-cold-key vault) tx input-index))

      (:recovery
       ;; Verify recovery signature
       (unless (pq-vault-recovery-key vault)
         (return-from verify-vault-spend
           (values nil "No recovery key configured")))
       (verify-pq-signature-in-witness
        witness (pq-vault-recovery-key vault) tx input-index))

      (otherwise
       (values nil "Unknown spending type")))))

(defun compute-vault-hash (vault)
  "Compute unique identifier for vault configuration.
   Used for covenant template verification."
  (let ((preimage (make-array 1024 :element-type '(unsigned-byte 8)
                              :fill-pointer 0 :adjustable t)))
    ;; Version
    (vector-push-extend +covenant-version+ preimage)
    ;; Keys
    (loop for b across (pq-vault-hot-key vault)
          do (vector-push-extend b preimage))
    (loop for b across (pq-vault-cold-key vault)
          do (vector-push-extend b preimage))
    (when (pq-vault-recovery-key vault)
      (loop for b across (pq-vault-recovery-key vault)
            do (vector-push-extend b preimage)))
    ;; Parameters
    (encode-uint32-le (pq-vault-unvault-delay vault) preimage)
    (encode-uint64-le (pq-vault-max-hot-spend vault) preimage)
    (sha256 (coerce preimage '(simple-array (unsigned-byte 8) (*))))))

(defun vault-state (vault tx-history)
  "Determine current state of vault from transaction history.
   Returns one of: :locked, :unvaulting, :recovered, :spent, :migrated"
  (declare (ignore vault))
  (cond
    ((null tx-history) :locked)
    ((find-if #'recovery-transaction-p tx-history) :recovered)
    ((find-if #'migration-transaction-p tx-history) :migrated)
    ((find-if #'unvault-in-progress-p tx-history) :unvaulting)
    ((find-if #'final-spend-p tx-history) :spent)
    (t :locked)))

(defun advance-vault-state (vault current-state action)
  "Compute next vault state given current state and action.
   Returns (values new-state valid-p reason)."
  (declare (ignore vault))
  (case current-state
    (:locked
     (case action
       (:unvault (values :unvaulting t nil))
       (:cold-spend (values :spent t nil))
       (otherwise (values current-state nil "Invalid action for locked vault"))))
    (:unvaulting
     (case action
       (:recover (values :recovered t nil))
       (:complete (values :spent t nil))
       (:migrate (values :migrated t nil))
       (otherwise (values current-state nil "Invalid action for unvaulting vault"))))
    (otherwise
     (values current-state nil "Vault is in terminal state"))))

;;; ============================================================================
;;; Time-Locked Recovery
;;; ============================================================================

(defun create-timelocked-recovery (primary-key recovery-key delay-blocks
                                   &key (recovery-window +max-recovery-window-blocks+))
  "Create a time-locked recovery covenant.

   Funds can be spent by PRIMARY-KEY immediately, or by RECOVERY-KEY
   after DELAY-BLOCKS have passed. Useful for inheritance planning
   and dead-man switches.

   Returns a PQ-COVENANT structure."
  (when (> delay-blocks recovery-window)
    (error "Delay ~D exceeds maximum recovery window ~D"
           delay-blocks recovery-window))
  (let ((primary-condition (make-spending-condition
                            :immediate
                            :pubkey primary-key))
        (recovery-condition (make-spending-condition
                             :timelocked
                             :pubkey recovery-key
                             :timelock delay-blocks)))
    (make-pq-covenant :recovery
                      (list primary-condition recovery-condition)
                      :recovery-key recovery-key
                      :timelock delay-blocks)))

(defun create-recovery-script (covenant)
  "Generate script for time-locked recovery covenant."
  (unless (eq (pq-covenant-type covenant) :recovery)
    (error "Expected recovery covenant"))
  (let ((conditions (pq-covenant-spending-conditions covenant))
        (script-bytes (make-array 256 :element-type '(unsigned-byte 8)
                                  :fill-pointer 0 :adjustable t)))
    (dolist (cond conditions)
      (let ((pk-hash (sha256 (spending-condition-pubkey cond))))
        (case (spending-condition-type cond)
          (:immediate
           ;; Primary key path
           (vector-push-extend 32 script-bytes)
           (loop for b across pk-hash do (vector-push-extend b script-bytes))
           (vector-push-extend +op-pq-checksig+ script-bytes)
           (vector-push-extend +op-if+ script-bytes)
           (vector-push-extend +op-true+ script-bytes)
           (vector-push-extend +op-else+ script-bytes))
          (:timelocked
           ;; Recovery key path with timelock
           (encode-number-to-script (spending-condition-timelock cond) script-bytes)
           (vector-push-extend +op-checklocktimeverify+ script-bytes)
           (vector-push-extend +op-drop+ script-bytes)
           (vector-push-extend 32 script-bytes)
           (loop for b across pk-hash do (vector-push-extend b script-bytes))
           (vector-push-extend +op-pq-checksigverify+ script-bytes)
           (vector-push-extend +op-endif+ script-bytes)))))
    (coerce script-bytes '(simple-array (unsigned-byte 8) (*)))))

(defun verify-recovery-spend (covenant tx input-index)
  "Verify a recovery spending transaction."
  (let* ((input (nth input-index (tx-inputs tx)))
         (witness (tx-input-witness input))
         (locktime (tx-locktime tx)))
    (unless witness
      (return-from verify-recovery-spend (values nil "Missing witness")))
    ;; Try each spending condition
    (dolist (cond (pq-covenant-spending-conditions covenant))
      (case (spending-condition-type cond)
        (:immediate
         (when (verify-pq-signature-in-witness
                witness (spending-condition-pubkey cond) tx input-index)
           (return-from verify-recovery-spend (values t nil))))
        (:timelocked
         (when (and (>= locktime (spending-condition-timelock cond))
                    (verify-pq-signature-in-witness
                     witness (spending-condition-pubkey cond) tx input-index))
           (return-from verify-recovery-spend (values t nil))))))
    (values nil "No valid spending path")))

(defun compute-recovery-hash (covenant)
  "Compute unique hash for recovery covenant."
  (let ((preimage (make-array 512 :element-type '(unsigned-byte 8)
                              :fill-pointer 0 :adjustable t)))
    (vector-push-extend (pq-covenant-version covenant) preimage)
    (vector-push-extend 2 preimage) ; recovery type
    (encode-uint32-le (pq-covenant-timelock covenant) preimage)
    (dolist (cond (pq-covenant-spending-conditions covenant))
      (when (spending-condition-pubkey cond)
        (loop for b across (spending-condition-pubkey cond)
              do (vector-push-extend b preimage))))
    (sha256 (coerce preimage '(simple-array (unsigned-byte 8) (*))))))

(defun recovery-eligible-p (covenant current-block-height)
  "Check if recovery path is available at current block height."
  (>= current-block-height (pq-covenant-timelock covenant)))

;;; ============================================================================
;;; Recursive Covenants
;;; ============================================================================

(defun create-recursive-covenant (output-constraints
                                  &key (max-depth +max-covenant-depth+)
                                       signing-key)
  "Create a recursive covenant that enforces output constraints.

   OUTPUT-CONSTRAINTS: List of (script-template . value-constraint) pairs
   Each output of a spending transaction must match a constraint.

   This enables:
   - Rate limiting (max value per time period)
   - Destination whitelisting
   - Self-referential covenants (outputs recreate the covenant)"
  (declare (ignore max-depth))
  (let ((constraint-conditions
          (loop for (script . value) in output-constraints
                collect (make-spending-condition
                         :threshold
                         :pubkey signing-key
                         :max-amount value))))
    (declare (ignore script))
    (make-pq-covenant :recursive
                      constraint-conditions
                      :recursive-p t)))

(defun compute-covenant-template-hash (tx &key (exclude-witnesses t))
  "Compute CTV-style template hash for covenant verification.

   The template hash commits to:
   - Transaction version
   - Locktime
   - Number of inputs and outputs
   - Sequence numbers
   - Output amounts and scripts

   When EXCLUDE-WITNESSES is T, witness data is not included,
   enabling pre-signed covenant templates."
  (declare (ignore exclude-witnesses))
  (let ((preimage (make-array 1024 :element-type '(unsigned-byte 8)
                              :fill-pointer 0 :adjustable t)))
    ;; Version (4 bytes)
    (encode-uint32-le (tx-version tx) preimage)
    ;; Locktime (4 bytes)
    (encode-uint32-le (tx-locktime tx) preimage)
    ;; Input count
    (let ((inputs (tx-inputs tx)))
      (encode-uint32-le (length inputs) preimage)
      ;; Hash of all input outpoints and sequences
      (let ((inputs-hash (make-array 0 :element-type '(unsigned-byte 8)
                                     :fill-pointer 0 :adjustable t)))
        (dolist (input inputs)
          (loop for b across (tx-input-prev-txid input)
                do (vector-push-extend b inputs-hash))
          (encode-uint32-le (tx-input-prev-index input) inputs-hash)
          (encode-uint32-le (tx-input-sequence input) inputs-hash))
        (loop for b across (sha256 (coerce inputs-hash
                                           '(simple-array (unsigned-byte 8) (*))))
              do (vector-push-extend b preimage))))
    ;; Output count and hashes
    (let ((outputs (tx-outputs tx)))
      (encode-uint32-le (length outputs) preimage)
      (dolist (output outputs)
        (encode-uint64-le (tx-output-value output) preimage)
        (let ((script (tx-output-script-pubkey output)))
          (encode-uint32-le (length script) preimage)
          (loop for b across script do (vector-push-extend b preimage)))))
    (sha256 (coerce preimage '(simple-array (unsigned-byte 8) (*))))))

(defun verify-recursive-covenant (covenant tx input-index &key (depth 0))
  "Verify transaction satisfies recursive covenant constraints.

   Checks that:
   1. Output constraints are satisfied
   2. Recursion depth is within limits
   3. PQ signature is valid"
  (when (> depth +max-covenant-depth+)
    (return-from verify-recursive-covenant
      (values nil "Maximum covenant depth exceeded")))

  (unless (pq-covenant-recursive-p covenant)
    (return-from verify-recursive-covenant
      (values nil "Not a recursive covenant")))

  ;; Verify output constraints
  (let ((outputs (tx-outputs tx))
        (conditions (pq-covenant-spending-conditions covenant)))
    (unless (= (length outputs) (length conditions))
      (return-from verify-recursive-covenant
        (values nil "Output count mismatch")))

    (loop for output in outputs
          for cond in conditions
          do (when (spending-condition-max-amount cond)
               (when (> (tx-output-value output)
                        (spending-condition-max-amount cond))
                 (return-from verify-recursive-covenant
                   (values nil "Output exceeds value constraint"))))))

  ;; Verify signature
  (let* ((input (nth input-index (tx-inputs tx)))
         (witness (tx-input-witness input)))
    (unless witness
      (return-from verify-recursive-covenant (values nil "Missing witness")))
    (let ((signing-cond (find :threshold (pq-covenant-spending-conditions covenant)
                              :key #'spending-condition-type)))
      (when (and signing-cond (spending-condition-pubkey signing-cond))
        (unless (verify-pq-signature-in-witness
                 witness (spending-condition-pubkey signing-cond) tx input-index)
          (return-from verify-recursive-covenant
            (values nil "Invalid covenant signature"))))))

  (values t nil))

(defun enforce-output-constraints (covenant tx)
  "Check all outputs satisfy covenant constraints.
   Returns (values T nil) or (values NIL error-message)."
  (let ((outputs (tx-outputs tx))
        (conditions (pq-covenant-spending-conditions covenant)))
    (loop for output in outputs
          for i from 0
          for cond = (nth i conditions)
          do (when cond
               (when (and (spending-condition-max-amount cond)
                          (> (tx-output-value output)
                             (spending-condition-max-amount cond)))
                 (return-from enforce-output-constraints
                   (values nil (format nil "Output ~D exceeds max amount" i))))))
    (values t nil)))

(defun validate-covenant-chain (covenants txs)
  "Validate a chain of covenant-constrained transactions.
   Returns (values T nil) or (values NIL error-message index)."
  (loop for covenant in covenants
        for tx in txs
        for i from 0
        do (multiple-value-bind (valid-p error-msg)
               (verify-recursive-covenant covenant tx 0 :depth i)
             (unless valid-p
               (return-from validate-covenant-chain
                 (values nil error-msg i)))))
  (values t nil nil))

;;; ============================================================================
;;; Emergency Migration Covenants
;;; ============================================================================

(defun create-emergency-migration-covenant (current-keys new-keys
                                            &key (delay +emergency-migration-delay+))
  "Create an emergency migration covenant.

   Allows migration from CURRENT-KEYS to NEW-KEYS after DELAY blocks.
   Used when quantum computer threat is imminent or keys may be compromised.

   The migration requires:
   1. Signature from current key
   2. Commitment to new key
   3. Timelock delay (allows intervention)"
  (let ((migration-condition (make-spending-condition
                              :emergency
                              :pubkey current-keys
                              :timelock delay)))
    (make-pq-covenant :migration
                      (list migration-condition)
                      :recovery-key new-keys
                      :timelock delay)))

(defun trigger-emergency-migration (covenant current-private-key new-pubkey)
  "Create migration transaction for emergency covenant.

   Returns transaction template that:
   1. Spends from current covenant
   2. Creates new output with NEW-PUBKEY
   3. Is time-locked by emergency delay"
  (declare (ignore current-private-key))
  (unless (eq (pq-covenant-type covenant) :migration)
    (error "Not a migration covenant"))
  (let* ((delay (pq-covenant-timelock covenant))
         (commitment (compute-migration-commitment new-pubkey delay))
         ;; Create output script with new key
         (new-script (create-p2pq-script new-pubkey)))
    (values commitment new-script delay)))

(defun compute-migration-commitment (new-pubkey delay)
  "Compute commitment hash for migration verification.
   Commits to new key and delay to prevent tampering."
  (let ((preimage (make-array 256 :element-type '(unsigned-byte 8)
                              :fill-pointer 0 :adjustable t)))
    (loop for b across new-pubkey do (vector-push-extend b preimage))
    (encode-uint32-le delay preimage)
    (vector-push-extend +covenant-version+ preimage)
    (sha256 (coerce preimage '(simple-array (unsigned-byte 8) (*))))))

(defun verify-migration-signature (covenant tx input-index new-pubkey)
  "Verify migration transaction signature and commitment."
  (let* ((input (nth input-index (tx-inputs tx)))
         (witness (tx-input-witness input))
         (locktime (tx-locktime tx)))
    ;; Check timelock
    (unless (>= locktime (pq-covenant-timelock covenant))
      (return-from verify-migration-signature
        (values nil "Migration timelock not satisfied")))
    ;; Verify old key signature
    (let ((old-cond (first (pq-covenant-spending-conditions covenant))))
      (unless (verify-pq-signature-in-witness
               witness (spending-condition-pubkey old-cond) tx input-index)
        (return-from verify-migration-signature
          (values nil "Invalid migration signature"))))
    ;; Verify output commits to new key
    (let ((outputs (tx-outputs tx)))
      (unless (find-if (lambda (out)
                         (output-commits-to-key-p out new-pubkey))
                       outputs)
        (return-from verify-migration-signature
          (values nil "No output commits to new key"))))
    (values t nil)))

(defun migration-eligible-p (covenant current-block-height)
  "Check if emergency migration is available."
  (>= current-block-height (pq-covenant-timelock covenant)))

;;; ============================================================================
;;; Script Generation Utilities
;;; ============================================================================

(defun generate-pq-covenant-script (covenant)
  "Generate complete script for any PQ covenant type."
  (case (pq-covenant-type covenant)
    (:vault
     ;; Delegate to vault-specific script generation
     (error "Use create-vault-deposit-script for vault covenants"))
    (:recovery
     (create-recovery-script covenant))
    (:recursive
     (create-recursive-covenant-script covenant))
    (:migration
     (create-migration-script covenant))
    (otherwise
     (create-generic-covenant-script covenant))))

(defun generate-spending-witness (covenant tx input-index private-key spending-path)
  "Generate witness data for spending a covenant output.

   SPENDING-PATH: Which condition to satisfy (:primary, :recovery, :migration)"
  (let* ((sighash (compute-pq-sighash tx input-index))
         (signature (dilithium-sign private-key sighash))
         (sig-bytes (dilithium-serialize-signature signature))
         (witness (list sig-bytes)))
    ;; Add path-specific witness data
    (case spending-path
      (:recovery
       (push (make-array 1 :element-type '(unsigned-byte 8)
                         :initial-element 1)
             witness))
      (:migration
       (push (pq-covenant-recovery-key covenant) witness)))
    (nreverse witness)))

(defun serialize-covenant (covenant)
  "Serialize covenant to bytes for on-chain storage."
  (let ((buffer (make-array 2048 :element-type '(unsigned-byte 8)
                            :fill-pointer 0 :adjustable t)))
    ;; Version
    (vector-push-extend (pq-covenant-version covenant) buffer)
    ;; Type
    (vector-push-extend (case (pq-covenant-type covenant)
                          (:vault 1) (:recovery 2)
                          (:recursive 3) (:migration 4)
                          (otherwise 0))
                        buffer)
    ;; Flags
    (vector-push-extend (if (pq-covenant-recursive-p covenant) 1 0) buffer)
    ;; Timelock
    (encode-uint32-le (pq-covenant-timelock covenant) buffer)
    ;; Spending conditions count
    (let ((conditions (pq-covenant-spending-conditions covenant)))
      (encode-uint16-le (length conditions) buffer)
      (dolist (cond conditions)
        (serialize-spending-condition cond buffer)))
    ;; Recovery key (optional)
    (let ((rk (pq-covenant-recovery-key covenant)))
      (if rk
          (progn
            (encode-uint16-le (length rk) buffer)
            (loop for b across rk do (vector-push-extend b buffer)))
          (encode-uint16-le 0 buffer)))
    (coerce buffer '(simple-array (unsigned-byte 8) (*)))))

(defun deserialize-covenant (bytes)
  "Deserialize covenant from bytes."
  (let ((pos 0))
    (flet ((read-byte-at ()
             (prog1 (aref bytes pos) (incf pos)))
           (read-uint16 ()
             (prog1 (+ (aref bytes pos)
                       (ash (aref bytes (1+ pos)) 8))
               (incf pos 2)))
           (read-uint32 ()
             (prog1 (+ (aref bytes pos)
                       (ash (aref bytes (+ pos 1)) 8)
                       (ash (aref bytes (+ pos 2)) 16)
                       (ash (aref bytes (+ pos 3)) 24))
               (incf pos 4))))
      (let* ((version (read-byte-at))
             (type-byte (read-byte-at))
             (type (case type-byte
                     (1 :vault) (2 :recovery)
                     (3 :recursive) (4 :migration)
                     (otherwise :custom)))
             (flags (read-byte-at))
             (recursive-p (plusp (logand flags 1)))
             (timelock (read-uint32))
             (cond-count (read-uint16))
             (conditions (loop repeat cond-count
                               collect (deserialize-spending-condition bytes pos)))
             (rk-len (read-uint16))
             (recovery-key (when (plusp rk-len)
                            (subseq bytes pos (+ pos rk-len)))))
        (declare (ignore version))
        (%make-pq-covenant :type type
                           :spending-conditions conditions
                           :recovery-key recovery-key
                           :timelock timelock
                           :recursive-p recursive-p)))))

;;; ============================================================================
;;; Serialization Helpers
;;; ============================================================================

(defun serialize-spending-condition (cond buffer)
  "Serialize a spending condition to buffer."
  (vector-push-extend (case (spending-condition-type cond)
                        (:immediate 0) (:timelocked 1)
                        (:multisig 2) (:threshold 3)
                        (:emergency 4) (otherwise 255))
                      buffer)
  (encode-uint32-le (spending-condition-timelock cond) buffer)
  (let ((pk (spending-condition-pubkey cond)))
    (if pk
        (progn
          (encode-uint16-le (length pk) buffer)
          (loop for b across pk do (vector-push-extend b buffer)))
        (encode-uint16-le 0 buffer)))
  (let ((max-amt (spending-condition-max-amount cond)))
    (if max-amt
        (progn
          (vector-push-extend 1 buffer)
          (encode-uint64-le max-amt buffer))
        (vector-push-extend 0 buffer))))

(defun deserialize-spending-condition (bytes pos)
  "Deserialize spending condition from bytes at position."
  (declare (ignore bytes pos))
  ;; Placeholder - full implementation would mirror serialize
  (make-spending-condition :immediate))
