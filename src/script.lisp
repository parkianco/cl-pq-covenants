;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; script.lisp - Script patterns and opcode definitions

(in-package #:cl-pq-covenants)

;;; ============================================================================
;;; Standard Bitcoin Script Opcodes
;;; ============================================================================

(defconstant +op-0+ #x00 "Push empty array.")
(defconstant +op-false+ #x00 "Alias for OP_0.")
(defconstant +op-1+ #x51 "Push 1.")
(defconstant +op-true+ #x51 "Alias for OP_1.")
(defconstant +op-1negate+ #x4F "Push -1.")
(defconstant +op-if+ #x63 "If condition.")
(defconstant +op-else+ #x67 "Else branch.")
(defconstant +op-endif+ #x68 "End if.")
(defconstant +op-drop+ #x75 "Drop top stack item.")
(defconstant +op-equalverify+ #x88 "OP_EQUAL + OP_VERIFY.")
(defconstant +op-checklocktimeverify+ #xB1 "CLTV opcode.")
(defconstant +op-checksequenceverify+ #xB2 "CSV opcode.")

;;; ============================================================================
;;; PQ Introspection Opcodes (0xD0-0xDF range)
;;; ============================================================================
;;;
;;; These opcodes extend the Bitcoin Script language with post-quantum
;;; signature verification and transaction introspection capabilities.
;;; They operate within the existing script execution context.

(defconstant +op-pq-checksig+ #xD0
  "Verify Dilithium signature on transaction sighash.
   Stack: <sig> <pubkey> -> <result>
   Uses BIP341-style sighash with PQ extension.")

(defconstant +op-pq-checksigverify+ #xD1
  "OP_PQ_CHECKSIG + OP_VERIFY (fail if invalid).")

(defconstant +op-pq-checkmultisig+ #xD2
  "M-of-N Dilithium multisig verification.
   Stack: <sig1>...<sigM> <M> <pk1>...<pkN> <N> -> <result>")

(defconstant +op-pq-checktemplateverify+ #xD3
  "Verify transaction matches committed template (CTV-style).
   Stack: <template-hash> -> (fails if mismatch)
   Enables recursive covenants.")

(defconstant +op-pq-inspectoutputvalue+ #xD4
  "Push output value at index onto stack.
   Stack: <index> -> <value>")

(defconstant +op-pq-inspectoutputscript+ #xD5
  "Push output scriptPubKey at index onto stack.
   Stack: <index> -> <script>")

(defconstant +op-pq-inspectinputvalue+ #xD6
  "Push input value at index onto stack (requires UTXO context).
   Stack: <index> -> <value>")

(defconstant +op-pq-inspecttxversion+ #xD7
  "Push transaction version onto stack.
   Stack: -> <version>")

(defconstant +op-pq-inspecttxlocktime+ #xD8
  "Push transaction locktime onto stack.
   Stack: -> <locktime>")

(defconstant +op-pq-inspectinputcount+ #xD9
  "Push number of inputs onto stack.
   Stack: -> <count>")

(defconstant +op-pq-inspectoutputcount+ #xDA
  "Push number of outputs onto stack.
   Stack: -> <count>")

;;; ============================================================================
;;; Script Number Encoding for Scripts
;;; ============================================================================

(defun encode-number-to-script (n buffer)
  "Encode integer N to script minimal push format."
  (cond
    ((zerop n)
     (vector-push-extend +op-0+ buffer))
    ((<= 1 n 16)
     (vector-push-extend (+ +op-1+ (1- n)) buffer))
    ((= n -1)
     (vector-push-extend +op-1negate+ buffer))
    (t
     ;; Minimal encoding for larger numbers
     (let ((bytes (encode-script-number n)))
       (vector-push-extend (length bytes) buffer)
       (loop for b across bytes do (vector-push-extend b buffer))))))

;;; ============================================================================
;;; Script Generation Utilities
;;; ============================================================================

(defun create-recursive-covenant-script (covenant)
  "Generate script for recursive covenant."
  (let ((script-bytes (make-array 256 :element-type '(unsigned-byte 8)
                                  :fill-pointer 0 :adjustable t)))
    ;; CTV-style template verification
    (vector-push-extend +op-pq-checktemplateverify+ script-bytes)
    ;; Add signing key verification if present
    (let ((signing-cond (find :threshold (pq-covenant-spending-conditions covenant)
                              :key #'spending-condition-type)))
      (when (and signing-cond (spending-condition-pubkey signing-cond))
        (let ((pk-hash (sha256 (spending-condition-pubkey signing-cond))))
          (vector-push-extend 32 script-bytes)
          (loop for b across pk-hash do (vector-push-extend b script-bytes))
          (vector-push-extend +op-pq-checksigverify+ script-bytes))))
    (coerce script-bytes '(simple-array (unsigned-byte 8) (*)))))

(defun create-migration-script (covenant)
  "Generate script for migration covenant."
  (let ((script-bytes (make-array 256 :element-type '(unsigned-byte 8)
                                  :fill-pointer 0 :adjustable t))
        (cond (first (pq-covenant-spending-conditions covenant))))
    ;; Timelock
    (encode-number-to-script (pq-covenant-timelock covenant) script-bytes)
    (vector-push-extend +op-checklocktimeverify+ script-bytes)
    (vector-push-extend +op-drop+ script-bytes)
    ;; Verify old key signature
    (let ((pk-hash (sha256 (spending-condition-pubkey cond))))
      (vector-push-extend 32 script-bytes)
      (loop for b across pk-hash do (vector-push-extend b script-bytes))
      (vector-push-extend +op-pq-checksigverify+ script-bytes))
    ;; Verify new key commitment in outputs
    (when (pq-covenant-recovery-key covenant)
      (let ((new-hash (sha256 (pq-covenant-recovery-key covenant))))
        (vector-push-extend +op-0+ script-bytes)  ; Output index 0
        (vector-push-extend +op-pq-inspectoutputscript+ script-bytes)
        (vector-push-extend 32 script-bytes)
        (loop for b across new-hash do (vector-push-extend b script-bytes))
        (vector-push-extend +op-equalverify+ script-bytes)))
    (coerce script-bytes '(simple-array (unsigned-byte 8) (*)))))

(defun create-generic-covenant-script (covenant)
  "Generate script for generic/custom covenant."
  (let ((script-bytes (make-array 256 :element-type '(unsigned-byte 8)
                                  :fill-pointer 0 :adjustable t)))
    ;; Simple: require signature from first condition
    (let ((cond (first (pq-covenant-spending-conditions covenant))))
      (when cond
        (let ((pk-hash (sha256 (spending-condition-pubkey cond))))
          (vector-push-extend 32 script-bytes)
          (loop for b across pk-hash do (vector-push-extend b script-bytes))
          (vector-push-extend +op-pq-checksigverify+ script-bytes))))
    (coerce script-bytes '(simple-array (unsigned-byte 8) (*)))))
