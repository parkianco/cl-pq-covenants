;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; verify.lisp - PQ signature verification for scripts

(in-package #:cl-pq-covenants)

;;; ============================================================================
;;; Transaction Structure (minimal for standalone operation)
;;; ============================================================================

(defstruct (transaction (:conc-name tx-))
  "Minimal transaction structure for covenant verification."
  (version 2 :type (unsigned-byte 32))
  (locktime 0 :type (unsigned-byte 32))
  (inputs nil :type list)
  (outputs nil :type list))

(defstruct (tx-input (:conc-name tx-input-))
  "Transaction input."
  (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
             :type (simple-array (unsigned-byte 8) (32)))
  (prev-index 0 :type (unsigned-byte 32))
  (sequence #xFFFFFFFF :type (unsigned-byte 32))
  (witness nil :type list))

(defstruct (tx-output (:conc-name tx-output-))
  "Transaction output."
  (value 0 :type (unsigned-byte 64))
  (script-pubkey #() :type (simple-array (unsigned-byte 8) (*))))

;;; ============================================================================
;;; PQ Signature Verification in Witness
;;; ============================================================================

(defun verify-pq-signature-in-witness (witness pubkey tx input-index)
  "Extract and verify Dilithium signature from witness stack."
  (when (and witness (>= (length witness) 1))
    (let* ((sig-bytes (first witness))
           (sighash (compute-pq-sighash tx input-index)))
      (handler-case
          (let ((signature (dilithium-deserialize-signature sig-bytes))
                (pk (dilithium-deserialize-public-key pubkey)))
            (dilithium-verify pk sighash signature))
        (error () nil)))))

(defun compute-pq-sighash (tx input-index)
  "Compute signature hash for PQ covenant verification.
   Uses BIP341-style tagged hash with PQ domain separator."
  (declare (ignore input-index))
  (let ((template-hash (compute-covenant-template-hash-internal tx)))
    (tagged-hash "PQCovenant/sighash" template-hash)))

(defun compute-covenant-template-hash-internal (tx)
  "Internal template hash computation for sighash."
  (let ((preimage (make-array 512 :element-type '(unsigned-byte 8)
                              :fill-pointer 0 :adjustable t)))
    ;; Version
    (encode-uint32-le (tx-version tx) preimage)
    ;; Locktime
    (encode-uint32-le (tx-locktime tx) preimage)
    ;; Input count
    (encode-uint32-le (length (tx-inputs tx)) preimage)
    ;; Output count and data
    (let ((outputs (tx-outputs tx)))
      (encode-uint32-le (length outputs) preimage)
      (dolist (output outputs)
        (encode-uint64-le (tx-output-value output) preimage)
        (let ((script (tx-output-script-pubkey output)))
          (encode-uint32-le (length script) preimage)
          (loop for b across script do (vector-push-extend b preimage)))))
    (sha256 (coerce preimage '(simple-array (unsigned-byte 8) (*))))))

;;; ============================================================================
;;; Address Decoding
;;; ============================================================================

(defun decode-address-to-hash (address)
  "Decode address to pubkey hash (simplified).
   In production, this would decode bech32/bech32m."
  (sha256 (map '(vector (unsigned-byte 8)) #'char-code address)))

;;; ============================================================================
;;; P2PQ Script Creation
;;; ============================================================================

(defun create-p2pq-script (pubkey)
  "Create P2PQ output script for pubkey."
  (let* ((pk-hash (p2pq-pubkey-hash pubkey))
         (script (make-array 34 :element-type '(unsigned-byte 8))))
    (setf (aref script 0) #x52)  ; OP_2 (witness version 2)
    (setf (aref script 1) 32)    ; Push 32 bytes
    (replace script pk-hash :start1 2)
    script))

(defun output-commits-to-key-p (output pubkey)
  "Check if output script commits to pubkey."
  (let ((script (tx-output-script-pubkey output))
        (expected-hash (p2pq-pubkey-hash pubkey)))
    (and (= (length script) 34)
         (= (aref script 0) #x52)
         (= (aref script 1) 32)
         (equalp (subseq script 2) expected-hash))))

;;; ============================================================================
;;; Transaction State Predicates
;;; ============================================================================

(defun recovery-transaction-p (tx)
  "Check if transaction is a vault recovery."
  (declare (ignore tx))
  ;; Placeholder - would check witness structure
  nil)

(defun migration-transaction-p (tx)
  "Check if transaction is an emergency migration."
  (declare (ignore tx))
  ;; Placeholder - would check witness structure
  nil)

(defun unvault-in-progress-p (tx)
  "Check if transaction is an unvaulting initiation."
  (declare (ignore tx))
  ;; Placeholder - would check output script structure
  nil)

(defun final-spend-p (tx)
  "Check if transaction is a final vault spend."
  (declare (ignore tx))
  ;; Placeholder - would check input structure
  nil)
