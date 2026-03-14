;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; test-covenants.lisp - Tests for cl-pq-covenants

(defpackage #:cl-pq-covenants/test
  (:use #:cl #:cl-pq-covenants)
  (:export #:run-tests))

(in-package #:cl-pq-covenants/test)

;;; ============================================================================
;;; Test Infrastructure
;;; ============================================================================

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defmacro deftest (name &body body)
  "Define a test case."
  `(defun ,name ()
     (incf *test-count*)
     (handler-case
         (progn
           ,@body
           (incf *pass-count*)
           (format t "~&  PASS: ~A~%" ',name))
       (error (e)
         (incf *fail-count*)
         (format t "~&  FAIL: ~A~%        ~A~%" ',name e)))))

(defmacro assert-true (form &optional message)
  "Assert form evaluates to true."
  `(unless ,form
     (error "Assertion failed: ~A~@[ - ~A~]" ',form ,message)))

(defmacro assert-equal (expected actual &optional message)
  "Assert two values are equal."
  `(unless (equal ,expected ,actual)
     (error "Expected ~S, got ~S~@[ - ~A~]" ,expected ,actual ,message)))

(defmacro assert-signals (condition-type &body body)
  "Assert body signals specified condition type."
  `(handler-case
       (progn ,@body
              (error "Expected ~A to be signaled" ',condition-type))
     (,condition-type () t)))

;;; ============================================================================
;;; Utility Tests
;;; ============================================================================

(deftest test-sha256-empty
  (let ((hash (sha256 "")))
    (assert-true (= (length hash) 32) "SHA256 produces 32 bytes")
    ;; Known hash of empty string
    (assert-equal #xe3 (aref hash 0) "First byte of SHA256('')")))

(deftest test-sha256-hello
  (let ((hash (sha256 "hello")))
    (assert-true (= (length hash) 32))
    ;; Known: SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e...
    (assert-equal #x2c (aref hash 0))
    (assert-equal #xf2 (aref hash 1))))

(deftest test-tagged-hash
  (let ((hash (tagged-hash "test" #(1 2 3))))
    (assert-true (= (length hash) 32))
    ;; Should be different from plain SHA256
    (assert-true (not (equalp hash (sha256 #(1 2 3)))))))

(deftest test-encode-uint32-le
  (let ((buf (make-array 10 :element-type '(unsigned-byte 8) :fill-pointer 0)))
    (encode-uint32-le #x12345678 buf)
    (assert-equal #x78 (aref buf 0))
    (assert-equal #x56 (aref buf 1))
    (assert-equal #x34 (aref buf 2))
    (assert-equal #x12 (aref buf 3))))

;;; ============================================================================
;;; Dilithium Stub Tests
;;; ============================================================================

(deftest test-dilithium-keypair
  (let ((kp (make-dilithium-keypair)))
    (assert-true (dilithium-keypair-p kp))
    (assert-true (= (length (dilithium-keypair-public-key kp))
                    +dilithium-public-key-bytes+))
    (assert-true (= (length (dilithium-keypair-private-key kp))
                    +dilithium-private-key-bytes+))))

(deftest test-dilithium-sign-verify
  (let* ((kp (make-dilithium-keypair))
         (msg #(1 2 3 4 5))
         (sig (dilithium-sign (dilithium-keypair-private-key kp) msg)))
    (assert-true (= (length sig) +dilithium-signature-bytes+))
    ;; Stub always verifies true
    (assert-true (dilithium-verify (dilithium-keypair-public-key kp) msg sig))))

(deftest test-p2pq-pubkey-hash
  (let* ((kp (make-dilithium-keypair))
         (hash (p2pq-pubkey-hash (dilithium-keypair-public-key kp))))
    (assert-true (= (length hash) 32))))

;;; ============================================================================
;;; Spending Condition Tests
;;; ============================================================================

(deftest test-spending-condition-immediate
  (let* ((kp (make-dilithium-keypair))
         (pk (dilithium-keypair-public-key kp))
         (cond (make-spending-condition :immediate :pubkey pk)))
    (assert-true (spending-condition-p cond))
    (assert-equal :immediate (spending-condition-type cond))
    (assert-true (equalp pk (spending-condition-pubkey cond)))))

(deftest test-spending-condition-timelocked
  (let* ((kp (make-dilithium-keypair))
         (pk (dilithium-keypair-public-key kp))
         (cond (make-spending-condition :timelocked
                                        :pubkey pk
                                        :timelock 1000)))
    (assert-equal :timelocked (spending-condition-type cond))
    (assert-equal 1000 (spending-condition-timelock cond))))

(deftest test-spending-condition-validation
  ;; Should error without pubkey for immediate
  (assert-signals error
    (make-spending-condition :immediate))
  ;; Should error without timelock for timelocked
  (let ((pk (dilithium-keypair-public-key (make-dilithium-keypair))))
    (assert-signals error
      (make-spending-condition :timelocked :pubkey pk))))

;;; ============================================================================
;;; Covenant Tests
;;; ============================================================================

(deftest test-pq-covenant-creation
  (let* ((kp (make-dilithium-keypair))
         (pk (dilithium-keypair-public-key kp))
         (cond (make-spending-condition :immediate :pubkey pk))
         (covenant (make-pq-covenant :custom (list cond))))
    (assert-true (pq-covenant-p covenant))
    (assert-equal :custom (pq-covenant-type covenant))
    (assert-equal +covenant-version+ (pq-covenant-version covenant))))

(deftest test-pq-covenant-requires-conditions
  (assert-signals error
    (make-pq-covenant :custom nil)))

(deftest test-vault-requires-two-paths
  (let* ((kp (make-dilithium-keypair))
         (pk (dilithium-keypair-public-key kp))
         (cond (make-spending-condition :immediate :pubkey pk)))
    (assert-signals error
      (make-pq-covenant :vault (list cond)))))

;;; ============================================================================
;;; PQ Vault Tests
;;; ============================================================================

(deftest test-pq-vault-creation
  (let* ((hot-kp (make-dilithium-keypair))
         (cold-kp (make-dilithium-keypair))
         (vault (create-pq-vault hot-kp cold-kp)))
    (assert-true (pq-vault-p vault))
    (assert-equal +min-vault-delay-blocks+ (pq-vault-unvault-delay vault))))

(deftest test-pq-vault-with-recovery
  (let* ((hot-kp (make-dilithium-keypair))
         (cold-kp (make-dilithium-keypair))
         (recovery-kp (make-dilithium-keypair))
         (vault (create-pq-vault hot-kp cold-kp :recovery-keypair recovery-kp)))
    (assert-true (pq-vault-recovery-key vault))))

(deftest test-pq-vault-min-delay
  (let* ((hot-kp (make-dilithium-keypair))
         (cold-kp (make-dilithium-keypair)))
    (assert-signals error
      (create-pq-vault hot-kp cold-kp :unvault-delay 10))))

(deftest test-vault-deposit-script
  (let* ((hot-kp (make-dilithium-keypair))
         (cold-kp (make-dilithium-keypair))
         (vault (create-pq-vault hot-kp cold-kp))
         (script (create-vault-deposit-script vault)))
    (assert-true (> (length script) 0))
    ;; Should contain OP_PQ_CHECKSIG
    (assert-true (find +op-pq-checksig+ script))))

(deftest test-vault-unvault-script
  (let* ((hot-kp (make-dilithium-keypair))
         (cold-kp (make-dilithium-keypair))
         (recovery-kp (make-dilithium-keypair))
         (vault (create-pq-vault hot-kp cold-kp
                                 :recovery-keypair recovery-kp
                                 :max-hot-spend 100000000))
         (script (create-vault-unvault-script vault "bc1qtest" 50000000)))
    (assert-true (> (length script) 0))))

(deftest test-vault-hash
  (let* ((hot-kp (make-dilithium-keypair))
         (cold-kp (make-dilithium-keypair))
         (vault (create-pq-vault hot-kp cold-kp))
         (hash (compute-vault-hash vault)))
    (assert-equal 32 (length hash))))

(deftest test-vault-state-initial
  (let* ((hot-kp (make-dilithium-keypair))
         (cold-kp (make-dilithium-keypair))
         (vault (create-pq-vault hot-kp cold-kp)))
    (assert-equal :locked (vault-state vault nil))))

;;; ============================================================================
;;; Timelocked Recovery Tests
;;; ============================================================================

(deftest test-timelocked-recovery-creation
  (let* ((primary-kp (make-dilithium-keypair))
         (recovery-kp (make-dilithium-keypair))
         (covenant (create-timelocked-recovery
                    (dilithium-keypair-public-key primary-kp)
                    (dilithium-keypair-public-key recovery-kp)
                    52560)))
    (assert-equal :recovery (pq-covenant-type covenant))
    (assert-equal 52560 (pq-covenant-timelock covenant))))

(deftest test-recovery-script-generation
  (let* ((primary-kp (make-dilithium-keypair))
         (recovery-kp (make-dilithium-keypair))
         (covenant (create-timelocked-recovery
                    (dilithium-keypair-public-key primary-kp)
                    (dilithium-keypair-public-key recovery-kp)
                    1000))
         (script (create-recovery-script covenant)))
    (assert-true (> (length script) 0))
    (assert-true (find +op-pq-checksig+ script))))

(deftest test-recovery-eligible
  (let* ((primary-kp (make-dilithium-keypair))
         (recovery-kp (make-dilithium-keypair))
         (covenant (create-timelocked-recovery
                    (dilithium-keypair-public-key primary-kp)
                    (dilithium-keypair-public-key recovery-kp)
                    1000)))
    (assert-true (not (recovery-eligible-p covenant 500)))
    (assert-true (recovery-eligible-p covenant 1000))
    (assert-true (recovery-eligible-p covenant 2000))))

;;; ============================================================================
;;; Recursive Covenant Tests
;;; ============================================================================

(deftest test-recursive-covenant-creation
  (let* ((kp (make-dilithium-keypair))
         (constraints (list (cons nil 100000000)
                            (cons nil 50000000)))
         (covenant (create-recursive-covenant
                    constraints
                    :signing-key (dilithium-keypair-public-key kp))))
    (assert-equal :recursive (pq-covenant-type covenant))
    (assert-true (pq-covenant-recursive-p covenant))))

(deftest test-covenant-template-hash
  (let* ((tx (make-transaction :version 2 :locktime 0)))
    (setf (tx-inputs tx) (list (make-tx-input)))
    (setf (tx-outputs tx) (list (make-tx-output :value 50000000
                                                :script-pubkey #(1 2 3))))
    (let ((hash (compute-covenant-template-hash tx)))
      (assert-equal 32 (length hash)))))

;;; ============================================================================
;;; Emergency Migration Tests
;;; ============================================================================

(deftest test-emergency-migration-creation
  (let* ((old-kp (make-dilithium-keypair))
         (new-kp (make-dilithium-keypair))
         (covenant (create-emergency-migration-covenant
                    (dilithium-keypair-public-key old-kp)
                    (dilithium-keypair-public-key new-kp))))
    (assert-equal :migration (pq-covenant-type covenant))
    (assert-equal +emergency-migration-delay+ (pq-covenant-timelock covenant))))

(deftest test-migration-commitment
  (let* ((kp (make-dilithium-keypair))
         (commitment (compute-migration-commitment
                      (dilithium-keypair-public-key kp)
                      1000)))
    (assert-equal 32 (length commitment))))

(deftest test-migration-eligible
  (let* ((old-kp (make-dilithium-keypair))
         (new-kp (make-dilithium-keypair))
         (covenant (create-emergency-migration-covenant
                    (dilithium-keypair-public-key old-kp)
                    (dilithium-keypair-public-key new-kp)
                    :delay 1000)))
    (assert-true (not (migration-eligible-p covenant 500)))
    (assert-true (migration-eligible-p covenant 1000))))

;;; ============================================================================
;;; Serialization Tests
;;; ============================================================================

(deftest test-covenant-serialization
  (let* ((kp (make-dilithium-keypair))
         (pk (dilithium-keypair-public-key kp))
         (cond (make-spending-condition :immediate :pubkey pk))
         (covenant (make-pq-covenant :recovery (list cond)
                                     :timelock 1000))
         (bytes (serialize-covenant covenant)))
    (assert-true (> (length bytes) 0))
    ;; First byte should be version
    (assert-equal +covenant-version+ (aref bytes 0))
    ;; Second byte should be type (recovery = 2)
    (assert-equal 2 (aref bytes 1))))

;;; ============================================================================
;;; Script Generation Tests
;;; ============================================================================

(deftest test-script-opcodes-defined
  (assert-equal #xD0 +op-pq-checksig+)
  (assert-equal #xD1 +op-pq-checksigverify+)
  (assert-equal #xD3 +op-pq-checktemplateverify+))

(deftest test-p2pq-script-creation
  (let* ((kp (make-dilithium-keypair))
         (script (create-p2pq-script (dilithium-keypair-public-key kp))))
    (assert-equal 34 (length script))
    (assert-equal #x52 (aref script 0))  ; witness v2
    (assert-equal 32 (aref script 1))))   ; push 32 bytes

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-tests ()
  "Run all tests and report results."
  (setf *test-count* 0 *pass-count* 0 *fail-count* 0)
  (format t "~&Running cl-pq-covenants tests...~%~%")

  ;; Utility tests
  (format t "~&Utility Tests:~%")
  (test-sha256-empty)
  (test-sha256-hello)
  (test-tagged-hash)
  (test-encode-uint32-le)

  ;; Dilithium tests
  (format t "~&~%Dilithium Stub Tests:~%")
  (test-dilithium-keypair)
  (test-dilithium-sign-verify)
  (test-p2pq-pubkey-hash)

  ;; Spending condition tests
  (format t "~&~%Spending Condition Tests:~%")
  (test-spending-condition-immediate)
  (test-spending-condition-timelocked)
  (test-spending-condition-validation)

  ;; Covenant tests
  (format t "~&~%Covenant Tests:~%")
  (test-pq-covenant-creation)
  (test-pq-covenant-requires-conditions)
  (test-vault-requires-two-paths)

  ;; Vault tests
  (format t "~&~%PQ Vault Tests:~%")
  (test-pq-vault-creation)
  (test-pq-vault-with-recovery)
  (test-pq-vault-min-delay)
  (test-vault-deposit-script)
  (test-vault-unvault-script)
  (test-vault-hash)
  (test-vault-state-initial)

  ;; Recovery tests
  (format t "~&~%Timelocked Recovery Tests:~%")
  (test-timelocked-recovery-creation)
  (test-recovery-script-generation)
  (test-recovery-eligible)

  ;; Recursive covenant tests
  (format t "~&~%Recursive Covenant Tests:~%")
  (test-recursive-covenant-creation)
  (test-covenant-template-hash)

  ;; Migration tests
  (format t "~&~%Emergency Migration Tests:~%")
  (test-emergency-migration-creation)
  (test-migration-commitment)
  (test-migration-eligible)

  ;; Serialization tests
  (format t "~&~%Serialization Tests:~%")
  (test-covenant-serialization)

  ;; Script tests
  (format t "~&~%Script Generation Tests:~%")
  (test-script-opcodes-defined)
  (test-p2pq-script-creation)

  ;; Summary
  (format t "~&~%========================================~%")
  (format t "Tests: ~D  Passed: ~D  Failed: ~D~%"
          *test-count* *pass-count* *fail-count*)
  (format t "========================================~%")

  (zerop *fail-count*))
