;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; util.lisp - Utility functions and inlined PQ crypto primitives

(in-package #:cl-pq-covenants)

;;; ============================================================================
;;; Type Definitions
;;; ============================================================================

(deftype octet-vector ()
  "A simple vector of unsigned bytes."
  '(simple-array (unsigned-byte 8) (*)))

(deftype covenant-type ()
  "Type of PQ covenant."
  '(member :vault :recovery :recursive :migration :custom))

(deftype spending-condition-type ()
  "Type of spending condition."
  '(member :immediate :timelocked :multisig :threshold :emergency))

(deftype vault-state ()
  "State of a PQ vault."
  '(member :locked :unvaulting :recovered :spent :migrated))

;;; ============================================================================
;;; Encoding Utilities
;;; ============================================================================

(defun encode-uint16-le (n buffer)
  "Encode 16-bit unsigned integer little-endian."
  (vector-push-extend (logand n #xFF) buffer)
  (vector-push-extend (logand (ash n -8) #xFF) buffer))

(defun encode-uint32-le (n buffer)
  "Encode 32-bit unsigned integer little-endian."
  (vector-push-extend (logand n #xFF) buffer)
  (vector-push-extend (logand (ash n -8) #xFF) buffer)
  (vector-push-extend (logand (ash n -16) #xFF) buffer)
  (vector-push-extend (logand (ash n -24) #xFF) buffer))

(defun encode-uint64-le (n buffer)
  "Encode 64-bit unsigned integer little-endian."
  (loop for i from 0 below 8
        do (vector-push-extend (logand (ash n (* i -8)) #xFF) buffer)))

(defun decode-uint16-le (bytes offset)
  "Decode 16-bit unsigned integer little-endian."
  (+ (aref bytes offset)
     (ash (aref bytes (+ offset 1)) 8)))

(defun decode-uint32-le (bytes offset)
  "Decode 32-bit unsigned integer little-endian."
  (+ (aref bytes offset)
     (ash (aref bytes (+ offset 1)) 8)
     (ash (aref bytes (+ offset 2)) 16)
     (ash (aref bytes (+ offset 3)) 24)))

;;; ============================================================================
;;; Script Number Encoding
;;; ============================================================================

(defun encode-script-number (n)
  "Encode integer as Bitcoin script number (minimal, sign-magnitude)."
  (when (zerop n)
    (return-from encode-script-number #()))
  (let* ((negative (< n 0))
         (abs-n (abs n))
         (bytes (make-array 8 :element-type '(unsigned-byte 8)
                            :fill-pointer 0)))
    (loop while (plusp abs-n)
          do (vector-push-extend (logand abs-n #xFF) bytes)
             (setf abs-n (ash abs-n -8)))
    ;; Handle sign bit
    (if (plusp (logand (aref bytes (1- (length bytes))) #x80))
        (vector-push-extend (if negative #x80 #x00) bytes)
        (when negative
          (setf (aref bytes (1- (length bytes)))
                (logior (aref bytes (1- (length bytes))) #x80))))
    (coerce bytes '(simple-array (unsigned-byte 8) (*)))))

;;; ============================================================================
;;; SHA-256 Implementation (standalone)
;;; ============================================================================

(defvar +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA-256 round constants.")

(defvar +sha256-init+
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
  "SHA-256 initial hash values.")

(defun rotr32 (x n)
  "32-bit right rotation."
  (logand #xFFFFFFFF
          (logior (ash x (- n))
                  (ash x (- 32 n)))))

(defun sha256-pad-message (message)
  "Pad message according to SHA-256 specification."
  (let* ((len (length message))
         (bit-len (* len 8))
         (pad-len (- 64 (mod (+ len 1 8) 64)))
         (pad-len (if (< pad-len 0) (+ pad-len 64) pad-len))
         (total-len (+ len 1 pad-len 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8))))
    ;; Copy message
    (replace padded message)
    ;; Append 1 bit (0x80)
    (setf (aref padded len) #x80)
    ;; Append length in bits (big-endian)
    (loop for i from 0 below 8
          do (setf (aref padded (- total-len 1 i))
                   (logand #xFF (ash bit-len (* i -8)))))
    padded))

(defun sha256-process-block (block state)
  "Process a single 512-bit block."
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    ;; Prepare message schedule
    (loop for i from 0 below 16
          for j = (* i 4)
          do (setf (aref w i)
                   (logior (ash (aref block j) 24)
                           (ash (aref block (+ j 1)) 16)
                           (ash (aref block (+ j 2)) 8)
                           (aref block (+ j 3)))))
    (loop for i from 16 below 64
          for s0 = (logxor (rotr32 (aref w (- i 15)) 7)
                           (rotr32 (aref w (- i 15)) 18)
                           (ash (aref w (- i 15)) -3))
          for s1 = (logxor (rotr32 (aref w (- i 2)) 17)
                           (rotr32 (aref w (- i 2)) 19)
                           (ash (aref w (- i 2)) -10))
          do (setf (aref w i)
                   (logand #xFFFFFFFF
                           (+ (aref w (- i 16)) s0
                              (aref w (- i 7)) s1))))
    ;; Working variables
    (let ((a (aref state 0)) (b (aref state 1))
          (c (aref state 2)) (d (aref state 3))
          (e (aref state 4)) (f (aref state 5))
          (g (aref state 6)) (h (aref state 7)))
      ;; Main loop
      (loop for i from 0 below 64
            for s1 = (logxor (rotr32 e 6) (rotr32 e 11) (rotr32 e 25))
            for ch = (logxor (logand e f) (logand (lognot e) g))
            for temp1 = (logand #xFFFFFFFF
                                (+ h s1 ch (aref +sha256-k+ i) (aref w i)))
            for s0 = (logxor (rotr32 a 2) (rotr32 a 13) (rotr32 a 22))
            for maj = (logxor (logand a b) (logand a c) (logand b c))
            for temp2 = (logand #xFFFFFFFF (+ s0 maj))
            do (setf h g
                     g f
                     f e
                     e (logand #xFFFFFFFF (+ d temp1))
                     d c
                     c b
                     b a
                     a (logand #xFFFFFFFF (+ temp1 temp2))))
      ;; Update state
      (setf (aref state 0) (logand #xFFFFFFFF (+ (aref state 0) a)))
      (setf (aref state 1) (logand #xFFFFFFFF (+ (aref state 1) b)))
      (setf (aref state 2) (logand #xFFFFFFFF (+ (aref state 2) c)))
      (setf (aref state 3) (logand #xFFFFFFFF (+ (aref state 3) d)))
      (setf (aref state 4) (logand #xFFFFFFFF (+ (aref state 4) e)))
      (setf (aref state 5) (logand #xFFFFFFFF (+ (aref state 5) f)))
      (setf (aref state 6) (logand #xFFFFFFFF (+ (aref state 6) g)))
      (setf (aref state 7) (logand #xFFFFFFFF (+ (aref state 7) h))))))

(defun sha256 (message)
  "Compute SHA-256 hash of message (octet vector or string).
   Returns 32-byte octet vector."
  (let* ((input (etypecase message
                  ((simple-array (unsigned-byte 8) (*)) message)
                  (string (map '(vector (unsigned-byte 8)) #'char-code message))))
         (padded (sha256-pad-message input))
         (state (copy-seq +sha256-init+)))
    ;; Process each 64-byte block
    (loop for i from 0 below (length padded) by 64
          do (sha256-process-block (subseq padded i (+ i 64)) state))
    ;; Convert state to bytes
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for w = (aref state i)
            do (setf (aref result (* i 4)) (logand #xFF (ash w -24)))
               (setf (aref result (+ (* i 4) 1)) (logand #xFF (ash w -16)))
               (setf (aref result (+ (* i 4) 2)) (logand #xFF (ash w -8)))
               (setf (aref result (+ (* i 4) 3)) (logand #xFF w)))
      result)))

(defun tagged-hash (tag message)
  "Compute BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || message)."
  (let* ((tag-hash (sha256 tag))
         (preimage (make-array (+ 64 (length message))
                               :element-type '(unsigned-byte 8))))
    (replace preimage tag-hash :start1 0)
    (replace preimage tag-hash :start1 32)
    (replace preimage message :start1 64)
    (sha256 preimage)))

;;; ============================================================================
;;; Dilithium PQ Signature Stubs (NIST FIPS 204 ML-DSA)
;;; ============================================================================
;;;
;;; This is a minimal stub implementation for API compatibility.
;;; Production use requires a verified Dilithium implementation.
;;; Parameters: Dilithium3 (NIST security level 3)

(defconstant +dilithium-public-key-bytes+ 1952
  "Dilithium3 public key size in bytes.")

(defconstant +dilithium-private-key-bytes+ 4000
  "Dilithium3 private key size in bytes.")

(defconstant +dilithium-signature-bytes+ 3293
  "Dilithium3 signature size in bytes.")

(defstruct (dilithium-keypair (:constructor %make-dilithium-keypair))
  "A Dilithium key pair."
  (public-key nil :type (or null octet-vector) :read-only t)
  (private-key nil :type (or null octet-vector) :read-only t))

(defun make-dilithium-keypair (&optional seed)
  "Generate a Dilithium keypair from optional seed.
   WARNING: This is a stub. Use verified implementation for production."
  (let* ((seed-bytes (or seed
                         (let ((s (make-array 32 :element-type '(unsigned-byte 8))))
                           (dotimes (i 32 s)
                             (setf (aref s i) (random 256))))))
         (pk-seed (sha256 (concatenate '(vector (unsigned-byte 8))
                                       seed-bytes #(0))))
         (sk-seed (sha256 (concatenate '(vector (unsigned-byte 8))
                                       seed-bytes #(1))))
         ;; Expand to full key sizes (stub: repeat hash)
         (public-key (make-array +dilithium-public-key-bytes+
                                 :element-type '(unsigned-byte 8)))
         (private-key (make-array +dilithium-private-key-bytes+
                                  :element-type '(unsigned-byte 8))))
    ;; Fill with deterministic bytes (stub)
    (loop for i from 0 below +dilithium-public-key-bytes+
          do (setf (aref public-key i)
                   (aref pk-seed (mod i 32))))
    (loop for i from 0 below +dilithium-private-key-bytes+
          do (setf (aref private-key i)
                   (aref sk-seed (mod i 32))))
    (%make-dilithium-keypair :public-key public-key
                             :private-key private-key)))

(defun dilithium-sign (private-key message)
  "Sign message with Dilithium private key.
   WARNING: This is a stub. Use verified implementation for production."
  (let ((sig (make-array +dilithium-signature-bytes+
                         :element-type '(unsigned-byte 8)))
        (msg-hash (sha256 message)))
    ;; Stub: combine private key hash with message hash
    (let ((combined (sha256 (concatenate '(vector (unsigned-byte 8))
                                         (subseq private-key 0 32)
                                         msg-hash))))
      (loop for i from 0 below +dilithium-signature-bytes+
            do (setf (aref sig i)
                     (aref combined (mod i 32)))))
    sig))

(defun dilithium-verify (public-key message signature)
  "Verify Dilithium signature.
   WARNING: This is a stub. Use verified implementation for production."
  (declare (ignore public-key message signature))
  ;; Stub always returns T - replace with real verification
  t)

(defun dilithium-serialize-public-key (key)
  "Serialize Dilithium public key to bytes."
  (etypecase key
    ((simple-array (unsigned-byte 8) (*)) key)
    (dilithium-keypair (dilithium-keypair-public-key key))))

(defun dilithium-deserialize-public-key (bytes)
  "Deserialize bytes to Dilithium public key."
  (unless (= (length bytes) +dilithium-public-key-bytes+)
    (error "Invalid Dilithium public key length: ~D (expected ~D)"
           (length bytes) +dilithium-public-key-bytes+))
  bytes)

(defun dilithium-serialize-signature (sig)
  "Serialize Dilithium signature to bytes."
  sig)

(defun dilithium-deserialize-signature (bytes)
  "Deserialize bytes to Dilithium signature."
  (unless (= (length bytes) +dilithium-signature-bytes+)
    (error "Invalid Dilithium signature length: ~D (expected ~D)"
           (length bytes) +dilithium-signature-bytes+))
  bytes)

;;; ============================================================================
;;; P2PQ Address Utilities
;;; ============================================================================

(defun p2pq-pubkey-hash (pubkey)
  "Compute P2PQ pubkey hash (SHA256 of serialized Dilithium public key)."
  (sha256 (dilithium-serialize-public-key pubkey)))
