;;;; cl-pq-covenants.asd - Post-Quantum Covenant System Definition

(asdf:defsystem #:cl-pq-covenants
  :description "Post-quantum covenant script patterns for blockchain transactions"
  :author "CLPIC Project"
  :license "MIT"
  :version "0.1.0"
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "util")
                             (:file "verify")
                             (:file "script")
                             (:file "covenant")))))

(asdf:defsystem #:cl-pq-covenants/test
  :description "Tests for cl-pq-covenants"
  :depends-on (#:cl-pq-covenants)
  :components ((:module "test"
                :components ((:file "test-covenants")))))
