;; hash-verified-repository

;; Error codes for operation responses
(define-constant ERR_NOT_FOUND (err u401))
(define-constant ERR_ALREADY_EXISTS (err u402))
(define-constant ERR_SIZE_VIOLATION (err u403))
(define-constant ERR_VALUE_VIOLATION (err u404))
(define-constant ERR_UNAUTHORIZED (err u405))
(define-constant ERR_OWNERSHIP_VIOLATION (err u406))
(define-constant ERR_ADMIN_REQUIRED (err u400))
(define-constant ERR_TAG_VIOLATION (err u407))
(define-constant ERR_PERMISSION_VIOLATION (err u408))


(define-map authorization-ledger
  { record-key: uint, requester-principal: principal }
  { has-authorization: bool }
)

(define-map integrity-records
  { record-key: uint }
  {
    check-block: uint,
    checker-principal: principal,
    integrity-value: uint,
    check-passed: bool
  }
)

(define-map incident-records
  { record-key: uint, incident-block: uint }
  {
    severity-level: uint,
    incident-description: (string-ascii 128),
    incident-identifier: (string-ascii 16),
    response-action: (string-ascii 32),
    responder-principal: principal,
    impacted-principal: principal,
    incident-state: (string-ascii 16)
  }
)

;; System authority principal
(define-constant system-authority tx-sender)

;; Record storage maps
(define-map content-ledger
  { record-key: uint }
  {
    content-id: (string-ascii 64),
    owner-principal: principal,
    weight-value: uint,
    creation-block: uint,
    hash-signature: (string-ascii 128),
    metadata-tags: (list 10 (string-ascii 32))
  }
)

;; Global sequence counter
(define-data-var sequence-counter uint u0)

;; Helper function to check record presence
(define-private (is-record-present (record-key uint))
  (is-some (map-get? content-ledger { record-key: record-key }))
)

;; Helper function to extract weight from record
(define-private (extract-weight (record-key uint))
  (default-to u0
    (get weight-value
      (map-get? content-ledger { record-key: record-key })
    )
  )
)

;; Helper function to verify ownership rights
(define-private (verify-ownership (record-key uint) (owner-principal principal))
  (match (map-get? content-ledger { record-key: record-key })
    record-details (is-eq (get owner-principal record-details) owner-principal)
    false
  )
)

;; Tag validation helper for single tag
(define-private (is-tag-valid (tag (string-ascii 32)))
  (and 
    (> (len tag) u0)
    (< (len tag) u33)
  )
)

;; Tag validation helper for tag collection
(define-private (validate-tag-collection (tags (list 10 (string-ascii 32))))
  (and
    (> (len tags) u0)
    (<= (len tags) u10)
    (is-eq (len (filter is-tag-valid tags)) (len tags))
  )
)

;; Public function to register new content record
(define-public (register-content 
  (content-id (string-ascii 64))
  (weight-value uint)
  (hash-signature (string-ascii 128))
  (metadata-tags (list 10 (string-ascii 32)))
)
  (let
    (
      (record-key (+ (var-get sequence-counter) u1))
    )
    ;; Input validation
    (asserts! (> (len content-id) u0) ERR_SIZE_VIOLATION)
    (asserts! (< (len content-id) u65) ERR_SIZE_VIOLATION)
    (asserts! (> weight-value u0) ERR_VALUE_VIOLATION)
    (asserts! (< weight-value u1000000000) ERR_VALUE_VIOLATION)
    (asserts! (> (len hash-signature) u0) ERR_SIZE_VIOLATION)
    (asserts! (< (len hash-signature) u129) ERR_SIZE_VIOLATION)
    (asserts! (validate-tag-collection metadata-tags) ERR_TAG_VIOLATION)

    ;; Insert new record
    (map-insert content-ledger
      { record-key: record-key }
      {
        content-id: content-id,
        owner-principal: tx-sender,
        weight-value: weight-value,
        creation-block: block-height,
        hash-signature: hash-signature,
        metadata-tags: metadata-tags
      }
    )

    ;; Grant self-authorization
    (map-insert authorization-ledger
      { record-key: record-key, requester-principal: tx-sender }
      { has-authorization: true }
    )

    ;; Increment sequence
    (var-set sequence-counter record-key)
    (ok record-key)
  )
)

;; Public function to update existing record
(define-public (update-content 
  (record-key uint)
  (content-id (string-ascii 64))
  (weight-value uint)
  (hash-signature (string-ascii 128))
  (metadata-tags (list 10 (string-ascii 32)))
)
  (let
    (
      (record-details (unwrap! (map-get? content-ledger { record-key: record-key }) ERR_NOT_FOUND))
    )
    ;; Validation checks
    (asserts! (is-record-present record-key) ERR_NOT_FOUND)
    (asserts! (is-eq (get owner-principal record-details) tx-sender) ERR_UNAUTHORIZED)
    (asserts! (> (len content-id) u0) ERR_SIZE_VIOLATION)
    (asserts! (< (len content-id) u65) ERR_SIZE_VIOLATION)
    (asserts! (> weight-value u0) ERR_VALUE_VIOLATION)
    (asserts! (< weight-value u1000000000) ERR_VALUE_VIOLATION)
    (asserts! (> (len hash-signature) u0) ERR_SIZE_VIOLATION)
    (asserts! (< (len hash-signature) u129) ERR_SIZE_VIOLATION)
    (asserts! (validate-tag-collection metadata-tags) ERR_TAG_VIOLATION)

    ;; Update record
    (map-set content-ledger
      { record-key: record-key }
      (merge record-details { 
        content-id: content-id, 
        weight-value: weight-value, 
        hash-signature: hash-signature, 
        metadata-tags: metadata-tags 
      })
    )
    (ok true)
  )
)

;; Public function to reassign record ownership
(define-public (reassign-ownership (record-key uint) (new-owner principal))
  (let
    (
      (record-details (unwrap! (map-get? content-ledger { record-key: record-key }) ERR_NOT_FOUND))
    )
    ;; Ownership verification
    (asserts! (is-record-present record-key) ERR_NOT_FOUND)
    (asserts! (is-eq (get owner-principal record-details) tx-sender) ERR_UNAUTHORIZED)

    ;; Reassign owner
    (map-set content-ledger
      { record-key: record-key }
      (merge record-details { owner-principal: new-owner })
    )
    (ok true)
  )
)

;; Public function to compute integrity score
(define-public (compute-integrity-score 
  (record-key uint)
  (score-inputs (list 5 uint))
)
  (let
    (
      (record-details (unwrap! (map-get? content-ledger { record-key: record-key }) ERR_NOT_FOUND))
      (input-count (len score-inputs))
      (owner-principal (get owner-principal record-details))
      (record-age (- block-height (get creation-block record-details)))
    )
    ;; Input validation
    (asserts! (is-record-present record-key) ERR_NOT_FOUND)
    (asserts! (> input-count u0) ERR_SIZE_VIOLATION)
    (asserts! (<= input-count u5) ERR_SIZE_VIOLATION)
    (asserts! (or 
      (is-eq owner-principal tx-sender)
      (is-eq system-authority tx-sender)
    ) ERR_UNAUTHORIZED)

    ;; Score computation
    (let
      (
        (raw-score (fold + score-inputs u0))
        (age-adjustment (if (> record-age u1000) u10 u0))
        (weight-adjustment (if (> (get weight-value record-details) u1000) u5 u0))
        (tag-adjustment (if (> (len (get metadata-tags record-details)) u3) u3 u0))
        (computed-score (- (+ raw-score weight-adjustment tag-adjustment) age-adjustment))
      )
      ;; Threshold check
      (asserts! (>= computed-score u10) ERR_VALUE_VIOLATION)

      ;; Record integrity check
      (map-set integrity-records
        { record-key: record-key }
        {
          check-block: block-height,
          checker-principal: tx-sender,
          integrity-value: computed-score,
          check-passed: true
        }
      )

      (ok {
        security-score: computed-score,
        validation-passed: true,
        validation-block: block-height,
        next-validation-due: (+ block-height u2000)
      })
    )
  )
)

;; Helper function to process authorization change
(define-private (process-authorization-change 
  (record-key uint) 
  (requester-principal principal) 
  (authorize bool)
)
  (let
    (
      (record-details (unwrap! (map-get? content-ledger { record-key: record-key }) false))
    )
    ;; Ownership check before authorization change
    (if (and 
          (is-record-present record-key)
          (is-eq (get owner-principal record-details) tx-sender)
        )
      (begin
        (if authorize
          (map-set authorization-ledger
            { record-key: record-key, requester-principal: requester-principal }
            { has-authorization: true }
          )
          (map-set authorization-ledger
            { record-key: record-key, requester-principal: requester-principal }
            { has-authorization: false }
          )
        )
        true
      )
      false
    )
  )
)

;; Public function to manage multiple authorizations
(define-public (manage-bulk-authorizations 
  (record-keys (list 20 uint)) 
  (requester-principals (list 20 principal)) 
  (authorize-flags (list 20 bool))
)
  (let
    (
      (keys-count (len record-keys))
      (principals-count (len requester-principals))
      (flags-count (len authorize-flags))
    )
    ;; Array length validation
    (asserts! (> keys-count u0) ERR_SIZE_VIOLATION)
    (asserts! (<= keys-count u20) ERR_SIZE_VIOLATION)
    (asserts! (is-eq keys-count principals-count) ERR_SIZE_VIOLATION)
    (asserts! (is-eq keys-count flags-count) ERR_SIZE_VIOLATION)

    ;; Bulk processing
    (ok (map process-authorization-change 
      record-keys 
      requester-principals 
      authorize-flags
    ))
  )
)

;; Public function to validate hash integrity
(define-public (validate-hash-integrity (record-key uint) (expected-hash (string-ascii 128)))
  (let
    (
      (record-details (unwrap! (map-get? content-ledger { record-key: record-key }) ERR_NOT_FOUND))
      (stored-hash (get hash-signature record-details))
      (stored-weight (get weight-value record-details))
      (stored-block (get creation-block record-details))
    )
    ;; Presence and format validation
    (asserts! (is-record-present record-key) ERR_NOT_FOUND)
    (asserts! (> (len expected-hash) u0) ERR_SIZE_VIOLATION)
    (asserts! (< (len expected-hash) u129) ERR_SIZE_VIOLATION)

    ;; Hash comparison
    (asserts! (is-eq stored-hash expected-hash) ERR_SIZE_VIOLATION)

    ;; Data consistency checks
    (asserts! (> stored-weight u0) ERR_VALUE_VIOLATION)
    (asserts! (> stored-block u0) ERR_VALUE_VIOLATION)
    (asserts! (<= stored-block block-height) ERR_VALUE_VIOLATION)

    ;; Return validation result
    (ok {
      verified: true,
      entry-weight: stored-weight,
      verification-block: block-height,
      signature-match: true
    })
  )
)

;; Public function to check authorization level
(define-public (check-authorization-level (record-key uint) (requester-principal principal) (level-required uint))
  (let
    (
      (record-details (unwrap! (map-get? content-ledger { record-key: record-key }) ERR_NOT_FOUND))
      (auth-details (map-get? authorization-ledger { record-key: record-key, requester-principal: requester-principal }))
    )
    ;; Existence and level validation
    (asserts! (is-record-present record-key) ERR_NOT_FOUND)
    (asserts! (> level-required u0) ERR_VALUE_VIOLATION)
    (asserts! (<= level-required u5) ERR_VALUE_VIOLATION)

    ;; Owner check has highest level
    (if (is-eq (get owner-principal record-details) requester-principal)
      (ok u5)
      ;; Check explicit authorization
      (match auth-details
        auth-record
          (if (get has-authorization auth-record)
            (ok u3)
            ERR_PERMISSION_VIOLATION
          )
        ERR_PERMISSION_VIOLATION
      )
    )
  )
)


