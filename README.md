# MTC Document Validation

Long-term validation and preservation requirements for documents signed using Merkle Tree Certificates, including evidence closure, independent monitoring and issuer retirement.

**Draft 01. No stable release or upstream adoption is claimed.**

[Draft](draft.md) defines the technical scope and limits. [Sources](sources.json) pins the upstream documents. [Cases](cases.json) identifies the positive and negative evaluation cases.

The [history vectors](vectors/history.json) constrain a fact-only decision over already authenticated status and issuer-authorization facts. `SATISFIED` is a history precondition, not a document-validation result. This fact resolver does not itself verify the raw records, archive completeness or AdES containers.

This repository can be reviewed and used independently of the CertConcord framework. It does not require the framework's authority hierarchy, operation objects or deployment. The framework selects this work through a pinned dependency and adds its own integration policy.

The [archive-availability vectors](vectors/archive-availability.json) exercise separate post-retirement checks for an admitted published-head inventory and the selected document's declared evidence set. The reference consumes independently admitted facts and reports byte availability at one check time; it does not establish complete document validity or future access.

The [transfer-continuity vectors](vectors/transfer-continuity.json) test two successive custodians against an admitted original-object and prior-evidence inventory. Recorded responsibility and observed transfer-time bytes are separate results; neither proves present or future retrieval.

The [frozen DER corpus](vectors/raw-status-der.json) and [positive and negative cases](vectors/raw-status-cases.json) constrain a narrow [raw-status reference](reference/raw-status.mjs) for RFC 6960 OCSP and RFC 5280 direct CRLs. It checks original signed bytes and their target, signer, request, scope and time bindings under externally admitted policy and receipt facts. A scoped `GOOD` observation does not prove certificate issuance, MTC issuer authorization, a complete history through the knowledge cutoff, or document validity. Unsupported CRL forms and cryptography fail explicitly.

The [frozen timestamp corpus](vectors/raw-timestamp-der.json) and [positive and negative cases](vectors/raw-timestamp-cases.json) constrain a bounded [timestamp reference](reference/raw-timestamp.mjs). It contains original DER records and exact covered bytes, and verifies a signed TSA claim about those bytes, including CMS attributes, ESS certificate identity and the original request when retained. `SIGNED_CLAIM` does not establish historical TSA status, clock reliability, signature coverage, full preservation continuity or document validity; those require independent application evidence.

The [original binary ERS corpus](vectors/raw-ers-der.json) and [binding cases](vectors/raw-ers-cases.json) constrain a detached, one-object [ERS reference](reference/raw-ers.mjs). It checks original RFC 4998 DER, reduced trees, exact preceding timestamp bytes and data plus prior-chain hash renewal using the signed CMS tokens embedded in the record. `BOUND_CLAIMS` remains subject to independently authenticated TSA history, algorithm protection, renewal timing and document-signature validation.

The [original signed authority corpus](vectors/raw-authority-bytes.json) and [cases](vectors/raw-authority-cases.json) constrain a bounded [authority-history reference](reference/raw-authority-history.mjs). It checks exact source-signed appointment and document-action statements, source sequence links, claimed knowledge cutoffs and the exact document hash. `BOUND_CLAIMS` authenticates only those source claims and their internal binding. The application must independently admit each source and establish trustworthy time, actual source completeness, signer-to-document binding and succession before using them as historical facts or returning document validity.

The [original MTC certificate corpus](vectors/raw-mtc-der.json) and [issuance cases](vectors/raw-mtc-cases.json) constrain a bounded [standalone MTC proof reference](reference/raw-mtc-issuance.mjs) under the selected revision 07. It checks the original X.509 DER structure and TLS proof bytes, reconstructed log-entry and subtree hashes, admitted CA serial bounds, and CA and required cosigner signatures. `ISSUANCE_PROVEN` is only the certificate-signature step; X.509 path, historical status and authority, document signature, trusted time and preservation remain separate.

The [one-leaf original relative corpus](vectors/raw-mtc-relative.json), [multi-leaf direct corpus](vectors/raw-mtc-relative-multileaf.json) and their [one-leaf](vectors/raw-mtc-relative-cases.json) and [multi-leaf](vectors/raw-mtc-relative-multileaf-cases.json) cases constrain a bounded [landmark-relative issuance reference](reference/raw-mtc-relative.mjs). It verifies the selected subtree against a directly cosigned checkpoint through an original MTC consistency proof, with publication identity, log scope and minimum tree size admitted outside the archive. The multi-leaf positive connects nonempty certificate and consistency paths to a distinct signed root. Unadmitted extra checkpoint signatures cannot supply a required role or veto the admitted set. `RELATIVE_ISSUANCE_BOUND` is an issuance-provenance result, not document validity. Other algorithm suites remain outside the reference.

The same reference also accepts each required role's original signature on a later containing checkpoint when an [RFC 9162 consistency proof](reference/raw-mtc-log-consistency.mjs) connects the authenticated reference root to that signed later root. Its [seven-entry original corpus](vectors/raw-mtc-later-checkpoint.json), [composition cases](vectors/raw-mtc-later-checkpoint-cases.json) and [ordered prefix-proof cases](vectors/raw-mtc-log-consistency.json) cover direct and later signatures, distinct later sizes, and failed signature, log, root, size and proof bindings. This adds an append-only checkpoint edge under the selected MTC -07 profile; it does not establish trusted time, all published checkpoints, historical status or document validity.

The [active-subtree-set reference](reference/raw-mtc-active-subtrees.mjs) checks both canonical subtrees of every selected active landmark against one authenticated reference checkpoint. Its [original publication, log and proof corpus](vectors/raw-mtc-active-subtree-set.json) and [positive and negative cases](vectors/raw-mtc-active-subtree-cases.json) distinguish a complete set relative to one independently admitted publication from an explicitly declared older contiguous suffix. A canonical empty subtree is retained but cannot contain a certificate. Publication source and freshness, per-log watermark and a CA-wide cap allocation must be admitted independently; these results do not prove a current global publication inventory or document validity.

Run with Node.js 24.15 or later:

    npm run check
    npm test

Original text is licensed under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). Upstream material is referenced under its own terms. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).
