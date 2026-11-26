# MTC Document Validation

Long-term validation and preservation requirements for documents signed using Merkle Tree Certificates, including evidence closure, independent monitoring and issuer retirement.

**Draft 01. No stable release or upstream adoption is claimed.**

[Draft](draft.md) defines the technical scope and limits. [Sources](sources.json) pins the upstream documents. [Cases](cases.json) identifies the positive and negative evaluation cases.

This repository can be reviewed and used independently of the CertConcord framework. It does not require the framework's authority hierarchy, operation objects or deployment. The framework selects this work through a pinned dependency and adds its own integration policy.

The [frozen DER corpus](vectors/raw-status-der.json) and [positive and negative cases](vectors/raw-status-cases.json) constrain a narrow [raw-status reference](reference/raw-status.mjs) for RFC 6960 OCSP and RFC 5280 direct CRLs. It checks original signed bytes and their target, signer, request, scope and time bindings under externally admitted policy and receipt facts. A scoped `GOOD` observation does not prove certificate issuance, MTC issuer authorization, a complete history through the knowledge cutoff, or document validity. Unsupported CRL forms and cryptography fail explicitly.

Run with Node.js 24.15 or later:

    npm run check
    npm test

Original text is licensed under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). Upstream material is referenced under its own terms. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).
