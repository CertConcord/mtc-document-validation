# MTC Document Validation

Long-term validation and preservation requirements for documents signed using Merkle Tree Certificates, including evidence closure, independent monitoring and issuer retirement.

**Draft 01. No stable release or upstream adoption is claimed.**

[Draft](draft.md) defines the technical scope and limits. [Sources](sources.json) pins the upstream documents. [Cases](cases.json) identifies the positive and negative evaluation cases.

The [history vectors](vectors/history.json) constrain the reference decision over already authenticated status and issuer-authorization facts. `SATISFIED` is a history precondition, not a document-validation result. The reference does not verify raw OCSP/CRL bytes, authority signatures, archive completeness or AdES containers.

This repository can be reviewed and used independently of the CertConcord framework. It does not require the framework's authority hierarchy, operation objects or deployment. The framework selects this work through a pinned dependency and adds its own integration policy.

Run with Node.js 24.15 or later:

    npm run check
    npm test

Original text is licensed under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). Upstream material is referenced under its own terms. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).
