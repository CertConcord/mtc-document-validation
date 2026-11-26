# MTC Document Validation — draft 01

Status: independent application draft. Normative keywords describe this proposed profile, not additional requirements of the IETF MTC specification.

## 1. Problem and scope

A document may need verifiable signatures after its signing certificate expires or its issuer retires. Certificate issuance, online service availability and document retention have different lifetimes. This draft specifies the retained inputs and validation decisions for that setting. It does not change MTC certificate bytes, introduce an archive-signature object, define a CA governance hierarchy, or replace an AdES container standard.

The published MTC baseline is draft-ietf-plants-merkle-tree-certs-07, an active Internet-Draft dated 7 October 2026. It assigns PKIX identifiers and permits unknown GREASE cosignatures; a deployment MUST select an exact revision and verifier. The retained editor snapshot is a historical comparison. The signed-artifact starting point is [draft-ietf-plants-mtc-deploy-use-cases-00](https://www.ietf.org/archive/id/draft-ietf-plants-mtc-deploy-use-cases-00.txt), an informational WG Internet-Draft published on 23 October 2026. Its body is unchanged from individual draft-gray-plants-mtc-deploy-use-cases-01. This draft adds a document retention horizon, authority/status history, proof closure and explicit renewal deadlines. The published revision has corrected the landmark row bound; that correction is not a new proposal here.

## 2. Inputs and separate conclusions

The verifier receives original document and signature bytes, an identified application profile, the validation state time, the knowledge time, and externally admitted trust and algorithm policies. Trust MUST NOT be bootstrapped from certificates, checkpoints or policy objects supplied only by the document.

The result distinguishes cryptographic integrity, certificate authorization at the relevant time, preservation continuity, and present admissibility. It records both times and missing dependencies. A historically valid result does not establish current acceptance. A later known compromise may invalidate a signature at an earlier state time according to the applicable policy.

Identity qualification, signing-key possession and authorization for the particular document are separate checks. The selected application identifies their evidence and authority. Login, identity-credential presentation, an issuance inclusion proof and a timestamp are not interchangeable evidence for these claims. This draft does not prescribe a new identity or intent object.

## 3. Retained evidence closure

For self-contained distribution, the signer SHOULD select standalone MTC representation before constructing the signature. Preserve the exact TBSCertificate, proof, extensions, leaf position, inclusion path and required signatures. Retain the corresponding issuer/operator keys, accepted membership and scope, and the policy authenticating their authority. A change from revision-06 placeholder OIDs to revision-07 assigned OIDs changes the issuer name and Merkle leaf commitment. Replacing identifiers in retained certificates is not preservation or migration. Evidence renewal MUST preserve the original bytes and exact verification interpretation; an implementation that no longer supports that revision MUST NOT claim to have validated it under a successor.

A relative certificate requires an explicit preservation contract for its authenticated landmark, log/range scope, epoch, policy and all proof dependencies. A live cache or issuer URL is insufficient. Archived validation MUST NOT lower a live verifier's monotonic trust watermark.

Once the signature commits to a certificate representation, its original bytes MUST remain unchanged. Converting a relative certificate to standalone form does not preserve a commitment to the original encoding. Additional independently validated evidence may be stored only under a declared supplementary binding; this draft does not allocate such a wire format.

The retained set MUST include:

- original content, signature container and certificate representation;
- issuer, cosigner, timestamp and other application-required authority evidence;
- authenticated status history, its coverage and policy decisions for both supplied times;
- required inclusion, consistency and monitoring evidence, including scope;
- time proofs, renewal chains and the evidence needed to validate their authorities.

An unavailable required dependency yields INDETERMINATE. An invalid signature, inconsistent binding or applicable revocation yields INVALID. Required evidence that is stale at the selected time cannot yield VALID. Unsupported revisions fail explicitly; trying a weaker policy is not recovery.

### 3.1. Original status records and historical coverage

When an application admits [RFC 6960 OCSP](https://www.rfc-editor.org/rfc/rfc6960) or [RFC 5280 CRLs](https://www.rfc-editor.org/rfc/rfc5280) as a status source for a particular certificate, it MUST retain the original signed DER record and independently admitted issuer, responder, trust and source policy. An OCSP observation MUST bind the response to the target issuer name, issuer public key and serial, verify the signed ResponseData and responder identity and authority, and compare a retained request nonce when one was used. A matching serial alone, an embedded responder certificate alone, or OCSP `good` alone does not establish issuance, MTC issuer appointment or permission for the document-signing action. A CRL observation MUST verify the original signed TBSCertList, issuer and target scope; absence of an entry is informative only with all required distribution-point and reason coverage. A later record may carry an earlier compromise-effective time, which the selected application must interpret under an explicit policy.

The bounded raw-status reference accepts one target certificate directly signed by an externally admitted CA certificate, a BasicOCSPResponse with a CA signer or a directly CA-issued responder bearing `id-kp-OCSPSigning` and `id-pkix-ocsp-nocheck`, or a complete direct all-reasons CRL for one URI distribution point with no issuing-distribution-point extension. It supports RSA/SHA-256 OCSP and CRL record signatures and SHA-1 or SHA-256 OCSP CertID hashes; SHA-1 here identifies a certificate and is not a permitted status-record signature algorithm. Other path shapes, responder revocation methods, partitioned or indirect CRLs, delta CRLs, additional distribution points, unsupported cryptography and unknown critical status extensions return explicit unresolved or unsupported results. Production verification MUST apply its selected MTC/PKIX certificate interpretation and critical-extension policy independently; this reference does not validate those certificate semantics or install trust anchors from retained material.

The reference's `stateAt` is the selected historical certificate-state time; `knownAt` is the latest admitted knowledge time. A separately authenticated receipt supplied by the caller binds a record hash, source and observed time. The reference checks that binding and rejects a receipt dated before its record, but it does not authenticate the receipt or prove all status changes were captured. `thisUpdate`, `nextUpdate`, `producedAt`, CRL issue time, revocation time and `invalidityDate` remain separate. The application explicitly chooses whether a retained `invalidityDate` governs retrospective compromise; a later revoked record never becomes a prior `good` record by implication. `nextUpdate`, OCSP `archiveCutoff` and one receipt MUST NOT be promoted to `knowledgeThrough` or to a complete historical status interval. `GOOD`, `REVOKED` and `UNKNOWN` are scoped observations from one authenticated record at the chosen state and knowledge times; `INDETERMINATE`, `UNSUPPORTED` and `REJECTED` describe missing coverage, unsupported form or invalid binding. None is an issuer-authorization fact or a document VALID result. A history resolver may use an observation only after independently proving required source completeness and authority history through `knownAt`.

## 4. Time and protection lifetimes

An authenticated timestamp bounds existence, subject to TSA authority, status and stated accuracy. It does not establish the signer's intention or the exact signing instant. Declared signing time, issuance time and a log clock do not replace that evidence.

For an archive protecting one immutable data object, freeze that object before requesting its first archive timestamp. Later status and authority material may form an augmented version; it MUST NOT rewrite the original object or earlier timestamp input.

Let a timestamp have generation time g, accuracy a, and upper bound u = g + a. The entire interval MUST fit the admitted TSA lifetime and precede or equal evaluation time. Initial archive protection MUST satisfy u less than the original data protection deadline. Ordinary signer-certificate expiry alone is not that deadline.

For consecutive renewals, the previous upper bound MUST be no later than the next lower bound g - a. The next upper bound MUST precede expiry of the previous protection. At evaluation, the final protection MUST still be adequate.

Timestamp renewal preserves the current chain's data hash. Hash renewal replaces that protection and must cover the original object and preceding evidence according to the selected evidence-record format. A later timestamp under an already inadequate data hash cannot repair the intervening gap. For each old hash, the replacing chain's upper bound MUST precede its protection deadline; when no replacement exists, evaluation time MUST precede it.

The reference lifetime function operates only on already authenticated timestamp facts. It does not parse ERS, verify a TSA, or resolve historical trust. A production verifier must perform those checks before using the function.

## 5. Monitoring, retirement and archive transfer

Issuance monitoring checks issued certificates, log consistency, operator policy and equivocation under the selected MTC composition. It cannot observe arbitrary later signatures produced with an existing private key. Document-operation monitoring requires separately justified application evidence.

The deployment draft already calls for published batch tree heads to remain available for a period at least as long as the maximum certificate validity period in their batch, including after CA retirement. That lower bound need not cover a longer application validation horizon.

An archive policy MUST state the document validation horizon, responsible custodians, retrieval obligations, status/authority-history sources, algorithm review schedule and succession process. Retention cannot end solely because the signing certificate expired.

Before an issuer or archive operator retires, the successor obtains the retained closure, verifies byte identity and completeness, and records responsibility and access continuity through the deployment's existing administrative mechanism. Partial transfer must not be reported as completed preservation. Transfer does not install new trust anchors or erase earlier compromise information.

## 6. Existing container standards

| Format | Application binding |
| --- | --- |
| CAdES | Preserve exact CMS signature inputs and certificate commitments; apply the selected ETSI timestamp, validation-data and archive rules. |
| PAdES | Preserve the signed PDF revision and ByteRange; distinguish validation augmentation from content changes, and apply DSS and document-timestamp requirements. |
| JAdES | Preserve protected headers, payload mode and signature bytes; use the selected signature-timestamp and archive-timestamp coverage rules. |

The editions in sources.json remain normative for their formats. A detached ERS around an application evidence object does not by itself establish any complete AdES LT/LTA level.

## 7. Security and evidence

Adversarial cases include missing proof material, archive-supplied trust, inconsistent log scope, stale status, retrospective compromise, late renewal, hash-protection gaps, timestamp interval overlap and cross-profile substitution. Availability and privacy of historical lookups remain deployment properties.

The positive and negative cases and reference lifetime tests cover ordering and protection deadlines. Complete historical authority resolution, actual archive succession and all AdES container augmentation require additional implementation evidence. Independent adoption is possible without a particular authority hierarchy or wallet ecosystem.
