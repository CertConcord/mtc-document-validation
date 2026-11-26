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

## 4. Time and protection lifetimes

An authenticated timestamp bounds existence, subject to TSA authority, status and stated accuracy. It does not establish the signer's intention or the exact signing instant. Declared signing time, issuance time and a log clock do not replace that evidence.

For an archive protecting one immutable data object, freeze that object before requesting its first archive timestamp. Later status and authority material may form an augmented version; it MUST NOT rewrite the original object or earlier timestamp input.

Let a timestamp have generation time g, accuracy a, and upper bound u = g + a. The entire interval MUST fit the admitted TSA lifetime and precede or equal evaluation time. Initial archive protection MUST satisfy u less than the original data protection deadline. Ordinary signer-certificate expiry alone is not that deadline.

For consecutive renewals, the previous upper bound MUST be no later than the next lower bound g - a. The next upper bound MUST precede expiry of the previous protection. At evaluation, the final protection MUST still be adequate.

Timestamp renewal preserves the current chain's data hash. Hash renewal replaces that protection and must cover the original object and preceding evidence according to the selected evidence-record format. A later timestamp under an already inadequate data hash cannot repair the intervening gap. For each old hash, the replacing chain's upper bound MUST precede its protection deadline; when no replacement exists, evaluation time MUST precede it.

The reference lifetime function operates only on already authenticated timestamp facts. It does not parse ERS, verify a TSA, or resolve historical trust. A production verifier must perform those checks before using the function.

### 4.1. Original RFC 3161 timestamp claims

When an application admits an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp for retained evidence, it MUST preserve the original `TimeStampResp` and CMS token, the exact bytes whose digest the `TSTInfo` commits to, and the original request when a nonce or requested policy is relied on. It MUST verify the response status, CMS signed attributes and signature over their DER `SET OF` encoding, the encapsulated `TSTInfo` digest, signer certificate identity, the `messageImprint`, requested policy and nonce. When the request sets `certReq`, the signer certificate MUST be included in the response; otherwise an independently admitted copy may be used. A certificate included in the token is a candidate key, not an installed trust anchor. The TSA path, timestamp purpose, applicable status and compromise history, trust policy and clock or receipt basis are admitted independently of the archive.

The bounded reference supports one RSA/SHA-256 CMS signer, a SHA-256 imprint, a directly CA-issued TSA certificate with a critical sole time-stamping EKU, and the SHA-256 `ESSCertIDv2` signer binding of [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816) and [RFC 5035](https://www.rfc-editor.org/rfc/rfc5035). It checks CMS `content-type` and `message-digest` according to [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652). Legacy `ESSCertID` and dual ESS attributes are explicit unsupported forms in this subset; a verifier MUST NOT ignore a second, potentially conflicting signer identifier. An absent `accuracy` is not zero accuracy; unsupported algorithms, certificate paths and valid CMS forms fail explicitly. Production validation MUST process the applicable PKIX critical extensions and historical TSA certificate status beyond this bounded direct-signature reference. A successfully checked token yields `SIGNED_CLAIM` with `genTime`, explicit accuracy and a *claimed* upper bound as exact decimal microsecond integers, not an authenticated proof-of-existence bound. A verifier MUST use exact or conservatively rounded interval arithmetic at subsecond protection deadlines. Only after the selected application separately resolves TSA status, authority, time reliability and the relevant original object coverage may it use that interval as an authenticated fact in the lifetime rules. A timestamp alone does not prove signer intent, document authorization, full ERS continuity or document VALID.

### 4.2. Original binary ERS binding

For a detached [RFC 4998](https://www.rfc-editor.org/rfc/rfc4998) EvidenceRecord, the application MUST identify and freeze the exact archived byte stream before the initial ArchiveTimeStamp. A later augmented package, a reserialized signature container and the original signed object are different byte streams. The verifier MUST retain the original DER EvidenceRecord, its immutable archived object, each embedded `timeStamp` CMS `ContentInfo`, and the original RFC 3161 request when its nonce or requested policy is relied on. An ERS `timeStamp` is a token, not a `TimeStampResp`; validation of a bare token MUST NOT infer a response status or request binding that the retained inputs do not show.

The selected one-object binary subset uses v1 ASN.1 ERS, SHA-256 for the data/tree and timestamp imprint, and the bounded RFC 3161 token checks in §4.1. It MUST verify the declared digest-algorithm union, each original token signature and imprint, and every reduced-tree level. The first `PartialHashtree` contains the object's digest; its hashes are binary sorted at full width. At each higher level the computed parent is inserted virtually among the encoded sibling hashes, sorted and hashed. A record without a reduced tree timestamps the one input directly. Membership of one archived object does not establish that a group contains only that object. The reference reports encrypted records, unhandled ATS attributes, other algorithms and timestamp types as unsupported; `cryptoInfos` cannot appoint an anchor or authenticate historical status.

Within a chain, each later ArchiveTimeStamp MUST bind the complete original DER `ContentInfo` of the preceding `timeStamp`, rather than the preceding whole ArchiveTimeStamp or the original document again. For the first ArchiveTimeStamp of a new chain, this draft selects the numbered construction in RFC 4998 §5.2: `H(H(d) || H(P))`, where `d` is the unchanged archived object and `P` is the complete DER `ArchiveTimeStampSequence` of all preceding chains, including its outer tag and length. RFC 4998 Figure 4 instead describes binary sorting of the two inner hashes. This profile makes the choice explicit and MUST NOT try both until one matches; a validly signed record using that alternate pair order is `UNSUPPORTED` by this subset, not a claim that RFC 4998 itself is invalid. Bare concatenation of chain encodings and omission of earlier chains fail binding. XMLERS under [RFC 6283](https://www.rfc-editor.org/rfc/rfc6283) has separate syntax and processing.

The reference returns `BOUND_CLAIMS` only when the original object, reduced trees, predecessor bytes, signed tokens and claimed time order bind. It marks absent original requests as `NOT_PROVIDED`. These are signed claims, not authenticated preservation continuity or document `VALID`: the selected application MUST separately establish historical TSA path and status, clock reliability, algorithm-protection deadlines, timely renewal, final protection at evaluation, actual document signature coverage, MTC authority/status history and present admissibility before passing authenticated facts to the lifetime rules.

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
