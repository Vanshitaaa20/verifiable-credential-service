// None of the @digitalbazaar/* signing-suite packages ship type declarations.
// Rather than hand-maintain types for a vendor library's internal shapes,
// treat them as `any` at the boundary and rely on our own interfaces
// (GeneratedDid, IssueCredentialInput, etc.) for type safety in our code.
declare module '@digitalbazaar/vc';
declare module '@digitalbazaar/ed25519-signature-2020';
declare module '@digitalbazaar/ed25519-verification-key-2020';
declare module '@digitalbazaar/did-method-key';
declare module '@digitalbazaar/credentials-context';
declare module '@digitalbazaar/credentials-examples-context';
declare module 'jsonld-signatures';
declare module 'ed25519-signature-2020-context';
declare module '@digitalbazaar/vc-status-list';
declare module '@digitalbazaar/vc-status-list-context';
