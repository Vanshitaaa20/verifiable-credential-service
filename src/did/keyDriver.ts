import * as didKeyMethod from '@digitalbazaar/did-method-key';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';

const driver = didKeyMethod.driver();

driver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey2020.from,
});

export { driver as didKeyDriver };
