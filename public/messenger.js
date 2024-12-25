'use strict';

/** ******* Imports ********/

import {
  generateKeyPair,
  deriveSharedKey,
  encrypt,
  decrypt,
  sign,
  verify,
  generateSalt,
  hkdf,
} from 'browser-encrypted';

/** ******* Implementation ********/

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
    this.EGKeyPair = null; // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {
    const keypair = await generateKeyPair();
    this.EGKeyPair = keypair;

    const certificate = {
      username,
      pub: keypair.publicKey,
    };

    return certificate;
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: string
   *
   * Return Type: void
   */
  async receiveCertificate(certificate, signature) {
    const certString = JSON.stringify(certificate);
    const isValid = await verify(this.caPublicKey, certString, signature);

    if (isValid) {
      this.certs[certificate.username] = certificate;
    } else {
      throw new Error('Tampered certificate!');
    }
  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, string]
   */
  async sendMessage(name, plaintext) {
    const cert = this.certs[name];

    if (!this.conns[name]) {
      const sharedKey = await deriveSharedKey(this.EGKeyPair.privateKey, cert.pub);
      this.conns[name] = {
        keypair: this.EGKeyPair,
        rootKey: sharedKey,
        sendCounter: 0,
        receiveCounter: 0,
      };
    }

    const connState = this.conns[name];
    const sendCounter = connState.sendCounter;

    const salt = generateSalt();
    const derivedKey = await hkdf(connState.rootKey, salt, 'AES-GCM');

    const ciphertext = await encrypt(plaintext, derivedKey);
    const messageHeader = {
      pub: connState.keypair.publicKey,
      salt,
      sendCounter,
    };

    connState.sendCounter += 1;

    return [messageHeader, ciphertext];
  }

  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, string]
   *
   * Return Type: string
   */
  async receiveMessage(name, [header, ciphertext]) {
    const cert = this.certs[name];

    if (!this.conns[name]) {
      const sharedKey = await deriveSharedKey(this.EGKeyPair.privateKey, cert.pub);
      this.conns[name] = {
        keypair: this.EGKeyPair,
        rootKey: sharedKey,
        sendCounter: 0,
        receiveCounter: 0,
      };
    }

    const connState = this.conns[name];

    const derivedKey = await hkdf(connState.rootKey, header.salt, 'AES-GCM');
    const plaintext = await decrypt(ciphertext, derivedKey);

    connState.receiveCounter = Math.max(connState.receiveCounter, header.sendCounter + 1);

    return plaintext;
  }
}

export default MessengerClient;
