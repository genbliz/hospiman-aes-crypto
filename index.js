"use strict";
const crypto = require("crypto");
const buffer_1 = require("buffer");
class EncryptionServiceBase {
  constructor() {
    this.algorithm = "aes-128-cbc";
  }
  getIv() {
    const iv = buffer_1.Buffer.from(crypto.randomBytes(16));
    return iv.toString("hex").slice(0, 16);
  }
  hashEncPassword(secret) {
    return crypto
      .createHash("md5")
      .update(secret.toLowerCase(), "utf8")
      .digest();
  }
  /**
   * @param {string} stringData
   * @param {string} secret
   * @returns {string}
   */
  encodeSync(stringData, secret) {
    try {
      const encIv = this.getIv();
      const key = this.hashEncPassword(secret);
      const cipher = crypto.createCipheriv(this.algorithm, key, encIv);
      let encrypted = cipher.update(stringData, "utf8", "hex");
      encrypted += cipher.final("hex");
      const result = {
        content: encrypted,
        iv: encIv,
      };
      return buffer_1.Buffer.from(JSON.stringify(result)).toString("base64");
    } catch (err) {
      console.log("encodeSync ERROR:");
      console.log(err);
      throw err;
    }
  }
  /**
   * @param {string} stringData
   * @param {string} secret
   * @returns {Promise<string>}
   */
  encode(stringData, secret) {
    return new Promise((resolve, reject) => {
      try {
        const _enc = this.encodeSync(stringData, secret);
        resolve(_enc);
      } catch (e) {
        reject(e);
      }
    });
  }
  /**
   * @param {string} encryptedStringData
   * @param {string} secret
   * @returns {string}
   */
  decodeSync(encryptedStringData, secret) {
    try {
      const encrypted01 = buffer_1.Buffer.from(encryptedStringData, "base64").toString("utf8");
      let encrypted02;
      try {
        encrypted02 = JSON.parse(encrypted01);
      } catch (err) {
        throw new Error("Invalid Encryption Data format...");
      }
      const key = this.hashEncPassword(secret);
      const decipher = crypto.createDecipheriv(this.algorithm, key, encrypted02.iv);
      let dec = decipher.update(encrypted02.content, "hex", "utf8");
      dec += decipher.final("utf8");
      return dec;
    } catch (err) {
      console.log("decodeSync ERROR:");
      console.log(err);
      throw err;
    }
  }
  /**
   * @param {string} stringData
   * @param {string} secret
   * @returns {Promise<string>}
   */
  decode(stringData, secret) {
    return new Promise((resolve, reject) => {
      try {
        const _decData = this.decodeSync(stringData, secret);
        resolve(_decData);
      } catch (e) {
        reject(e);
      }
    });
  }
}
const encryptionService = new EncryptionServiceBase();

module.exports = {
  encode: encryptionService.encode,
  decode: encryptionService.decode,
  decodeSync: encryptionService.decodeSync,
  encodeSync: encryptionService.encodeSync,
};
