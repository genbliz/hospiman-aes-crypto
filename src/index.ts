import { Buffer } from "buffer";
import * as crypto from "crypto";

interface ICipherRaw {
  content: string;
  iv: string;
}

const EncryptionService = (() => {
  const algorithm = "aes-128-cbc";
  function getIv() {
    const iv = Buffer.from(crypto.randomBytes(16));
    return iv.toString("hex").slice(0, 16);
  }
  function hashEncPassword(secret: string) {
    return crypto
      .createHash("md5")
      .update(secret.toLowerCase(), "utf8")
      .digest();
  }
  function encodeSync(stringData: string, secret: string) {
    if (typeof stringData !== "string") {
      throw new Error("Invalid input data. Data input MUST be string only.");
    }
    if (typeof secret !== "string") {
      throw new Error("Invalid input secret. MUST be string only.");
    }
    try {
      const encIv = getIv();
      //
      const key = hashEncPassword(secret);
      //
      const cipher = crypto.createCipheriv(algorithm, key, encIv);
      let encrypted = cipher.update(stringData, "utf8", "hex");
      encrypted += cipher.final("hex");
      const result: ICipherRaw = {
        content: encrypted,
        iv: encIv,
      };
      return Buffer.from(JSON.stringify(result)).toString("base64");
    } catch (err) {
      throw err;
    }
  }
  function encode(stringData: string, secret: string) {
    return new Promise<string>((resolve, reject) => {
      try {
        const _enc = encodeSync(stringData, secret);
        resolve(_enc);
      } catch (e) {
        reject(e);
      }
    });
  }
  function decodeSync(encryptedStringData: string, secret: string) {
    //
    if (typeof encryptedStringData !== "string") {
      throw new Error("Invalid input data. Data input MUST be string only.");
    }
    if (typeof secret !== "string") {
      throw new Error("Invalid input secret. MUST be string only.");
    }
    try {
      const encrypted01 = Buffer.from(encryptedStringData, "base64").toString("utf8");
      const encrypted02: ICipherRaw = JSON.parse(encrypted01);
      //
      const key = hashEncPassword(secret);
      //
      const decipher = crypto.createDecipheriv(algorithm, key, encrypted02.iv);
      //
      let dec = decipher.update(encrypted02.content, "hex", "utf8");
      dec += decipher.final("utf8");
      return dec;
    } catch (err) {
      throw err;
    }
  }
  function decode(stringData: string, secret: string) {
    return new Promise<string>((resolve, reject) => {
      try {
        const _decData = decodeSync(stringData, secret);
        resolve(_decData);
      } catch (e) {
        reject(e);
      }
    });
  }
  return {
    decode,
    encode,
    decodeSync,
    encodeSync,
  };
})();

export const decode = EncryptionService.decode;
export const encode = EncryptionService.encode;
export const decodeSync = EncryptionService.decodeSync;
export const encodeSync = EncryptionService.encodeSync;
