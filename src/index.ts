import { Buffer } from "buffer";
import * as crypto from "crypto";

interface ICipherRaw {
  content: string;
  iv: string;
}

class EncryptionServiceBase {
  private algorithm = "aes-128-cbc";

  private getIv() {
    const iv = Buffer.from(crypto.randomBytes(16));
    return iv.toString("hex").slice(0, 16);
  }

  private hashEncPassword(secret: string) {
    return crypto
      .createHash("md5")
      .update(secret.toLowerCase(), "utf8")
      .digest();
  }

  encodeSync(stringData: string, secret: string) {
    try {
      const encIv = this.getIv();
      //
      const key = this.hashEncPassword(secret);
      //
      const cipher = crypto.createCipheriv(this.algorithm, key, encIv);
      let encrypted = cipher.update(stringData, "utf8", "hex");
      encrypted += cipher.final("hex");
      const result: ICipherRaw = {
        content: encrypted,
        iv: encIv,
      };
      return Buffer.from(JSON.stringify(result)).toString("base64");
    } catch (err) {
      console.log("encodeSync ERROR:");
      console.log(err);
      throw err;
    }
  }

  encode(stringData: string, secret: string) {
    return new Promise<string>((resolve, reject) => {
      try {
        const _enc = this.encodeSync(stringData, secret);
        resolve(_enc);
      } catch (e) {
        reject(e);
      }
    });
  }

  decodeSync(encryptedStringData: string, secret: string) {
    try {
      //
      const encrypted01 = Buffer.from(encryptedStringData, "base64").toString("utf8");
      const encrypted02: ICipherRaw = JSON.parse(encrypted01);
      //
      const key = this.hashEncPassword(secret);
      //
      const decipher = crypto.createDecipheriv(this.algorithm, key, encrypted02.iv);
      //
      let dec = decipher.update(encrypted02.content, "hex", "utf8");
      dec += decipher.final("utf8");
      return dec;
    } catch (err) {
      console.log("decodeSync ERROR:");
      console.log(err);
      throw err;
    }
  }

  decode(stringData: string, secret: string) {
    return new Promise<string>((resolve, reject) => {
      try {
        const _decData = this.decodeSync(stringData, secret);
        resolve(_decData);
      } catch (e) {
        reject(e);
      }
    });
  }
}
const valueEnc = new EncryptionServiceBase();
export const decode = valueEnc.decode;
export const encode = valueEnc.encode;
export const decodeSync = valueEnc.decodeSync;
export const encodeSync = valueEnc.encodeSync;
