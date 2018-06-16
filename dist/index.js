"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var buffer_1 = require("buffer");
var EncryptionService = (function () {
    var algorithm = "aes-128-cbc";
    function getIv() {
        var iv = buffer_1.Buffer.from(crypto.randomBytes(16));
        return iv.toString("hex").slice(0, 16);
    }
    function hashEncPassword(secret) {
        return crypto
            .createHash("md5")
            .update(secret.toLowerCase(), "utf8")
            .digest();
    }
    function encodeSync(stringData, secret) {
        try {
            var encIv = getIv();
            //
            var key = hashEncPassword(secret);
            //
            var cipher = crypto.createCipheriv(algorithm, key, encIv);
            var encrypted = cipher.update(stringData, "utf8", "hex");
            encrypted += cipher.final("hex");
            var result = {
                content: encrypted,
                iv: encIv,
            };
            return buffer_1.Buffer.from(JSON.stringify(result)).toString("base64");
        }
        catch (err) {
            console.log("encodeSync ERROR:");
            console.log(err);
            throw err;
        }
    }
    function encode(stringData, secret) {
        return new Promise(function (resolve, reject) {
            try {
                var _enc = encodeSync(stringData, secret);
                resolve(_enc);
            }
            catch (e) {
                reject(e);
            }
        });
    }
    function decodeSync(encryptedStringData, secret) {
        try {
            //
            var encrypted01 = buffer_1.Buffer.from(encryptedStringData, "base64").toString("utf8");
            var encrypted02 = JSON.parse(encrypted01);
            //
            var key = hashEncPassword(secret);
            //
            var decipher = crypto.createDecipheriv(algorithm, key, encrypted02.iv);
            //
            var dec = decipher.update(encrypted02.content, "hex", "utf8");
            dec += decipher.final("utf8");
            return dec;
        }
        catch (err) {
            console.log("decodeSync ERROR:");
            console.log(err);
            throw err;
        }
    }
    function decode(stringData, secret) {
        return new Promise(function (resolve, reject) {
            try {
                var _decData = decodeSync(stringData, secret);
                resolve(_decData);
            }
            catch (e) {
                reject(e);
            }
        });
    }
    return {
        decode: decode,
        encode: encode,
        decodeSync: decodeSync,
        encodeSync: encodeSync,
    };
})();
exports.decode = EncryptionService.decode;
exports.encode = EncryptionService.encode;
exports.decodeSync = EncryptionService.decodeSync;
exports.encodeSync = EncryptionService.encodeSync;
