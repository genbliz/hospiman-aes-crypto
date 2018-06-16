"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var buffer_1 = require("buffer");
var crypto = __importStar(require("crypto"));
var EncryptionServiceBase = /** @class */ (function () {
    function EncryptionServiceBase() {
        this.algorithm = "aes-128-cbc";
    }
    EncryptionServiceBase.prototype.getIv = function () {
        var iv = buffer_1.Buffer.from(crypto.randomBytes(16));
        return iv.toString("hex").slice(0, 16);
    };
    EncryptionServiceBase.prototype.hashEncPassword = function (secret) {
        return crypto
            .createHash("md5")
            .update(secret.toLowerCase(), "utf8")
            .digest();
    };
    EncryptionServiceBase.prototype.encodeSync = function (stringData, secret) {
        try {
            var encIv = this.getIv();
            //
            var key = this.hashEncPassword(secret);
            //
            var cipher = crypto.createCipheriv(this.algorithm, key, encIv);
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
    };
    EncryptionServiceBase.prototype.encode = function (stringData, secret) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            try {
                var _enc = _this.encodeSync(stringData, secret);
                resolve(_enc);
            }
            catch (e) {
                reject(e);
            }
        });
    };
    EncryptionServiceBase.prototype.decodeSync = function (encryptedStringData, secret) {
        try {
            //
            var encrypted01 = buffer_1.Buffer.from(encryptedStringData, "base64").toString("utf8");
            var encrypted02 = JSON.parse(encrypted01);
            //
            var key = this.hashEncPassword(secret);
            //
            var decipher = crypto.createDecipheriv(this.algorithm, key, encrypted02.iv);
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
    };
    EncryptionServiceBase.prototype.decode = function (stringData, secret) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            try {
                var _decData = _this.decodeSync(stringData, secret);
                resolve(_decData);
            }
            catch (e) {
                reject(e);
            }
        });
    };
    return EncryptionServiceBase;
}());
var valueEnc = new EncryptionServiceBase();
exports.decode = valueEnc.decode;
exports.encode = valueEnc.encode;
exports.decodeSync = valueEnc.decodeSync;
exports.encodeSync = valueEnc.encodeSync;
