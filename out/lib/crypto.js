"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateJSKeys = exports.generateWORSessionKeys = exports.generateWORKey = exports.generateSessionKeys10 = exports.generateSessionKeys11 = exports.generateSessionKeys = exports.decryptJoinAccept = exports.decryptFOpts = exports.decryptJoin = exports.decrypt = exports.encrypt = void 0;
const util_1 = require("./util");
const crypto_js_1 = __importDefault(require("crypto-js"));
const buffer_1 = require("buffer");
const LORAIV = crypto_js_1.default.enc.Hex.parse("00000000000000000000000000000000");
var KeyType11;
(function (KeyType11) {
    KeyType11["FNwkSIntKey"] = "01";
    KeyType11["AppSKey"] = "02";
    KeyType11["SNwkSIntKey"] = "03";
    KeyType11["NwkSEncKey"] = "04";
})(KeyType11 || (KeyType11 = {}));
var KeyType10;
(function (KeyType10) {
    KeyType10["NwkSKey"] = "01";
    KeyType10["AppSKey"] = "02";
})(KeyType10 || (KeyType10 = {}));
var KeyTypeJS;
(function (KeyTypeJS) {
    KeyTypeJS["JSIntKey"] = "06";
    KeyTypeJS["JSEncKey"] = "05";
})(KeyTypeJS || (KeyTypeJS = {}));
var KeyTypeWORSession;
(function (KeyTypeWORSession) {
    KeyTypeWORSession["WorSIntKey"] = "01";
    KeyTypeWORSession["WorSEncKey"] = "02";
})(KeyTypeWORSession || (KeyTypeWORSession = {}));
function decrypt(payload, AppSKey, NwkSKey, fCntMSB32) {
    if (!payload.PHYPayload || !payload.FRMPayload)
        throw new Error("Payload was not defined");
    if (!fCntMSB32)
        fCntMSB32 = buffer_1.Buffer.alloc(2, 0);
    const blocks = Math.ceil(payload.FRMPayload.length / 16);
    const sequenceS = buffer_1.Buffer.alloc(16 * blocks);
    for (let block = 0; block < blocks; block++) {
        const ai = _metadataBlockAi(payload, block, fCntMSB32);
        ai.copy(sequenceS, block * 16);
    }
    const key = payload.getFPort() === 0 ? NwkSKey : AppSKey;
    if (!key || key.length !== 16)
        throw new Error("Expected a appropriate key with length 16");
    const cipherstream_base64 = crypto_js_1.default.AES.encrypt(crypto_js_1.default.enc.Hex.parse(sequenceS.toString("hex")), crypto_js_1.default.enc.Hex.parse(key.toString("hex")), {
        mode: crypto_js_1.default.mode.ECB,
        iv: LORAIV,
        padding: crypto_js_1.default.pad.NoPadding,
    });
    const cipherstream = buffer_1.Buffer.from(cipherstream_base64.toString(), "base64");
    const plaintextPayload = buffer_1.Buffer.alloc(payload.FRMPayload.length);
    for (let i = 0; i < payload.FRMPayload.length; i++) {
        const Si = cipherstream.readUInt8(i);
        plaintextPayload.writeUInt8(Si ^ payload.FRMPayload.readUInt8(i), i);
    }
    return plaintextPayload;
}
exports.decrypt = decrypt;
// Check
function decryptJoin(payload, AppKey) {
    if (!(payload === null || payload === void 0 ? void 0 : payload.MACPayloadWithMIC))
        throw new Error("Expected parsed payload to be defined");
    if (AppKey.length !== 16)
        throw new Error("Expected a appropriate key with length 16");
    const cipherstream = crypto_js_1.default.AES.decrypt(payload.MACPayloadWithMIC.toString("base64"), crypto_js_1.default.enc.Hex.parse(AppKey.toString("hex")), {
        mode: crypto_js_1.default.mode.ECB,
        padding: crypto_js_1.default.pad.NoPadding,
    });
    return buffer_1.Buffer.from(cipherstream.toString(), "hex");
}
exports.decryptJoin = decryptJoin;
function decryptFOpts(payload, NwkSEncKey, fCntMSB32) {
    if (!fCntMSB32)
        fCntMSB32 = buffer_1.Buffer.alloc(2);
    if (!(payload === null || payload === void 0 ? void 0 : payload.FOpts))
        throw new Error("Expected FOpts to be defined");
    if (!(payload === null || payload === void 0 ? void 0 : payload.DevAddr))
        throw new Error("Expected DevAddr to be defined");
    if (NwkSEncKey.length !== 16)
        throw new Error("Expected a appropriate key with length 16");
    if (!payload.FCnt)
        throw new Error("Expected FCnt to be defined");
    const direction = buffer_1.Buffer.alloc(1);
    let aFCntDown = false;
    if (payload.getDir() == "up") {
        direction.writeUInt8(0, 0);
    }
    else if (payload.getDir() == "down") {
        direction.writeUInt8(1, 0);
        if (payload.FPort != null && payload.getFPort() > 0) {
            aFCntDown = true;
        }
    }
    else {
        throw new Error("Decrypt error: expecting direction to be either 'up' or 'down'");
    }
    // https://lora-alliance.org/wp-content/uploads/2020/11/00001.002.00001.001.cr-fcntdwn-usage-in-fopts-encryption-v2-r1.pdf
    const aBuffer = buffer_1.Buffer.concat([
        buffer_1.Buffer.alloc(1, 1),
        buffer_1.Buffer.alloc(3, 0),
        buffer_1.Buffer.alloc(1, aFCntDown ? 2 : 1),
        direction,
        util_1.reverseBuffer(payload.DevAddr),
        util_1.reverseBuffer(payload.FCnt),
        fCntMSB32,
        buffer_1.Buffer.alloc(1, 0),
        buffer_1.Buffer.alloc(1, 1),
    ]);
    const cipherstream_base64 = crypto_js_1.default.AES.encrypt(crypto_js_1.default.enc.Hex.parse(aBuffer.toString("hex")), crypto_js_1.default.enc.Hex.parse(NwkSEncKey.toString("hex")), {
        mode: crypto_js_1.default.mode.ECB,
        iv: LORAIV,
        padding: crypto_js_1.default.pad.NoPadding,
    });
    const cipherstream = buffer_1.Buffer.from(cipherstream_base64.toString(), "base64");
    const plaintextPayload = buffer_1.Buffer.alloc(payload.FOpts.length);
    for (let i = 0; i < payload.FOpts.length; i++) {
        plaintextPayload[i] = cipherstream[i] ^ payload.FOpts[i];
    }
    return plaintextPayload;
}
exports.decryptFOpts = decryptFOpts;
function generateKey(key, AppNonce, NetIdOrJoinEui, DevNonce, keyType) {
    let keyNonceStr = keyType;
    keyNonceStr += util_1.reverseBuffer(AppNonce).toString("hex");
    keyNonceStr += util_1.reverseBuffer(NetIdOrJoinEui).toString("hex");
    keyNonceStr += util_1.reverseBuffer(DevNonce).toString("hex");
    keyNonceStr = keyNonceStr.padEnd(32, "0");
    const keyNonce = buffer_1.Buffer.from(keyNonceStr, "hex");
    const nwkSKey_base64 = crypto_js_1.default.AES.encrypt(crypto_js_1.default.enc.Hex.parse(keyNonce.toString("hex")), crypto_js_1.default.enc.Hex.parse(key.toString("hex")), {
        mode: crypto_js_1.default.mode.ECB,
        padding: crypto_js_1.default.pad.NoPadding,
    });
    return buffer_1.Buffer.from(nwkSKey_base64.toString(), "base64");
}
function generateSessionKeys(AppKey, NetId, AppNonce, DevNonce) {
    return generateSessionKeys10(AppKey, NetId, AppNonce, DevNonce);
}
exports.generateSessionKeys = generateSessionKeys;
function generateSessionKeys10(AppKey, NetId, AppNonce, DevNonce) {
    if (AppKey.length !== 16)
        throw new Error("Expected a AppKey with length 16");
    if (NetId.length !== 3)
        throw new Error("Expected a NetId with length 3");
    if (AppNonce.length !== 3)
        throw new Error("Expected a AppNonce with length 3");
    if (DevNonce.length !== 2)
        throw new Error("Expected a DevNonce with length 2");
    return {
        AppSKey: generateKey(AppKey, AppNonce, NetId, DevNonce, KeyType10.AppSKey),
        NwkSKey: generateKey(AppKey, AppNonce, NetId, DevNonce, KeyType10.NwkSKey),
    };
}
exports.generateSessionKeys10 = generateSessionKeys10;
function generateSessionKeys11(AppKey, NwkKey, JoinEUI, AppNonce, DevNonce) {
    if (AppKey.length !== 16)
        throw new Error("Expected a AppKey with length 16");
    if (NwkKey.length !== 16)
        throw new Error("Expected a NwkKey with length 16");
    if (AppNonce.length !== 3)
        throw new Error("Expected a AppNonce with length 3");
    if (DevNonce.length !== 2)
        throw new Error("Expected a DevNonce with length 2");
    return {
        AppSKey: generateKey(AppKey, AppNonce, JoinEUI, DevNonce, KeyType11.AppSKey),
        FNwkSIntKey: generateKey(NwkKey, AppNonce, JoinEUI, DevNonce, KeyType11.FNwkSIntKey),
        SNwkSIntKey: generateKey(NwkKey, AppNonce, JoinEUI, DevNonce, KeyType11.SNwkSIntKey),
        NwkSEncKey: generateKey(NwkKey, AppNonce, JoinEUI, DevNonce, KeyType11.NwkSEncKey),
    };
}
exports.generateSessionKeys11 = generateSessionKeys11;
function generateJSKeys(NwkKey, DevEui) {
    if (DevEui.length !== 8)
        throw new Error("Expected a DevEui with length 8");
    if (NwkKey.length !== 16)
        throw new Error("Expected a NwkKey with length 16");
    return {
        JSIntKey: generateKey(NwkKey, DevEui, buffer_1.Buffer.alloc(0), buffer_1.Buffer.alloc(0), KeyTypeJS.JSIntKey),
        JSEncKey: generateKey(NwkKey, DevEui, buffer_1.Buffer.alloc(0), buffer_1.Buffer.alloc(0), KeyTypeJS.JSEncKey),
    };
}
exports.generateJSKeys = generateJSKeys;
function generateWORKey(NwkSKey) {
    if (NwkSKey.length !== 16)
        throw new Error("Expected a NwkKey/NwkSEncKey with length 16");
    return {
        RootWorSKey: generateKey(NwkSKey, buffer_1.Buffer.alloc(0), buffer_1.Buffer.alloc(0), buffer_1.Buffer.alloc(0), KeyTypeWORSession.WorSIntKey),
    };
}
exports.generateWORKey = generateWORKey;
function generateWORSessionKeys(RootWorSKey, DevAddr) {
    if (DevAddr.length !== 4)
        throw new Error("Expected a DevAddr with length 4");
    if (RootWorSKey.length !== 16)
        throw new Error("Expected a RootWorSKey with length 16");
    return {
        WorSIntKey: generateKey(RootWorSKey, DevAddr, buffer_1.Buffer.alloc(0), buffer_1.Buffer.alloc(0), KeyTypeWORSession.WorSIntKey),
        WorSEncKey: generateKey(RootWorSKey, DevAddr, buffer_1.Buffer.alloc(0), buffer_1.Buffer.alloc(0), KeyTypeWORSession.WorSEncKey),
    };
}
exports.generateWORSessionKeys = generateWORSessionKeys;
function encrypt(buffer, key) {
    // CHECK
    const ciphertext = crypto_js_1.default.AES.encrypt(crypto_js_1.default.enc.Hex.parse(buffer.toString("hex")), crypto_js_1.default.enc.Hex.parse(key.toString("hex")), {
        mode: crypto_js_1.default.mode.ECB,
        iv: LORAIV,
        padding: crypto_js_1.default.pad.NoPadding,
    }).ciphertext.toString(crypto_js_1.default.enc.Hex);
    return buffer_1.Buffer.from(ciphertext, "hex");
}
exports.encrypt = encrypt;
function decryptJoinAccept(payload, appKey) {
    const payloadBuffer = payload.PHYPayload || buffer_1.Buffer.alloc(0);
    // Check
    const mhdr = payloadBuffer.slice(0, 1);
    const joinAccept = encrypt(payloadBuffer.slice(1), appKey);
    return buffer_1.Buffer.concat([mhdr, joinAccept]);
}
exports.decryptJoinAccept = decryptJoinAccept;
// Encrypt stream mixes in metadata blocks, as Ai =
//   0x01
//   0x00 0x00 0x00 0x00
//   direction-uplink/downlink [1]
//   DevAddr [4]
//   FCnt as 32-bit, lsb first [4]
//   0x00
//   counter = i [1]
function _metadataBlockAi(payload, blockNumber, fCntMSB32) {
    if (!fCntMSB32)
        fCntMSB32 = buffer_1.Buffer.alloc(2);
    let direction;
    if (payload.getDir() == "up") {
        direction = buffer_1.Buffer.alloc(1, 0);
    }
    else if (payload.getDir() == "down") {
        direction = buffer_1.Buffer.alloc(1, 1);
    }
    else {
        throw new Error("Decrypt error: expecting direction to be either 'up' or 'down'");
    }
    if (!payload.DevAddr)
        throw new Error("Decrypt error: DevAddr not defined'");
    if (!payload.FCnt)
        throw new Error("Decrypt error: FCnt not defined'");
    const aiBuffer = buffer_1.Buffer.concat([
        buffer_1.Buffer.from("0100000000", "hex"),
        direction,
        util_1.reverseBuffer(payload.DevAddr),
        util_1.reverseBuffer(payload.FCnt),
        fCntMSB32,
        buffer_1.Buffer.alloc(1, 0),
        buffer_1.Buffer.alloc(1, blockNumber + 1),
    ]);
    return aiBuffer;
}
//# sourceMappingURL=crypto.js.map