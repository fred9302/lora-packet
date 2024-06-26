import { decrypt, decryptJoin, generateSessionKeys, decryptJoinAccept, encrypt, generateSessionKeys11, generateSessionKeys10, generateWORSessionKeys, generateWORKey, generateJSKeys } from "./lib/crypto";
import { calculateMIC, recalculateMIC, verifyMIC } from "./lib/mic";
import LoraPacket from "./lib/LoraPacket";
declare const modules: {
    fromWire: typeof LoraPacket.fromWire;
    fromFields: typeof LoraPacket.fromFields;
    decrypt: typeof decrypt;
    decryptJoin: typeof decryptJoin;
    generateSessionKeys: typeof generateSessionKeys;
    generateSessionKeys10: typeof generateSessionKeys10;
    generateSessionKeys11: typeof generateSessionKeys11;
    generateWORSessionKeys: typeof generateWORSessionKeys;
    generateWORKey: typeof generateWORKey;
    generateJSKeys: typeof generateJSKeys;
    decryptJoinAccept: typeof decryptJoinAccept;
    encrypt: typeof encrypt;
    calculateMIC: typeof calculateMIC;
    recalculateMIC: typeof recalculateMIC;
    verifyMIC: typeof verifyMIC;
};
export default modules;
//# sourceMappingURL=lib.d.ts.map