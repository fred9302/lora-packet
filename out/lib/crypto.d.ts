/// <reference types="node" />
import LoraPacket from "./LoraPacket";
declare function decrypt(payload: LoraPacket, AppSKey?: Buffer, NwkSKey?: Buffer, fCntMSB32?: Buffer): Buffer;
declare function decryptJoin(payload: LoraPacket, AppKey: Buffer): Buffer;
declare function decryptFOpts(payload: LoraPacket, NwkSEncKey: Buffer, fCntMSB32?: Buffer): Buffer;
declare function generateSessionKeys(AppKey: Buffer, NetId: Buffer, AppNonce: Buffer, DevNonce: Buffer): {
    AppSKey: Buffer;
    NwkSKey: Buffer;
};
declare function generateSessionKeys10(AppKey: Buffer, NetId: Buffer, AppNonce: Buffer, DevNonce: Buffer): {
    AppSKey: Buffer;
    NwkSKey: Buffer;
};
declare function generateSessionKeys11(AppKey: Buffer, NwkKey: Buffer, JoinEUI: Buffer, AppNonce: Buffer, DevNonce: Buffer): {
    AppSKey: Buffer;
    FNwkSIntKey: Buffer;
    SNwkSIntKey: Buffer;
    NwkSEncKey: Buffer;
};
declare function generateJSKeys(NwkKey: Buffer, DevEui: Buffer): {
    JSIntKey: Buffer;
    JSEncKey: Buffer;
};
declare function generateWORKey(NwkSKey: Buffer): {
    RootWorSKey: Buffer;
};
declare function generateWORSessionKeys(RootWorSKey: Buffer, DevAddr: Buffer): {
    WorSIntKey: Buffer;
    WorSEncKey: Buffer;
};
declare function encrypt(buffer: Buffer, key: Buffer): Buffer;
declare function decryptJoinAccept(payload: LoraPacket, appKey: Buffer): Buffer;
export { encrypt, decrypt, decryptJoin, decryptFOpts, decryptJoinAccept, generateSessionKeys, generateSessionKeys11, generateSessionKeys10, generateWORKey, generateWORSessionKeys, generateJSKeys, };
//# sourceMappingURL=crypto.d.ts.map