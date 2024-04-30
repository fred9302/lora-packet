"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.recalculateMIC = exports.verifyMIC = exports.calculateMIC = void 0;
const LoraPacket_1 = require("./LoraPacket");
const util_1 = require("./util");
const aes_cmac_1 = require("aes-cmac");
const buffer_1 = require("buffer");
// calculate MIC from payload
function calculateMIC(payload, NwkSKey, //NwkSKey for DataUP/Down; SNwkSIntKey in data 1.1; SNwkSIntKey in Join 1.1
AppKey, //AppSKey for DataUP/Down; FNwkSIntKey in data 1.1; JSIntKey in Join 1.1
FCntMSBytes, ConfFCntDownTxDrTxCh) {
    let LWVersion = LoraPacket_1.LorawanVersion.V1_0;
    if (payload.isJoinRequestMessage()) {
        if (AppKey && AppKey.length !== 16)
            throw new Error("Expected a AppKey with length 16");
        if (!payload.MHDR)
            throw new Error("Expected MHDR to be defined");
        if (!payload.AppEUI)
            throw new Error("Expected AppEUI to be defined");
        if (!payload.DevEUI)
            throw new Error("Expected DevEUI to be defined");
        if (!payload.DevNonce)
            throw new Error("Expected DevNonce to be defined");
        if (!payload.MACPayload)
            throw new Error("Expected DevNonce to be defined");
        // const msgLen = payload.MHDR.length + payload.AppEUI.length + payload.DevEUI.length + payload.DevNonce.length;
        // CMAC over MHDR | AppEUI | DevEUI | DevNonce
        // the seperate fields are not in little-endian format, use the concatenated field
        const cmacInput = buffer_1.Buffer.concat([payload.MHDR, payload.MACPayload]);
        // CMAC calculation (as RFC4493)
        let fullCmac = new aes_cmac_1.AesCmac(AppKey).calculate(cmacInput);
        if (!(fullCmac instanceof buffer_1.Buffer))
            fullCmac = buffer_1.Buffer.from(fullCmac);
        // only first 4 bytes of CMAC are used as MIC
        const MIC = fullCmac.slice(0, 4);
        return MIC;
    }
    else if (payload.isReJoinRequestMessage()) {
        if (payload.RejoinType[0] === 1 && (!AppKey || AppKey.length !== 16))
            throw new Error("Expected a JSIntKey with length 16");
        if ((payload.RejoinType[0] === 0 || payload.RejoinType[0] === 2) && (!NwkSKey || NwkSKey.length !== 16))
            throw new Error("Expected a SNwkSIntKey with length 16");
        if (AppKey && AppKey.length !== 16)
            throw new Error("Expected a AppKey with length 16");
        if (!payload.MHDR)
            throw new Error("Expected MHDR to be defined");
        if (!payload.RejoinType)
            throw new Error("Expected RejoinType to be defined");
        if (!payload.NetID && !payload.AppEUI)
            throw new Error("Expected NetID or JoinEUI to be defined");
        if (!payload.DevEUI)
            throw new Error("Expected DevEUI to be defined");
        if (!payload.RJCount0 && !payload.RJCount1)
            throw new Error("Expected RJCount0 or RJCount1 to be defined");
        // const msgLen = payload.MHDR.length + payload.AppEUI.length + payload.DevEUI.length + payload.DevNonce.length;
        // CMAC over MHDR | AppEUI | DevEUI | DevNonce
        // the seperate fields are not in little-endian format, use the concatenated field
        const cmacInput = buffer_1.Buffer.concat([payload.MHDR, payload.MACPayload]);
        // CMAC calculation (as RFC4493)
        const calcKey = payload.RejoinType[0] === 1 ? AppKey : NwkSKey;
        let fullCmac = new aes_cmac_1.AesCmac(calcKey).calculate(cmacInput);
        if (!(fullCmac instanceof buffer_1.Buffer))
            fullCmac = buffer_1.Buffer.from(fullCmac);
        // only first 4 bytes of CMAC are used as MIC
        const MIC = fullCmac.slice(0, 4);
        return MIC;
    }
    else if (payload.isJoinAcceptMessage()) {
        if (AppKey && AppKey.length !== 16)
            throw new Error("Expected a AppKey with length 16");
        if (!payload.MHDR)
            throw new Error("Expected MHDR to be defined");
        if (!payload.AppNonce)
            throw new Error("Expected AppNonce to be defined");
        if (!payload.NetID)
            throw new Error("Expected NetID to be defined");
        if (!payload.DevAddr)
            throw new Error("Expected DevAddr to be defined");
        if (!payload.DLSettings)
            throw new Error("Expected DLSettings to be defined");
        if (!payload.RxDelay)
            throw new Error("Expected RxDelay to be defined");
        if (!payload.CFList)
            throw new Error("Expected CFList to be defined");
        if (!payload.MACPayload)
            throw new Error("Expected MACPayload to be defined");
        if (payload.getDLSettingsOptNeg())
            LWVersion = LoraPacket_1.LorawanVersion.V1_1;
        let cmacInput = buffer_1.Buffer.alloc(0);
        let cmacKey = AppKey;
        if (LWVersion === LoraPacket_1.LorawanVersion.V1_0) {
            // const msgLen =
            //   payload.MHDR.length +
            //   payload.AppNonce.length +
            //   payload.NetID.length +
            //   payload.DevAddr.length +
            //   payload.DLSettings.length +
            //   payload.RxDelay.length +
            //   payload.CFList.length;
            // CMAC over MHDR | AppNonce | NetID | DevAddr | DLSettings | RxDelay | CFList
            // the seperate fields are not encrypted, use the encrypted concatenated field
            cmacInput = buffer_1.Buffer.concat([payload.MHDR, payload.MACPayload]);
        }
        else if (LWVersion === LoraPacket_1.LorawanVersion.V1_1) {
            if (!payload.JoinReqType)
                throw new Error("Expected JoinReqType to be defined");
            if (!payload.JoinEUI)
                throw new Error("Expected JoinEUI to be defined");
            if (!payload.DevNonce)
                throw new Error("Expected DevNonce to be defined");
            if (!NwkSKey || NwkSKey.length !== 16)
                throw new Error("Expected a NwkSKey with length 16");
            cmacKey = NwkSKey;
            cmacInput = buffer_1.Buffer.concat([
                payload.JoinReqType,
                util_1.reverseBuffer(payload.JoinEUI),
                util_1.reverseBuffer(payload.DevNonce),
                payload.MHDR,
                payload.MACPayload,
            ]);
        }
        // CMAC calculation (as RFC4493)
        let fullCmac = new aes_cmac_1.AesCmac(cmacKey).calculate(cmacInput);
        if (!(fullCmac instanceof buffer_1.Buffer))
            fullCmac = buffer_1.Buffer.from(fullCmac);
        // only first 4 bytes of CMAC are used as MIC
        const MIC = fullCmac.slice(0, 4);
        return MIC;
    }
    else {
        // ConfFCntDownTxDrTxCh = ConfFCntDownTxDrTxCh || Buffer.alloc(2, 0);
        if (NwkSKey && NwkSKey.length !== 16)
            throw new Error("Expected a NwkSKey with length 16");
        if (payload.DevAddr && payload.DevAddr.length !== 4)
            throw new Error("Expected a payload DevAddr with length 4");
        if (payload.FCnt && payload.FCnt.length !== 2)
            throw new Error("Expected a payload FCnt with length 2");
        if (!payload.MHDR)
            throw new Error("Expected MHDR to be defined");
        if (!payload.DevAddr)
            throw new Error("Expected DevAddr to be defined");
        if (!payload.FCnt)
            throw new Error("Expected FCnt to be defined");
        if (!payload.MACPayload)
            throw new Error("Expected MACPayload to be defined");
        if (!FCntMSBytes) {
            FCntMSBytes = buffer_1.Buffer.from("0000", "hex");
        }
        if (ConfFCntDownTxDrTxCh) {
            if (!AppKey || (AppKey === null || AppKey === void 0 ? void 0 : AppKey.length) !== 16)
                throw new Error("Expected a FNwkSIntKey with length 16");
            LWVersion = LoraPacket_1.LorawanVersion.V1_1;
        }
        // if (NwkSKey && AppKey) {
        //   LWVersion = LorawanVersion.V1_1;
        // }
        let dir;
        const isUplinkAndIs1_1 = payload.getDir() === "up" && LWVersion === LoraPacket_1.LorawanVersion.V1_1;
        const isDownlinkAndIs1_1 = payload.getDir() === "down" && LWVersion === LoraPacket_1.LorawanVersion.V1_1;
        if (payload.getDir() == "up") {
            dir = buffer_1.Buffer.alloc(1, 0);
        }
        else if (payload.getDir() == "down") {
            dir = buffer_1.Buffer.alloc(1, 1);
            if (!ConfFCntDownTxDrTxCh) {
                ConfFCntDownTxDrTxCh = buffer_1.Buffer.alloc(4, 0);
            }
            else if (ConfFCntDownTxDrTxCh && (ConfFCntDownTxDrTxCh === null || ConfFCntDownTxDrTxCh === void 0 ? void 0 : ConfFCntDownTxDrTxCh.length) !== 2) {
                throw new Error("Expected a ConfFCntDown with length 2");
            }
            else {
                ConfFCntDownTxDrTxCh = buffer_1.Buffer.concat([ConfFCntDownTxDrTxCh, buffer_1.Buffer.alloc(2, 0)]);
            }
        }
        else {
            throw new Error("expecting direction to be either 'up' or 'down'");
        }
        if (isUplinkAndIs1_1) {
            if (!ConfFCntDownTxDrTxCh || (ConfFCntDownTxDrTxCh === null || ConfFCntDownTxDrTxCh === void 0 ? void 0 : ConfFCntDownTxDrTxCh.length) !== 4) {
                throw new Error("Expected a ConfFCntDownTxDrTxCh with length 4 Expected ( ConfFCnt | TxDr | TxCh)");
            }
            if (payload.getFCtrlACK() || (isUplinkAndIs1_1 && payload.getFPort() === 0)) {
                ConfFCntDownTxDrTxCh.writeUInt16BE(ConfFCntDownTxDrTxCh.readUInt16LE(0));
            }
            else {
                ConfFCntDownTxDrTxCh.writeUInt16BE(0);
            }
        }
        const msgLen = payload.MHDR.length + payload.MACPayload.length;
        const B0 = buffer_1.Buffer.concat([
            buffer_1.Buffer.from([0x49]),
            isDownlinkAndIs1_1 ? ConfFCntDownTxDrTxCh : buffer_1.Buffer.alloc(4, 0),
            dir,
            util_1.reverseBuffer(payload.DevAddr),
            util_1.reverseBuffer(payload.FCnt),
            FCntMSBytes,
            buffer_1.Buffer.alloc(1, 0),
            buffer_1.Buffer.alloc(1, msgLen),
        ]);
        // CMAC over B0 | MHDR | MACPayload
        const cmacInput = buffer_1.Buffer.concat([B0, payload.MHDR, payload.MACPayload]);
        // CMAC calculation (as RFC4493)
        let key = NwkSKey;
        if (isDownlinkAndIs1_1)
            key = AppKey;
        let fullCmac = new aes_cmac_1.AesCmac(key).calculate(cmacInput);
        if (!(fullCmac instanceof buffer_1.Buffer))
            fullCmac = buffer_1.Buffer.from(fullCmac);
        // only first 4 bytes of CMAC are used as MIC
        const MIC = fullCmac.slice(0, 4);
        if (isUplinkAndIs1_1) {
            const B1 = buffer_1.Buffer.concat([
                buffer_1.Buffer.from([0x49]),
                ConfFCntDownTxDrTxCh,
                dir,
                util_1.reverseBuffer(payload.DevAddr),
                util_1.reverseBuffer(payload.FCnt),
                FCntMSBytes,
                buffer_1.Buffer.alloc(1, 0),
                buffer_1.Buffer.alloc(1, msgLen),
            ]);
            const cmacSInput = buffer_1.Buffer.concat([B1, payload.MHDR, payload.MACPayload]);
            let fullCmacS = new aes_cmac_1.AesCmac(AppKey).calculate(cmacSInput);
            if (!(fullCmacS instanceof buffer_1.Buffer))
                fullCmacS = buffer_1.Buffer.from(fullCmacS);
            // only first 2 bytes of CMAC and CMACS are used as MIC
            const MICS = fullCmacS.slice(0, 4);
            return buffer_1.Buffer.concat([MICS.slice(0, 2), MIC.slice(0, 2)]);
        }
        return MIC;
    }
}
exports.calculateMIC = calculateMIC;
// verify is just calculate & compare
function verifyMIC(payload, NwkSKey, AppKey, FCntMSBytes, ConfFCntDownTxDrTxCh) {
    if (payload.MIC && payload.MIC.length !== 4)
        throw new Error("Expected a payload payload.MIC with length 4");
    const calculated = calculateMIC(payload, NwkSKey, AppKey, FCntMSBytes, ConfFCntDownTxDrTxCh);
    if (!payload.MIC)
        return false;
    return buffer_1.Buffer.compare(payload.MIC, calculated) === 0;
}
exports.verifyMIC = verifyMIC;
// calculate MIC & store
function recalculateMIC(payload, NwkSKey, AppKey, FCntMSBytes, ConfFCntDownTxDrTxCh) {
    const calculated = calculateMIC(payload, NwkSKey, AppKey, FCntMSBytes, ConfFCntDownTxDrTxCh);
    payload.MIC = calculated;
    if (!payload.MHDR)
        throw new Error("Missing MHDR");
    if (!payload.MACPayload)
        throw new Error("Missing MACPayload");
    if (!payload.MIC)
        throw new Error("Missing MIC");
    if (!payload.MHDR)
        throw new Error("Missing MHDR");
    payload.PHYPayload = buffer_1.Buffer.concat([payload.MHDR, payload.MACPayload, payload.MIC]);
    payload.MACPayloadWithMIC = payload.PHYPayload.slice(payload.MHDR.length, payload.PHYPayload.length);
}
exports.recalculateMIC = recalculateMIC;
//# sourceMappingURL=mic.js.map