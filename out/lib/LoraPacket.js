"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LorawanVersion = void 0;
const util_1 = require("./util");
const crypto_1 = require("./crypto");
const mic_1 = require("./mic");
const buffer_1 = require("buffer");
var MType;
(function (MType) {
    MType[MType["JOIN_REQUEST"] = 0] = "JOIN_REQUEST";
    MType[MType["JOIN_ACCEPT"] = 1] = "JOIN_ACCEPT";
    MType[MType["UNCONFIRMED_DATA_UP"] = 2] = "UNCONFIRMED_DATA_UP";
    MType[MType["UNCONFIRMED_DATA_DOWN"] = 3] = "UNCONFIRMED_DATA_DOWN";
    MType[MType["CONFIRMED_DATA_UP"] = 4] = "CONFIRMED_DATA_UP";
    MType[MType["CONFIRMED_DATA_DOWN"] = 5] = "CONFIRMED_DATA_DOWN";
    MType[MType["REJOIN_REQUEST"] = 6] = "REJOIN_REQUEST";
})(MType || (MType = {}));
const MTYPE_DESCRIPTIONS = {
    [MType.JOIN_REQUEST]: "Join Request",
    [MType.JOIN_ACCEPT]: "Join Accept",
    [MType.UNCONFIRMED_DATA_UP]: "Unconfirmed Data Up",
    [MType.UNCONFIRMED_DATA_DOWN]: "Unconfirmed Data Down",
    [MType.CONFIRMED_DATA_UP]: "Confirmed Data Up",
    [MType.CONFIRMED_DATA_DOWN]: "Confirmed Data Down",
    [MType.REJOIN_REQUEST]: "Rejoin Request",
};
const DESCRIPTIONS_MTYPE = Object.keys(MTYPE_DESCRIPTIONS).reduce((acc, key) => {
    const mTypeKey = key; // Cast the key to MType
    const description = MTYPE_DESCRIPTIONS[mTypeKey];
    acc[description] = mTypeKey;
    return acc;
}, {});
const PACKET_STRUCTURES = {
    JOIN_REQUEST: {
        AppEUI: { start: 1, end: 9 },
        DevEUI: { start: 9, end: 17 },
        DevNonce: { start: 17, end: 19 },
    },
    JOIN_ACCEPT: {
        AppNonce: { start: 1, end: 4 },
        NetID: { start: 4, end: 7 },
        DevAddr: { start: 7, end: 11 },
        DLSettings: { start: 11, end: 12 },
        RxDelay: { start: 12, end: 13 },
    },
    REJOIN_TYPE_1: {
        NetID: { start: 2, end: 5 },
        DevEUI: { start: 5, end: 13 },
        RJCount0: { start: 13, end: 15 },
    },
    REJOIN_TYPE_2: {
        JoinEUI: { start: 2, end: 10 },
        DevEUI: { start: 10, end: 18 },
        RJCount1: { start: 13, end: 15 },
    },
};
var LorawanVersion;
(function (LorawanVersion) {
    LorawanVersion["V1_0"] = "1.0";
    LorawanVersion["V1_1"] = "1.1";
})(LorawanVersion || (LorawanVersion = {}));
exports.LorawanVersion = LorawanVersion;
var Masks;
(function (Masks) {
    Masks[Masks["FCTRL_ADR"] = 128] = "FCTRL_ADR";
    Masks[Masks["FCTRL_ADRACKREQ"] = 64] = "FCTRL_ADRACKREQ";
    Masks[Masks["FCTRL_ACK"] = 32] = "FCTRL_ACK";
    Masks[Masks["FCTRL_FPENDING"] = 16] = "FCTRL_FPENDING";
    Masks[Masks["DLSETTINGS_RXONEDROFFSET_MASK"] = 112] = "DLSETTINGS_RXONEDROFFSET_MASK";
    Masks[Masks["DLSETTINGS_RXONEDROFFSET_POS"] = 4] = "DLSETTINGS_RXONEDROFFSET_POS";
    Masks[Masks["DLSETTINGS_RXTWODATARATE_MASK"] = 15] = "DLSETTINGS_RXTWODATARATE_MASK";
    Masks[Masks["DLSETTINGS_RXTWODATARATE_POS"] = 0] = "DLSETTINGS_RXTWODATARATE_POS";
    Masks[Masks["DLSETTINGS_OPTNEG_MASK"] = 128] = "DLSETTINGS_OPTNEG_MASK";
    Masks[Masks["DLSETTINGS_OPTNEG_POS"] = 7] = "DLSETTINGS_OPTNEG_POS";
    Masks[Masks["RXDELAY_DEL_MASK"] = 15] = "RXDELAY_DEL_MASK";
    Masks[Masks["RXDELAY_DEL_POS"] = 0] = "RXDELAY_DEL_POS";
})(Masks || (Masks = {}));
function extractBytesFromBuffer(buffer, start, end) {
    return util_1.reverseBuffer(buffer.slice(start, end));
}
function extractStructuredBytesFromBuffer(buffer, name) {
    const structure = PACKET_STRUCTURES[name];
    const ret = {};
    for (const key in structure) {
        if (structure.hasOwnProperty(key)) {
            ret[key] = extractBytesFromBuffer(buffer, structure[key].start, structure[key].end);
        }
    }
    return ret;
}
class LoraPacket {
    static fromWire(buffer) {
        const payload = new LoraPacket();
        payload._initfromWire(buffer);
        return payload;
    }
    static fromFields(fields, AppSKey, NwkSKey, AppKey, FCntMSBytes, ConfFCntDownTxDrTxCh) {
        if (!FCntMSBytes)
            FCntMSBytes = buffer_1.Buffer.alloc(2, 0);
        const payload = new LoraPacket();
        payload._initFromFields(fields);
        if (payload.isDataMessage()) {
            // to encrypt, need NwkSKey if port=0, else AppSKey
            const port = payload.getFPort();
            if (port !== null && ((port === 0 && (NwkSKey === null || NwkSKey === void 0 ? void 0 : NwkSKey.length) === 16) || (port > 0 && (AppSKey === null || AppSKey === void 0 ? void 0 : AppSKey.length) === 16))) {
                // crypto is reversible (just XORs FRMPayload), so we can
                //  just do "decrypt" on the plaintext to get ciphertext
                let ciphertext;
                if (port === 0 && (NwkSKey === null || NwkSKey === void 0 ? void 0 : NwkSKey.length) === 16 && (AppSKey === null || AppSKey === void 0 ? void 0 : AppSKey.length) === 16 && (AppKey === null || AppKey === void 0 ? void 0 : AppKey.length) === 16) {
                    ciphertext = crypto_1.decrypt(payload, undefined, AppSKey, FCntMSBytes);
                }
                else {
                    ciphertext = crypto_1.decrypt(payload, AppSKey, NwkSKey, FCntMSBytes);
                }
                // overwrite payload with ciphertext
                payload.FRMPayload = ciphertext;
                // recalculate buffers to be ready for MIC calc'n
                payload._mergeGroupFields();
                if ((NwkSKey === null || NwkSKey === void 0 ? void 0 : NwkSKey.length) === 16) {
                    mic_1.recalculateMIC(payload, NwkSKey, AppKey, FCntMSBytes, ConfFCntDownTxDrTxCh);
                    payload._mergeGroupFields();
                }
            }
        }
        else if (payload._getMType() === MType.JOIN_REQUEST) {
            if ((AppKey === null || AppKey === void 0 ? void 0 : AppKey.length) === 16) {
                mic_1.recalculateMIC(payload, NwkSKey, AppKey, FCntMSBytes);
                payload._mergeGroupFields();
            }
        }
        else if (payload._getMType() === MType.JOIN_ACCEPT) {
            if ((AppKey === null || AppKey === void 0 ? void 0 : AppKey.length) === 16) {
                mic_1.recalculateMIC(payload, NwkSKey, AppKey, FCntMSBytes);
                payload._mergeGroupFields();
                const ciphertext = crypto_1.decryptJoin(payload, AppKey);
                // overwrite payload with ciphertext
                if (payload.MACPayloadWithMIC)
                    ciphertext.copy(payload.MACPayloadWithMIC);
            }
        }
        return payload;
    }
    assignFromStructuredBuffer(buffer, structure) {
        const fields = extractStructuredBytesFromBuffer(buffer, structure);
        Object.assign(this, fields);
    }
    _initfromWire(contents) {
        const incoming = buffer_1.Buffer.from(contents);
        this.PHYPayload = incoming;
        this.MHDR = incoming.slice(0, 1);
        this.MACPayload = incoming.slice(1, incoming.length - 4);
        this.MACPayloadWithMIC = incoming.slice(1, incoming.length);
        this.MIC = incoming.slice(incoming.length - 4);
        const mtype = this._getMType();
        if (mtype == MType.JOIN_REQUEST) {
            if (incoming.length < 5 + 18) {
                throw new Error("contents too short for a Join Request");
            }
            this.assignFromStructuredBuffer(incoming, "JOIN_REQUEST");
        }
        else if (mtype == MType.JOIN_ACCEPT) {
            if (incoming.length < 5 + 12) {
                throw new Error("contents too short for a Join Accept");
            }
            this.assignFromStructuredBuffer(incoming, "JOIN_ACCEPT");
            this.JoinReqType = buffer_1.Buffer.from([0xff]);
            if (incoming.length == 13 + 16 + 4) {
                this.CFList = incoming.slice(13, 13 + 16);
            }
            else {
                this.CFList = buffer_1.Buffer.alloc(0);
            }
        }
        else if (mtype == MType.REJOIN_REQUEST) {
            this.RejoinType = incoming.slice(1, 1 + 1);
            if (this.RejoinType[0] === 0 || this.RejoinType[0] === 2) {
                if (incoming.length < 5 + 14) {
                    throw new Error("contents too short for a Rejoin Request (Type 0/2)");
                }
                this.assignFromStructuredBuffer(incoming, "REJOIN_TYPE_1");
            }
            else if (this.RejoinType[0] === 1) {
                if (incoming.length < 5 + 19) {
                    throw new Error("contents too short for a Rejoin Request (Type 1)");
                }
                this.assignFromStructuredBuffer(incoming, "REJOIN_TYPE_2");
            }
        }
        else if (this.isDataMessage()) {
            this.DevAddr = util_1.reverseBuffer(incoming.slice(1, 5));
            this.FCtrl = util_1.reverseBuffer(incoming.slice(5, 6));
            this.FCnt = util_1.reverseBuffer(incoming.slice(6, 8));
            const FCtrl = this.FCtrl.readInt8(0);
            const FOptsLen = FCtrl & 0x0f;
            this.FOpts = incoming.slice(8, 8 + FOptsLen);
            const FHDR_length = 7 + FOptsLen;
            this.FHDR = incoming.slice(1, 1 + FHDR_length);
            if (FHDR_length == this.MACPayload.length) {
                this.FPort = buffer_1.Buffer.alloc(0);
                this.FRMPayload = buffer_1.Buffer.alloc(0);
            }
            else {
                this.FPort = incoming.slice(FHDR_length + 1, FHDR_length + 2);
                this.FRMPayload = incoming.slice(FHDR_length + 2, incoming.length - 4);
            }
        }
    }
    _initFromFields(userFields) {
        if (typeof userFields.MType !== "undefined") {
            let MTypeNo;
            if (typeof userFields.MType === "number") {
                MTypeNo = userFields.MType;
            }
            else if (typeof userFields.MType == "string") {
                const mhdr_idx = DESCRIPTIONS_MTYPE[userFields.MType];
                if (mhdr_idx >= 0) {
                    MTypeNo = mhdr_idx;
                }
                else {
                    throw new Error("MType is unknown");
                }
            }
            else {
                throw new Error("MType is required in a suitable format");
            }
            if (MTypeNo == MType.JOIN_REQUEST) {
                this._initialiseJoinRequestPacketFromFields(userFields);
            }
            else if (MTypeNo == MType.JOIN_ACCEPT) {
                this._initialiseJoinAcceptPacketFromFields(userFields);
            }
            else {
                this._initialiseDataPacketFromFields(userFields);
            }
        }
        else {
            if (userFields.DevAddr && typeof userFields.payload !== "undefined") {
                this._initialiseDataPacketFromFields(userFields);
            }
            else if (userFields.AppEUI && userFields.DevEUI && userFields.DevNonce) {
                this._initialiseJoinRequestPacketFromFields(userFields);
            }
            else if (userFields.AppNonce && userFields.NetID && userFields.DevAddr) {
                this._initialiseJoinAcceptPacketFromFields(userFields);
            }
            else {
                throw new Error("No plausible packet");
            }
        }
    }
    _mergeGroupFields() {
        if (this.MHDR && this.MIC) {
            if (this._getMType() === MType.JOIN_REQUEST && this.AppEUI && this.DevEUI && this.DevNonce) {
                this.MACPayload = buffer_1.Buffer.concat([
                    util_1.reverseBuffer(this.AppEUI),
                    util_1.reverseBuffer(this.DevEUI),
                    util_1.reverseBuffer(this.DevNonce),
                ]);
                this.PHYPayload = buffer_1.Buffer.concat([this.MHDR, this.MACPayload, this.MIC]);
                this.MACPayloadWithMIC = this.PHYPayload.slice(this.MHDR.length, this.PHYPayload.length);
            }
            else if (this._getMType() === MType.JOIN_ACCEPT &&
                this.AppNonce &&
                this.NetID &&
                this.DevAddr &&
                this.DLSettings &&
                this.RxDelay &&
                this.CFList) {
                this.MACPayload = buffer_1.Buffer.concat([
                    util_1.reverseBuffer(this.AppNonce),
                    util_1.reverseBuffer(this.NetID),
                    util_1.reverseBuffer(this.DevAddr),
                    this.DLSettings,
                    this.RxDelay,
                    this.CFList,
                ]);
                this.PHYPayload = buffer_1.Buffer.concat([this.MHDR, this.MACPayload, this.MIC]);
                this.MACPayloadWithMIC = this.PHYPayload.slice(this.MHDR.length, this.PHYPayload.length);
            }
            else if (this.FCtrl && this.DevAddr && this.FPort && this.FCnt && this.FRMPayload && this.FOpts) {
                this.FHDR = buffer_1.Buffer.concat([util_1.reverseBuffer(this.DevAddr), this.FCtrl, util_1.reverseBuffer(this.FCnt), this.FOpts]);
                this.MACPayload = buffer_1.Buffer.concat([this.FHDR, this.FPort, this.FRMPayload]);
                this.PHYPayload = buffer_1.Buffer.concat([this.MHDR, this.MACPayload, this.MIC]);
                this.MACPayloadWithMIC = this.PHYPayload.slice(this.MHDR.length, this.PHYPayload.length);
            }
        }
    }
    _initialiseDataPacketFromFields(userFields) {
        var _a, _b, _c, _d;
        if (userFields.DevAddr && userFields.DevAddr.length == 4) {
            this.DevAddr = buffer_1.Buffer.from(userFields.DevAddr);
        }
        else {
            throw new Error("DevAddr is required in a suitable format");
        }
        if (typeof userFields.payload === "string") {
            this.FRMPayload = buffer_1.Buffer.from(userFields.payload);
        }
        else if (userFields.payload instanceof buffer_1.Buffer) {
            this.FRMPayload = buffer_1.Buffer.from(userFields.payload);
        }
        if (typeof userFields.MType !== "undefined") {
            if (typeof userFields.MType === "number") {
                this.MHDR = buffer_1.Buffer.alloc(1);
                this.MHDR.writeUInt8(userFields.MType << 5, 0);
            }
            else if (typeof userFields.MType === "string") {
                const mhdr_idx = DESCRIPTIONS_MTYPE[userFields.MType];
                if (mhdr_idx >= 0) {
                    this.MHDR = buffer_1.Buffer.alloc(1);
                    this.MHDR.writeUInt8(mhdr_idx << 5, 0);
                }
                else {
                    throw new Error("MType is unknown");
                }
            }
            else {
                throw new Error("MType is required in a suitable format");
            }
        }
        if (userFields.FCnt) {
            if (userFields.FCnt instanceof buffer_1.Buffer && userFields.FCnt.length == 2) {
                this.FCnt = buffer_1.Buffer.from(userFields.FCnt);
            }
            else if (typeof userFields.FCnt === "number") {
                this.FCnt = buffer_1.Buffer.alloc(2);
                this.FCnt.writeUInt16BE(userFields.FCnt, 0);
            }
            else {
                throw new Error("FCnt is required in a suitable format");
            }
        }
        if (typeof userFields.FOpts !== "undefined") {
            if (typeof userFields.FOpts === "string") {
                this.FOpts = buffer_1.Buffer.from(userFields.FOpts, "hex");
            }
            else if (userFields.FOpts instanceof buffer_1.Buffer) {
                this.FOpts = buffer_1.Buffer.from(userFields.FOpts);
            }
            else {
                throw new Error("FOpts is required in a suitable format");
            }
            if (15 < this.FOpts.length) {
                throw new Error("Too many options for piggybacking");
            }
        }
        else {
            this.FOpts = buffer_1.Buffer.from("", "hex");
        }
        let fctrl = 0;
        if ((_a = userFields.FCtrl) === null || _a === void 0 ? void 0 : _a.ADR) {
            fctrl |= Masks.FCTRL_ADR;
        }
        if ((_b = userFields.FCtrl) === null || _b === void 0 ? void 0 : _b.ADRACKReq) {
            fctrl |= Masks.FCTRL_ADRACKREQ;
        }
        if ((_c = userFields.FCtrl) === null || _c === void 0 ? void 0 : _c.ACK) {
            fctrl |= Masks.FCTRL_ACK;
        }
        if ((_d = userFields.FCtrl) === null || _d === void 0 ? void 0 : _d.FPending) {
            fctrl |= Masks.FCTRL_FPENDING;
        }
        fctrl |= this.FOpts.length & 0x0f;
        this.FCtrl = buffer_1.Buffer.alloc(1);
        this.FCtrl.writeUInt8(fctrl, 0);
        if (!isNaN(userFields.FPort) && userFields.FPort >= 0 && userFields.FPort <= 255) {
            this.FPort = buffer_1.Buffer.alloc(1);
            this.FPort.writeUInt8(userFields.FPort, 0);
        }
        if (!(this === null || this === void 0 ? void 0 : this.MHDR)) {
            this.MHDR = buffer_1.Buffer.alloc(1);
            this.MHDR.writeUInt8(MType.UNCONFIRMED_DATA_UP << 5, 0);
        }
        if ((this === null || this === void 0 ? void 0 : this.FPort) == null) {
            if ((this === null || this === void 0 ? void 0 : this.FRMPayload) && this.FRMPayload.length > 0) {
                this.FPort = buffer_1.Buffer.from("01", "hex");
            }
            else {
                this.FPort = buffer_1.Buffer.alloc(0);
            }
        }
        if (!(this === null || this === void 0 ? void 0 : this.FPort) == null) {
            this.FPort = buffer_1.Buffer.from("01", "hex");
        }
        if (!this.FCnt) {
            this.FCnt = buffer_1.Buffer.from("0000", "hex");
        }
        if (!this.MIC) {
            this.MIC = buffer_1.Buffer.from("EEEEEEEE", "hex");
        }
        this._mergeGroupFields();
    }
    _initialiseJoinRequestPacketFromFields(userFields) {
        if (userFields.AppEUI && userFields.AppEUI.length == 8) {
            this.AppEUI = buffer_1.Buffer.from(userFields.AppEUI);
        }
        else {
            throw new Error("AppEUI is required in a suitable format");
        }
        if (userFields.DevEUI && userFields.DevEUI.length == 8) {
            this.DevEUI = buffer_1.Buffer.from(userFields.DevEUI);
        }
        else {
            throw new Error("DevEUI is required in a suitable format");
        }
        if (userFields.DevNonce && userFields.DevNonce.length == 2) {
            this.DevNonce = buffer_1.Buffer.from(userFields.DevNonce);
        }
        else {
            throw new Error("DevNonce is required in a suitable format");
        }
        if (userFields.FCnt) {
            if (userFields.FCnt instanceof buffer_1.Buffer && userFields.FCnt.length == 2) {
                this.FCnt = buffer_1.Buffer.from(userFields.FCnt);
            }
            else if (typeof userFields.FCnt === "number") {
                this.FCnt = buffer_1.Buffer.alloc(2);
                this.FCnt.writeUInt16BE(userFields.FCnt, 0);
            }
            else {
                throw new Error("FCnt is required in a suitable format");
            }
        }
        this.MHDR = buffer_1.Buffer.alloc(1);
        this.MHDR.writeUInt8(MType.JOIN_REQUEST << 5, 0);
        if (!this.MIC) {
            this.MIC = buffer_1.Buffer.from("EEEEEEEE", "hex");
        }
        this._mergeGroupFields();
    }
    _initialiseJoinAcceptPacketFromFields(userFields) {
        if (userFields.AppNonce && userFields.AppNonce.length == 3) {
            this.AppNonce = buffer_1.Buffer.from(userFields.AppNonce);
        }
        else {
            throw new Error("AppNonce is required in a suitable format");
        }
        if (userFields.NetID && userFields.NetID.length == 3) {
            this.NetID = buffer_1.Buffer.from(userFields.NetID);
        }
        else {
            throw new Error("NetID is required in a suitable format");
        }
        if (userFields.DevAddr && userFields.DevAddr.length == 4) {
            this.DevAddr = buffer_1.Buffer.from(userFields.DevAddr);
        }
        else {
            throw new Error("DevAddr is required in a suitable format");
        }
        if (userFields.DLSettings) {
            if (userFields.DLSettings instanceof buffer_1.Buffer && userFields.DLSettings.length == 1) {
                this.DLSettings = buffer_1.Buffer.from(userFields.DLSettings);
            }
            else if (typeof userFields.DLSettings === "number") {
                this.DLSettings = buffer_1.Buffer.alloc(1);
                this.DLSettings.writeUInt8(userFields.DLSettings, 0);
            }
            else {
                throw new Error("DLSettings is required in a suitable format");
            }
        }
        if (userFields.RxDelay) {
            if (userFields.RxDelay instanceof buffer_1.Buffer && userFields.RxDelay.length == 1) {
                this.RxDelay = buffer_1.Buffer.from(userFields.RxDelay);
            }
            else if (typeof userFields.RxDelay == "number") {
                this.RxDelay = buffer_1.Buffer.alloc(1);
                this.RxDelay.writeUInt8(userFields.RxDelay, 0);
            }
            else {
                throw new Error("RxDelay is required in a suitable format");
            }
        }
        if (userFields.CFList) {
            if (userFields.CFList instanceof buffer_1.Buffer && (userFields.CFList.length == 0 || userFields.CFList.length == 16)) {
                this.CFList = buffer_1.Buffer.from(userFields.CFList);
            }
            else {
                throw new Error("CFList is required in a suitable format");
            }
        }
        if (!userFields.JoinReqType) {
            this.JoinReqType = buffer_1.Buffer.from("ff", "hex");
        }
        else {
            if (userFields.JoinReqType instanceof buffer_1.Buffer && userFields.JoinReqType.length == 1) {
                this.JoinReqType = buffer_1.Buffer.from(userFields.JoinReqType);
            }
            else if (typeof userFields.JoinReqType === "number") {
                this.JoinReqType = buffer_1.Buffer.alloc(1);
                this.JoinReqType.writeUInt8(userFields.JoinReqType, 0);
            }
            else {
                throw new Error("JoinReqType is required in a suitable format");
            }
        }
        if (userFields.AppEUI && userFields.AppEUI.length == 8) {
            this.AppEUI = buffer_1.Buffer.from(userFields.AppEUI);
        }
        else if (this.getDLSettingsOptNeg()) {
            throw new Error("AppEUI/JoinEUI is required in a suitable format");
        }
        if (userFields.DevNonce && userFields.DevNonce.length == 2) {
            this.DevNonce = buffer_1.Buffer.from(userFields.DevNonce);
        }
        else if (this.getDLSettingsOptNeg()) {
            throw new Error("DevNonce is required in a suitable format");
        }
        if (!this.DLSettings) {
            this.DLSettings = buffer_1.Buffer.from("00", "hex");
        }
        if (!this.RxDelay) {
            this.RxDelay = buffer_1.Buffer.from("00", "hex");
        }
        if (!this.CFList) {
            this.CFList = buffer_1.Buffer.from("", "hex");
        }
        this.MHDR = buffer_1.Buffer.alloc(1);
        this.MHDR.writeUInt8(MType.JOIN_ACCEPT << 5, 0);
        if (!this.MIC) {
            this.MIC = buffer_1.Buffer.from("EEEEEEEE", "hex");
        }
        this._mergeGroupFields();
    }
    _getMType() {
        if (this.MHDR)
            return (this.MHDR.readUInt8(0) & 0xff) >> 5;
        return -1;
    }
    isDataMessage() {
        const mtype = this._getMType();
        return mtype >= MType.UNCONFIRMED_DATA_UP && mtype <= MType.CONFIRMED_DATA_DOWN;
    }
    isConfirmed() {
        const mtype = this._getMType();
        return mtype === MType.CONFIRMED_DATA_DOWN || mtype === MType.CONFIRMED_DATA_UP;
    }
    /**
     * Provide MType as a string
     */
    getMType() {
        return MTYPE_DESCRIPTIONS[this._getMType()] || "Proprietary";
    }
    /**
     * Provide Direction as a string
     */
    getDir() {
        const mType = this._getMType();
        if (mType > 5)
            return null;
        if (mType % 2 == 0)
            return "up";
        return "down";
    }
    /**
     * Provide FPort as a number
     */
    getFPort() {
        if (this.FPort && this.FPort.length)
            return this.FPort.readUInt8(0);
        return null;
    }
    /**
     * Provide FCnt as a number
     */
    getFCnt() {
        if (this.FCnt)
            return this.FCnt.readUInt16BE(0);
        return null;
    }
    /**
     * Provide FCtrl.ACK as a flag
     */
    getFCtrlACK() {
        if (!this.FCtrl)
            return null;
        return !!(this.FCtrl.readUInt8(0) & Masks.FCTRL_ACK);
    }
    /**
     * Provide FCtrl.ADR as a flag
     */
    getFCtrlADR() {
        if (!this.FCtrl)
            return null;
        return !!(this.FCtrl.readUInt8(0) & Masks.FCTRL_ADR);
    }
    /**
     * Provide FCtrl.ADRACKReq as a flag
     */
    getFCtrlADRACKReq() {
        if (!this.FCtrl)
            return null;
        return !!(this.FCtrl.readUInt8(0) & Masks.FCTRL_ADRACKREQ);
    }
    /**
     * Provide FCtrl.FPending as a flag
     */
    getFCtrlFPending() {
        if (!this.FCtrl)
            return null;
        return !!(this.FCtrl.readUInt8(0) & Masks.FCTRL_FPENDING);
    }
    /**
     * Provide DLSettings.RX1DRoffset as integer
     */
    getDLSettingsRxOneDRoffset() {
        if (!this.DLSettings)
            return null;
        return (this.DLSettings.readUInt8(0) & Masks.DLSETTINGS_RXONEDROFFSET_MASK) >> Masks.DLSETTINGS_RXONEDROFFSET_POS;
    }
    /**
     * Provide DLSettings.RX2DataRate as integer
     */
    getDLSettingsRxTwoDataRate() {
        if (!this.DLSettings)
            return null;
        return (this.DLSettings.readUInt8(0) & Masks.DLSETTINGS_RXTWODATARATE_MASK) >> Masks.DLSETTINGS_RXTWODATARATE_POS;
    }
    /**
     * Provide DLSettings.OptNeg as boolean
     */
    getDLSettingsOptNeg() {
        if (!this.DLSettings)
            return null;
        return (this.DLSettings.readUInt8(0) & Masks.DLSETTINGS_OPTNEG_MASK) >> Masks.DLSETTINGS_OPTNEG_POS === 1;
    }
    /**
     * Provide RxDelay.Del as integer
     */
    getRxDelayDel() {
        if (!this.RxDelay)
            return null;
        return (this.RxDelay.readUInt8(0) & Masks.RXDELAY_DEL_MASK) >> Masks.RXDELAY_DEL_POS;
    }
    /**
     * Provide CFList.FreqChFour as buffer
     */
    getCFListFreqChFour() {
        if (this.CFList && this.CFList.length === 16) {
            return util_1.reverseBuffer(this.CFList.slice(0, /*0 +*/ 3));
        }
        else {
            return buffer_1.Buffer.alloc(0);
        }
    }
    /**
     * Provide CFList.FreqChFive as buffer
     */
    getCFListFreqChFive() {
        if (this.CFList && this.CFList.length === 16) {
            return util_1.reverseBuffer(this.CFList.slice(3, 3 + 3));
        }
        else {
            return buffer_1.Buffer.alloc(0);
        }
    }
    /**
     * Provide CFList.FreqChSix as buffer
     */
    getCFListFreqChSix() {
        if (this.CFList && this.CFList.length === 16) {
            return util_1.reverseBuffer(this.CFList.slice(6, 6 + 3));
        }
        else {
            return buffer_1.Buffer.alloc(0);
        }
    }
    /**
     * Provide CFList.FreqChSeven as buffer
     */
    getCFListFreqChSeven() {
        if (this.CFList && this.CFList.length === 16) {
            return util_1.reverseBuffer(this.CFList.slice(9, 9 + 3));
        }
        else {
            return buffer_1.Buffer.alloc(0);
        }
    }
    /**
     * Provide CFList.FreqChEight as buffer
     */
    getCFListFreqChEight() {
        if (this.CFList && this.CFList.length === 16) {
            return util_1.reverseBuffer(this.CFList.slice(12, 12 + 3));
        }
        else {
            return buffer_1.Buffer.alloc(0);
        }
    }
    getBuffers() {
        return this;
    }
    decryptFOpts(NwkSEncKey, NwkSKey, FCntMSBytes, ConfFCntDownTxDrTxCh) {
        return this.encryptFOpts(NwkSEncKey, NwkSKey, FCntMSBytes, ConfFCntDownTxDrTxCh);
    }
    encryptFOpts(NwkSEncKey, SNwkSIntKey, FCntMSBytes, ConfFCntDownTxDrTxCh) {
        if (!this.FOpts)
            return buffer_1.Buffer.alloc(0);
        if (!NwkSEncKey || (NwkSEncKey === null || NwkSEncKey === void 0 ? void 0 : NwkSEncKey.length) !== 16)
            throw new Error("NwkSEncKey must be 16 bytes");
        this.FOpts = crypto_1.decryptFOpts(this, NwkSEncKey, FCntMSBytes);
        this._mergeGroupFields();
        if ((SNwkSIntKey === null || SNwkSIntKey === void 0 ? void 0 : SNwkSIntKey.length) === 16) {
            mic_1.recalculateMIC(this, SNwkSIntKey, undefined, FCntMSBytes, ConfFCntDownTxDrTxCh);
            this._mergeGroupFields();
        }
        return this.FOpts;
    }
    getPHYPayload() {
        return this.PHYPayload;
    }
    isJoinRequestMessage() {
        return this._getMType() == MType.JOIN_REQUEST;
    }
    isRejoinRequestMessage() {
        return this._getMType() == MType.REJOIN_REQUEST;
    }
    // deprecated (bogus capitalisation)
    isReJoinRequestMessage() {
        return this._getMType() == MType.REJOIN_REQUEST;
    }
    isJoinAcceptMessage() {
        return this._getMType() == MType.JOIN_ACCEPT;
    }
    toString() {
        let msg = "";
        if (this.isJoinRequestMessage()) {
            msg += "          Message Type = Join Request" + "\n";
            msg += "            PHYPayload = " + util_1.asHexString(this.PHYPayload).toUpperCase() + "\n";
            msg += "\n";
            msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
            msg += "                  MHDR = " + util_1.asHexString(this.MHDR) + "\n";
            msg += "            MACPayload = " + util_1.asHexString(this.MACPayload) + "\n";
            msg += "                   MIC = " + util_1.asHexString(this.MIC) + "\n";
            msg += "\n";
            msg += "          ( MACPayload = AppEUI[8] | DevEUI[8] | DevNonce[2] )\n";
            msg += "                AppEUI = " + util_1.asHexString(this.AppEUI) + "\n";
            msg += "                DevEUI = " + util_1.asHexString(this.DevEUI) + "\n";
            msg += "              DevNonce = " + util_1.asHexString(this.DevNonce) + "\n";
        }
        else if (this.isJoinAcceptMessage()) {
            msg += "          Message Type = Join Accept" + "\n";
            msg += "            PHYPayload = " + util_1.asHexString(this.PHYPayload).toUpperCase() + "\n";
            msg += "\n";
            msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
            msg += "                  MHDR = " + util_1.asHexString(this.MHDR) + "\n";
            msg += "            MACPayload = " + util_1.asHexString(this.MACPayload) + "\n";
            msg += "                   MIC = " + util_1.asHexString(this.MIC) + "\n";
            msg += "\n";
            msg +=
                "          ( MACPayload = AppNonce[3] | NetID[3] | DevAddr[4] | DLSettings[1] | RxDelay[1] | CFList[0|15] )\n";
            msg += "              AppNonce = " + util_1.asHexString(this.AppNonce) + "\n";
            msg += "                 NetID = " + util_1.asHexString(this.NetID) + "\n";
            msg += "               DevAddr = " + util_1.asHexString(this.DevAddr) + "\n";
            msg += "            DLSettings = " + util_1.asHexString(this.DLSettings) + "\n";
            msg += "               RxDelay = " + util_1.asHexString(this.RxDelay) + "\n";
            msg += "                CFList = " + util_1.asHexString(this.CFList) + "\n";
            msg += "\n";
            msg += "DLSettings.RX1DRoffset = " + this.getDLSettingsRxOneDRoffset() + "\n";
            msg += "DLSettings.RX2DataRate = " + this.getDLSettingsRxTwoDataRate() + "\n";
            msg += "           RxDelay.Del = " + this.getRxDelayDel() + "\n";
            msg += "\n";
            if (this.CFList.length === 16) {
                msg += "              ( CFList = FreqCh4[3] | FreqCh5[3] | FreqCh6[3] | FreqCh7[3] | FreqCh8[3] )\n";
                msg += "               FreqCh4 = " + util_1.asHexString(this.getCFListFreqChFour()) + "\n";
                msg += "               FreqCh5 = " + util_1.asHexString(this.getCFListFreqChFive()) + "\n";
                msg += "               FreqCh6 = " + util_1.asHexString(this.getCFListFreqChSix()) + "\n";
                msg += "               FreqCh7 = " + util_1.asHexString(this.getCFListFreqChSeven()) + "\n";
                msg += "               FreqCh8 = " + util_1.asHexString(this.getCFListFreqChEight()) + "\n";
            }
        }
        else if (this.isRejoinRequestMessage()) {
            msg += "          Message Type = ReJoin Request" + "\n";
            msg += "            PHYPayload = " + util_1.asHexString(this.PHYPayload).toUpperCase() + "\n";
            msg += "\n";
            msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
            msg += "                  MHDR = " + util_1.asHexString(this.MHDR) + "\n";
            msg += "            MACPayload = " + util_1.asHexString(this.MACPayload) + "\n";
            msg += "                   MIC = " + util_1.asHexString(this.MIC) + "\n";
            msg += "\n";
            if (this.RejoinType[0] === 0 || this.RejoinType[0] === 2) {
                msg += "          ( MACPayload = RejoinType[1] | NetID[3] | DevEUI[8] | RJCount0[2] )\n";
                msg += "            RejoinType = " + util_1.asHexString(this.RejoinType) + "\n";
                msg += "                 NetID = " + util_1.asHexString(this.NetID) + "\n";
                msg += "                DevEUI = " + util_1.asHexString(this.DevEUI) + "\n";
                msg += "              RJCount0 = " + util_1.asHexString(this.RJCount0) + "\n";
            }
            else if (this.RejoinType[0] === 1) {
                msg += "          ( MACPayload = RejoinType[1] | JoinEUI[8] | DevEUI[8] | RJCount0[2] )\n";
                msg += "            RejoinType = " + util_1.asHexString(this.RejoinType) + "\n";
                msg += "               JoinEUI = " + util_1.asHexString(this.JoinEUI) + "\n";
                msg += "                DevEUI = " + util_1.asHexString(this.DevEUI) + "\n";
                msg += "              RJCount0 = " + util_1.asHexString(this.RJCount0) + "\n";
            }
        }
        else if (this.isDataMessage()) {
            msg += "Message Type = Data" + "\n";
            msg += "            PHYPayload = " + util_1.asHexString(this.PHYPayload).toUpperCase() + "\n";
            msg += "\n";
            msg += "          ( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n";
            msg += "                  MHDR = " + util_1.asHexString(this.MHDR) + "\n";
            msg += "            MACPayload = " + util_1.asHexString(this.MACPayload) + "\n";
            msg += "                   MIC = " + util_1.asHexString(this.MIC) + "\n";
            msg += "\n";
            msg += "          ( MACPayload = FHDR | FPort | FRMPayload )\n";
            msg += "                  FHDR = " + util_1.asHexString(this.FHDR) + "\n";
            msg += "                 FPort = " + util_1.asHexString(this.FPort) + "\n";
            msg += "            FRMPayload = " + util_1.asHexString(this.FRMPayload) + "\n";
            msg += "\n";
            msg += "                ( FHDR = DevAddr[4] | FCtrl[1] | FCnt[2] | FOpts[0..15] )\n";
            msg += "               DevAddr = " + util_1.asHexString(this.DevAddr) + " (Big Endian)\n";
            msg += "                 FCtrl = " + util_1.asHexString(this.FCtrl) + "\n"; //TODO as binary?
            msg += "                  FCnt = " + util_1.asHexString(this.FCnt) + " (Big Endian)\n";
            msg += "                 FOpts = " + util_1.asHexString(this.FOpts) + "\n";
            msg += "\n";
            msg += "          Message Type = " + this.getMType() + "\n";
            msg += "             Direction = " + this.getDir() + "\n";
            msg += "                  FCnt = " + this.getFCnt() + "\n";
            msg += "             FCtrl.ACK = " + this.getFCtrlACK() + "\n";
            msg += "             FCtrl.ADR = " + this.getFCtrlADR() + "\n";
            if (this._getMType() == MType.CONFIRMED_DATA_DOWN || this._getMType() == MType.UNCONFIRMED_DATA_DOWN) {
                msg += "        FCtrl.FPending = " + this.getFCtrlFPending() + "\n";
            }
            else {
                msg += "       FCtrl.ADRACKReq = " + this.getFCtrlADRACKReq() + "\n";
            }
        }
        return msg;
    }
    // Homemade function to export packet as object
    toObject() {
        let res = {};
        if (this.isJoinRequestMessage()) {
            res = {
                MType: "Join Request",
                PHYPayload: util_1.asHexString(this.PHYPayload).toUpperCase(),
                MHDR: util_1.asHexString(this.MHDR),
                MACPayload: util_1.asHexString(this.MACPayload),
                MIC: util_1.asHexString(this.MIC),
                RejoinType: this.RejoinType,
                AppEUI: util_1.asHexString(this.AppEUI),
                DevEUI: util_1.asHexString(this.DevEUI),
                DevNonce: util_1.asHexString(this.DevNonce),
            };
        }
        else if (this.isJoinAcceptMessage()) {
            if (this.CFList.length === 16) {
                res = {
                    MType: "Join Accept",
                    PHYPayload: util_1.asHexString(this.PHYPayload).toUpperCase(),
                    MHDR: util_1.asHexString(this.MHDR),
                    MACPayload: util_1.asHexString(this.MACPayload),
                    MIC: util_1.asHexString(this.MIC),
                    AppNonce: util_1.asHexString(this.AppNonce),
                    NetID: util_1.asHexString(this.NetID),
                    DevAddr: util_1.asHexString(this.DevAddr),
                    DLSettings: util_1.asHexString(this.DLSettings),
                    RxDelay: util_1.asHexString(this.RxDelay),
                    CFList: util_1.asHexString(this.CFList),
                    DLSettingsRX1DRoffset: this.getDLSettingsRxOneDRoffset(),
                    DLSettingsRX2DataRate: this.getDLSettingsRxTwoDataRate(),
                    RxDelayDel: this.getRxDelayDel(),
                    FreqCh4: util_1.asHexString(this.getCFListFreqChFour()),
                    FreqCh5: util_1.asHexString(this.getCFListFreqChFive()),
                    FreqCh6: util_1.asHexString(this.getCFListFreqChSix()),
                    FreqCh7: util_1.asHexString(this.getCFListFreqChSeven()),
                    FreqCh8: util_1.asHexString(this.getCFListFreqChEight()),
                };
            }
            else {
                res = {
                    MType: "Join Accept",
                    PHYPayload: util_1.asHexString(this.PHYPayload).toUpperCase(),
                    MHDR: util_1.asHexString(this.MHDR),
                    MACPayload: util_1.asHexString(this.MACPayload),
                    MIC: util_1.asHexString(this.MIC),
                    AppNonce: util_1.asHexString(this.AppNonce),
                    NetID: util_1.asHexString(this.NetID),
                    DevAddr: util_1.asHexString(this.DevAddr),
                    DLSettings: util_1.asHexString(this.DLSettings),
                    RxDelay: util_1.asHexString(this.RxDelay),
                    CFList: util_1.asHexString(this.CFList),
                    DLSettingsRX1DRoffset: this.getDLSettingsRxOneDRoffset(),
                    DLSettingsRX2DataRate: this.getDLSettingsRxTwoDataRate(),
                    RxDelayDel: this.getRxDelayDel(),
                };
            }
        }
        else if (this.isRejoinRequestMessage()) {
            res = {
                MType: "ReJoin Request",
                PHYPayload: util_1.asHexString(this.PHYPayload).toUpperCase(),
                MHDR: util_1.asHexString(this.MHDR),
                MACPayload: util_1.asHexString(this.MACPayload),
                MIC: util_1.asHexString(this.MIC),
            };
            if (this.RejoinType[0] === 0 || this.RejoinType[0] === 2) {
                Object.assign(res, {
                    RejoinType: util_1.asHexString(this.RejoinType),
                    NetID: util_1.asHexString(this.NetID),
                    DevEUI: util_1.asHexString(this.DevEUI),
                    RJCount0: util_1.asHexString(this.RJCount0),
                });
            }
            else if (this.RejoinType[0] === 1) {
                Object.assign(res, {
                    RejoinType: util_1.asHexString(this.RejoinType),
                    JoinEUI: util_1.asHexString(this.JoinEUI),
                    DevEUI: util_1.asHexString(this.DevEUI),
                    RJCount0: util_1.asHexString(this.RJCount0),
                });
            }
        }
        else if (this.isDataMessage()) {
            res = {
                MType: this.getMType(),
                PHYPayload: util_1.asHexString(this.PHYPayload).toUpperCase(),
                MHDR: util_1.asHexString(this.MHDR),
                MACPayload: util_1.asHexString(this.MACPayload),
                MIC: util_1.asHexString(this.MIC),
                FHDR: util_1.asHexString(this.FHDR),
                FPort: util_1.asHexString(this.FPort),
                FRMPayload: util_1.asHexString(this.FRMPayload),
                DevAddr: util_1.asHexString(this.DevAddr),
                FCtrl: util_1.asHexString(this.FCtrl),
                FCntHex: util_1.asHexString(this.FCnt),
                FOpts: util_1.asHexString(this.FOpts),
                Direction: this.getDir(),
                FCountUInt16: this.getFCnt(),
                FCtrlACK: this.getFCtrlACK(),
                FCtrlADR: this.getFCtrlADR(),
            };
            if (this._getMType() == MType.CONFIRMED_DATA_DOWN || this._getMType() == MType.UNCONFIRMED_DATA_DOWN) {
                Object.assign(res, {
                    FCtrlFPending: this.getFCtrlFPending(),
                });
            }
            else {
                Object.assign(res, {
                    FCtrlADRACKReq: this.getFCtrlADRACKReq(),
                });
            }
        }
        return res;
    }
    get JoinEUI() {
        return this.AppEUI;
    }
    set JoinEUI(v) {
        this.AppEUI = v;
    }
    get JoinNonce() {
        return this.AppNonce;
    }
    set JoinNonce(v) {
        this.AppNonce = v;
    }
}
exports.default = LoraPacket;
//# sourceMappingURL=LoraPacket.js.map