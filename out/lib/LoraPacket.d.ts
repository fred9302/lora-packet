/// <reference types="node" />
declare enum LorawanVersion {
    V1_0 = "1.0",
    V1_1 = "1.1"
}
export interface UserFields {
    CFList?: Buffer;
    RxDelay?: Buffer | number;
    DLSettings?: Buffer | number;
    NetID?: Buffer;
    AppNonce?: Buffer;
    DevNonce?: Buffer;
    DevEUI?: Buffer;
    AppEUI?: Buffer;
    FPort?: number;
    FOpts?: string | Buffer;
    FCnt?: number | Buffer;
    MType?: string | number;
    DevAddr?: Buffer;
    payload?: string | Buffer;
    FCtrl?: {
        ADR?: boolean;
        ADRACKReq?: boolean;
        ACK?: boolean;
        FPending?: boolean;
    };
    JoinReqType?: Buffer | number;
}
declare class LoraPacket {
    static fromWire(buffer: Buffer): LoraPacket;
    static fromFields(fields: UserFields, AppSKey?: Buffer, NwkSKey?: Buffer, AppKey?: Buffer, FCntMSBytes?: Buffer, ConfFCntDownTxDrTxCh?: Buffer): LoraPacket;
    private assignFromStructuredBuffer;
    private _initfromWire;
    private _initFromFields;
    private _mergeGroupFields;
    private _initialiseDataPacketFromFields;
    private _initialiseJoinRequestPacketFromFields;
    private _initialiseJoinAcceptPacketFromFields;
    private _getMType;
    isDataMessage(): boolean;
    isConfirmed(): boolean;
    /**
     * Provide MType as a string
     */
    getMType(): string;
    /**
     * Provide Direction as a string
     */
    getDir(): string | null;
    /**
     * Provide FPort as a number
     */
    getFPort(): number | null;
    /**
     * Provide FCnt as a number
     */
    getFCnt(): number | null;
    /**
     * Provide FCtrl.ACK as a flag
     */
    getFCtrlACK(): boolean | null;
    /**
     * Provide FCtrl.ADR as a flag
     */
    getFCtrlADR(): boolean | null;
    /**
     * Provide FCtrl.ADRACKReq as a flag
     */
    getFCtrlADRACKReq(): boolean | null;
    /**
     * Provide FCtrl.FPending as a flag
     */
    getFCtrlFPending(): boolean | null;
    /**
     * Provide DLSettings.RX1DRoffset as integer
     */
    getDLSettingsRxOneDRoffset(): number | null;
    /**
     * Provide DLSettings.RX2DataRate as integer
     */
    getDLSettingsRxTwoDataRate(): number | null;
    /**
     * Provide DLSettings.OptNeg as boolean
     */
    getDLSettingsOptNeg(): boolean | null;
    /**
     * Provide RxDelay.Del as integer
     */
    getRxDelayDel(): number | null;
    /**
     * Provide CFList.FreqChFour as buffer
     */
    getCFListFreqChFour(): Buffer;
    /**
     * Provide CFList.FreqChFive as buffer
     */
    getCFListFreqChFive(): Buffer;
    /**
     * Provide CFList.FreqChSix as buffer
     */
    getCFListFreqChSix(): Buffer;
    /**
     * Provide CFList.FreqChSeven as buffer
     */
    getCFListFreqChSeven(): Buffer;
    /**
     * Provide CFList.FreqChEight as buffer
     */
    getCFListFreqChEight(): Buffer;
    getBuffers(): this;
    decryptFOpts(NwkSEncKey: Buffer, NwkSKey?: Buffer, FCntMSBytes?: Buffer, ConfFCntDownTxDrTxCh?: Buffer): Buffer;
    encryptFOpts(NwkSEncKey: Buffer, SNwkSIntKey?: Buffer, FCntMSBytes?: Buffer, ConfFCntDownTxDrTxCh?: Buffer): Buffer;
    getPHYPayload(): Buffer | void;
    isJoinRequestMessage(): boolean;
    isRejoinRequestMessage(): boolean;
    isReJoinRequestMessage(): boolean;
    isJoinAcceptMessage(): boolean;
    toString(): string;
    toObject(): any;
    get JoinEUI(): Buffer;
    set JoinEUI(v: Buffer);
    get JoinNonce(): Buffer;
    set JoinNonce(v: Buffer);
    PHYPayload?: Buffer;
    MHDR?: Buffer;
    MACPayload?: Buffer;
    MACPayloadWithMIC?: Buffer;
    AppEUI?: Buffer;
    DevEUI?: Buffer;
    DevNonce?: Buffer;
    MIC?: Buffer;
    AppNonce?: Buffer;
    NetID?: Buffer;
    DevAddr?: Buffer;
    DLSettings?: Buffer;
    RxDelay?: Buffer;
    CFList?: Buffer;
    FCtrl?: Buffer;
    FOpts?: Buffer;
    FCnt?: Buffer;
    FHDR?: Buffer;
    FPort?: Buffer;
    FRMPayload?: Buffer;
    JoinReqType?: Buffer;
    RejoinType?: Buffer;
    RJCount0?: Buffer;
    RJCount1?: Buffer;
}
export default LoraPacket;
export { LorawanVersion };
//# sourceMappingURL=LoraPacket.d.ts.map