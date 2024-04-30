/// <reference types="node" />
import LoraPacket from "./LoraPacket";
declare function calculateMIC(payload: LoraPacket, NwkSKey?: Buffer, //NwkSKey for DataUP/Down; SNwkSIntKey in data 1.1; SNwkSIntKey in Join 1.1
AppKey?: Buffer, //AppSKey for DataUP/Down; FNwkSIntKey in data 1.1; JSIntKey in Join 1.1
FCntMSBytes?: Buffer, ConfFCntDownTxDrTxCh?: Buffer): Buffer;
declare function verifyMIC(payload: LoraPacket, NwkSKey?: Buffer, AppKey?: Buffer, FCntMSBytes?: Buffer, ConfFCntDownTxDrTxCh?: Buffer): boolean;
declare function recalculateMIC(payload: LoraPacket, NwkSKey?: Buffer, AppKey?: Buffer, FCntMSBytes?: Buffer, ConfFCntDownTxDrTxCh?: Buffer): void;
export { calculateMIC, verifyMIC, recalculateMIC };
//# sourceMappingURL=mic.d.ts.map