"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.asHexString = exports.reverseBuffer = void 0;
function reverseBuffer(buffer) {
    const reversedBuffer = Buffer.from(buffer);
    return reversedBuffer.reverse();
}
exports.reverseBuffer = reverseBuffer;
function asHexString(buffer) {
    return buffer.toString("hex").toUpperCase();
}
exports.asHexString = asHexString;
//# sourceMappingURL=util.js.map