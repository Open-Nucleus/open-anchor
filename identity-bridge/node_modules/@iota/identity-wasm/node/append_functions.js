"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const _identity_wasm_1 = require("./identity_wasm.js");
function _getCoreDocumentInternal(arg) {
    if (arg instanceof _identity_wasm_1.CoreDocument) {
        return arg._shallowCloneInternal();
    }
    else {
        return arg.toCoreDocument()._shallowCloneInternal();
    }
}
function _maybeGetIotaDocumentInternal(arg) {
    if (arg instanceof _identity_wasm_1.IotaDocument) {
        return arg._shallowCloneInternal();
    }
    else {
        return;
    }
}
function _getCoreDidCloneInternal(arg) {
    if (arg instanceof _identity_wasm_1.IotaDID || arg instanceof _identity_wasm_1.CoreDID) {
        return arg.toCoreDid();
    }
    else {
        // Pass deep clone to avoid nulling out pointer.
        return arg.toCoreDid().clone();
    }
}
globalThis._getCoreDocumentInternal = _getCoreDocumentInternal;
globalThis._maybeGetIotaDocumentInternal = _maybeGetIotaDocumentInternal;
globalThis._getCoreDidCloneInternal = _getCoreDidCloneInternal;
//# sourceMappingURL=append_functions.js.map