import { CoreDID, CoreDocument, IotaDID, IotaDocument } from "./identity_wasm.js";
function _getCoreDocumentInternal(arg) {
    if (arg instanceof CoreDocument) {
        return arg._shallowCloneInternal();
    }
    else {
        return arg.toCoreDocument()._shallowCloneInternal();
    }
}
function _maybeGetIotaDocumentInternal(arg) {
    if (arg instanceof IotaDocument) {
        return arg._shallowCloneInternal();
    }
    else {
        return;
    }
}
function _getCoreDidCloneInternal(arg) {
    if (arg instanceof IotaDID || arg instanceof CoreDID) {
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