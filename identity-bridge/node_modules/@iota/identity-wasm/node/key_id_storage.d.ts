import type { KeyIdStorage, MethodDigest } from "./identity_wasm.js";
export declare class KeyIdMemStore implements KeyIdStorage {
    private _keyIds;
    constructor();
    insertKeyId(methodDigest: MethodDigest, keyId: string): Promise<void>;
    getKeyId(methodDigest: MethodDigest): Promise<string>;
    deleteKeyId(methodDigest: MethodDigest): Promise<void>;
    count(): number;
}
