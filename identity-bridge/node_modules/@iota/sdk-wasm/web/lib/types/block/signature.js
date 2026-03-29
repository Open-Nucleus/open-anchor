// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
/**
 * All of the signature types.
 */
var SignatureType;
(function (SignatureType) {
    /**
     * An Ed25519 signature.
     */
    SignatureType[SignatureType["Ed25519"] = 0] = "Ed25519";
})(SignatureType || (SignatureType = {}));
/**
 * The base class for signatures.
 */
var Signature = /** @class */ (function () {
    /**
     * @param type The type of signature.
     */
    function Signature(type) {
        this.type = type;
    }
    /**
     * Get the type of signature.
     */
    Signature.prototype.getType = function () {
        return this.type;
    };
    return Signature;
}());
/**
 * An Ed25519 signature.
 */
var Ed25519Signature = /** @class */ (function (_super) {
    __extends(Ed25519Signature, _super);
    /**
     * @param publicKey A Ed25519 public key as hex-encoded string.
     * @param signature A Ed25519 signature as hex-encoded string.
     */
    function Ed25519Signature(publicKey, signature) {
        var _this = _super.call(this, SignatureType.Ed25519) || this;
        _this.publicKey = publicKey;
        _this.signature = signature;
        return _this;
    }
    return Ed25519Signature;
}(Signature));
export { SignatureType, Ed25519Signature, Signature };
//# sourceMappingURL=signature.js.map