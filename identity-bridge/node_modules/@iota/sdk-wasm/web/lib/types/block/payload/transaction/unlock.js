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
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { Type } from 'class-transformer';
import { Ed25519Signature } from '../../signature';
/**
 * All of the unlock types.
 */
var UnlockType;
(function (UnlockType) {
    /**
     * A signature unlock.
     */
    UnlockType[UnlockType["Signature"] = 0] = "Signature";
    /**
     * A reference unlock.
     */
    UnlockType[UnlockType["Reference"] = 1] = "Reference";
    /**
     * An Alias unlock.
     */
    UnlockType[UnlockType["Alias"] = 2] = "Alias";
    /**
     * An NFT unlock.
     */
    UnlockType[UnlockType["Nft"] = 3] = "Nft";
})(UnlockType || (UnlockType = {}));
/**
 * The base class for unlocks.
 */
var Unlock = /** @class */ (function () {
    /**
     * @param type The type of unlock.
     */
    function Unlock(type) {
        this.type = type;
    }
    /**
     * Get the type of unlock.
     */
    Unlock.prototype.getType = function () {
        return this.type;
    };
    return Unlock;
}());
/**
 * An unlock holding one or more signatures unlocking one or more inputs..
 */
var SignatureUnlock = /** @class */ (function (_super) {
    __extends(SignatureUnlock, _super);
    /**
     * @param signature An Ed25519 signature.
     */
    function SignatureUnlock(signature) {
        var _this = _super.call(this, UnlockType.Signature) || this;
        _this.signature = signature;
        return _this;
    }
    __decorate([
        Type(function () { return Ed25519Signature; })
    ], SignatureUnlock.prototype, "signature");
    return SignatureUnlock;
}(Unlock));
/**
 * An unlock which must reference a previous unlock which unlocks
 * also the input at the same index as this Reference Unlock.
 */
var ReferenceUnlock = /** @class */ (function (_super) {
    __extends(ReferenceUnlock, _super);
    /**
     * @param reference An index referencing a previous unlock.
     */
    function ReferenceUnlock(reference) {
        var _this = _super.call(this, UnlockType.Reference) || this;
        _this.reference = reference;
        return _this;
    }
    return ReferenceUnlock;
}(Unlock));
/**
 * An unlock which must reference a previous unlock which unlocks the alias that the input is locked to.
 */
var AliasUnlock = /** @class */ (function (_super) {
    __extends(AliasUnlock, _super);
    /**
     * @param reference An index referencing a previous unlock.
     */
    function AliasUnlock(reference) {
        var _this = _super.call(this, UnlockType.Alias) || this;
        _this.reference = reference;
        return _this;
    }
    return AliasUnlock;
}(Unlock));
/**
 * An unlock which must reference a previous unlock which unlocks the NFT that the input is locked to.
 */
var NftUnlock = /** @class */ (function (_super) {
    __extends(NftUnlock, _super);
    /**
     * @param reference An index referencing a previous unlock.
     */
    function NftUnlock(reference) {
        var _this = _super.call(this, UnlockType.Nft) || this;
        _this.reference = reference;
        return _this;
    }
    return NftUnlock;
}(Unlock));
var UnlockDiscriminator = {
    property: 'type',
    subTypes: [
        {
            value: SignatureUnlock,
            name: UnlockType.Signature
        },
        {
            value: ReferenceUnlock,
            name: UnlockType.Reference
        },
        {
            value: AliasUnlock,
            name: UnlockType.Alias
        },
        {
            value: NftUnlock,
            name: UnlockType.Nft
        },
    ]
};
export { UnlockType, Unlock, SignatureUnlock, ReferenceUnlock, AliasUnlock, NftUnlock, UnlockDiscriminator, };
//# sourceMappingURL=unlock.js.map