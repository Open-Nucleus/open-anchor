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
import { plainToInstance } from 'class-transformer';
/**
 * Address type variants.
 */
var AddressType;
(function (AddressType) {
    /** An Ed25519 address. */
    AddressType[AddressType["Ed25519"] = 0] = "Ed25519";
    /** An Alias address. */
    AddressType[AddressType["Alias"] = 8] = "Alias";
    /** An NFT address. */
    AddressType[AddressType["Nft"] = 16] = "Nft";
})(AddressType || (AddressType = {}));
/**
 * The base class for addresses.
 */
var Address = /** @class */ (function () {
    /**
     * @param type The type of the address.
     */
    function Address(type) {
        this.type = type;
    }
    /**
     * Get the type of address.
     */
    Address.prototype.getType = function () {
        return this.type;
    };
    /**
     * Parse an address from a JSON string.
     */
    Address.parse = function (data) {
        if (data.type == AddressType.Ed25519) {
            return plainToInstance(Ed25519Address, data);
        }
        else if (data.type == AddressType.Alias) {
            return plainToInstance(AliasAddress, data);
        }
        else if (data.type == AddressType.Nft) {
            return plainToInstance(NftAddress, data);
        }
        throw new Error('Invalid JSON');
    };
    return Address;
}());
/**
 * An Ed25519 Address.
 */
var Ed25519Address = /** @class */ (function (_super) {
    __extends(Ed25519Address, _super);
    /**
     * @param address An Ed25519 address as hex-encoded string.
     */
    function Ed25519Address(address) {
        var _this = _super.call(this, AddressType.Ed25519) || this;
        _this.pubKeyHash = address;
        return _this;
    }
    /**
     * Get the public key hash.
     */
    Ed25519Address.prototype.getPubKeyHash = function () {
        return this.pubKeyHash;
    };
    Ed25519Address.prototype.toString = function () {
        return this.getPubKeyHash();
    };
    return Ed25519Address;
}(Address));
/**
 * An Alias address.
 */
var AliasAddress = /** @class */ (function (_super) {
    __extends(AliasAddress, _super);
    /**
     * @param address An Alias address as Alias ID.
     */
    function AliasAddress(address) {
        var _this = _super.call(this, AddressType.Alias) || this;
        _this.aliasId = address;
        return _this;
    }
    /**
     * Get the alias ID.
     */
    AliasAddress.prototype.getAliasId = function () {
        return this.aliasId;
    };
    AliasAddress.prototype.toString = function () {
        return this.getAliasId();
    };
    return AliasAddress;
}(Address));
/**
 * An NFT address.
 */
var NftAddress = /** @class */ (function (_super) {
    __extends(NftAddress, _super);
    /**
     * @param address An NFT address as NFT ID.
     */
    function NftAddress(address) {
        var _this = _super.call(this, AddressType.Nft) || this;
        _this.nftId = address;
        return _this;
    }
    /**
     * Get the NFT ID.
     */
    NftAddress.prototype.getNftId = function () {
        return this.nftId;
    };
    NftAddress.prototype.toString = function () {
        return this.getNftId();
    };
    return NftAddress;
}(Address));
var AddressDiscriminator = {
    property: 'type',
    subTypes: [
        { value: Ed25519Address, name: AddressType.Ed25519 },
        { value: AliasAddress, name: AddressType.Alias },
        { value: NftAddress, name: AddressType.Nft },
    ]
};
export { AddressDiscriminator, Address, AddressType, Ed25519Address, AliasAddress, NftAddress, };
//# sourceMappingURL=address.js.map