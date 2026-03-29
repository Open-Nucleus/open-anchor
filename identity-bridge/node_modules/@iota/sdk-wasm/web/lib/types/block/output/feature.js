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
import { Address, AddressDiscriminator } from '../address';
/**
 * All of the feature block types.
 */
var FeatureType;
(function (FeatureType) {
    /** A Sender feature. */
    FeatureType[FeatureType["Sender"] = 0] = "Sender";
    /** An Issuer feature. */
    FeatureType[FeatureType["Issuer"] = 1] = "Issuer";
    /** A Metadata feature. */
    FeatureType[FeatureType["Metadata"] = 2] = "Metadata";
    /** A Tag feature. */
    FeatureType[FeatureType["Tag"] = 3] = "Tag";
})(FeatureType || (FeatureType = {}));
/** The base class for features. */
var Feature = /** @class */ (function () {
    /**
     * @param type The type of feature.
     */
    function Feature(type) {
        this.type = type;
    }
    /**
     * Get the type of feature.
     */
    Feature.prototype.getType = function () {
        return this.type;
    };
    return Feature;
}());
/**
 * A Sender feature.
 */
var SenderFeature = /** @class */ (function (_super) {
    __extends(SenderFeature, _super);
    /**
     * @param sender The Sender address stored with the feature.
     */
    function SenderFeature(sender) {
        var _this = _super.call(this, FeatureType.Sender) || this;
        _this.address = sender;
        return _this;
    }
    /**
     * Get the sender address.
     */
    SenderFeature.prototype.getSender = function () {
        return this.address;
    };
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], SenderFeature.prototype, "address");
    return SenderFeature;
}(Feature));
/**
 * An Issuer feature.
 */
var IssuerFeature = /** @class */ (function (_super) {
    __extends(IssuerFeature, _super);
    /**
     * @param issuer The Issuer address stored with the feature.
     */
    function IssuerFeature(issuer) {
        var _this = _super.call(this, FeatureType.Issuer) || this;
        _this.address = issuer;
        return _this;
    }
    /**
     * Get the Issuer address.
     */
    IssuerFeature.prototype.getIssuer = function () {
        return this.address;
    };
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], IssuerFeature.prototype, "address");
    return IssuerFeature;
}(Feature));
/**
 * A Metadata feature.
 */
var MetadataFeature = /** @class */ (function (_super) {
    __extends(MetadataFeature, _super);
    /**
     * @param data The metadata stored with the feature.
     */
    function MetadataFeature(data) {
        var _this = _super.call(this, FeatureType.Metadata) || this;
        _this.data = data;
        return _this;
    }
    /**
     * Get the metadata.
     */
    MetadataFeature.prototype.getData = function () {
        return this.data;
    };
    return MetadataFeature;
}(Feature));
/**
 * A Tag feature.
 */
var TagFeature = /** @class */ (function (_super) {
    __extends(TagFeature, _super);
    /**
     * @param tag The tag stored with the feature.
     */
    function TagFeature(tag) {
        var _this = _super.call(this, FeatureType.Tag) || this;
        _this.tag = tag;
        return _this;
    }
    /**
     * Get the tag.
     */
    TagFeature.prototype.getTag = function () {
        return this.tag;
    };
    return TagFeature;
}(Feature));
var FeatureDiscriminator = {
    property: 'type',
    subTypes: [
        { value: SenderFeature, name: FeatureType.Sender },
        { value: IssuerFeature, name: FeatureType.Issuer },
        { value: MetadataFeature, name: FeatureType.Metadata },
        { value: TagFeature, name: FeatureType.Tag },
    ]
};
export { FeatureDiscriminator, Feature, FeatureType, SenderFeature, IssuerFeature, MetadataFeature, TagFeature, };
//# sourceMappingURL=feature.js.map