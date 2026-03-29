// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
import { utf8ToHex } from '../../../utils/utf8';
import { MetadataFeature } from './feature';
/**
 * The IRC27 NFT standard schema.
 */
var Irc27Metadata = /** @class */ (function () {
    /**
     * @param type The media type (MIME) of the asset.
     * @param uri URL pointing to the NFT file location.
     * @param name The human-readable name of the native token.
     */
    function Irc27Metadata(type, uri, name) {
        /** The IRC standard */
        this.standard = 'IRC27';
        /** The current version. */
        this.version = 'v1.0';
        /** Royalty payment addresses mapped to the payout percentage. */
        this.royalties = new Map();
        /** Additional attributes which follow [OpenSea Metadata standards](https://docs.opensea.io/docs/metadata-standards). */
        this.attributes = [];
        this.type = type;
        this.uri = uri;
        this.name = name;
    }
    Irc27Metadata.prototype.withCollectionName = function (collectionName) {
        this.collectionName = collectionName;
        return this;
    };
    Irc27Metadata.prototype.addRoyalty = function (address, percentage) {
        this.royalties.set(address, percentage);
        return this;
    };
    Irc27Metadata.prototype.withRoyalties = function (royalties) {
        this.royalties = royalties;
        return this;
    };
    Irc27Metadata.prototype.withIssuerName = function (issuerName) {
        this.issuerName = issuerName;
        return this;
    };
    Irc27Metadata.prototype.withDescription = function (description) {
        this.description = description;
        return this;
    };
    Irc27Metadata.prototype.addAttribute = function (attribute) {
        this.attributes.push(attribute);
        return this;
    };
    Irc27Metadata.prototype.withAttributes = function (attributes) {
        this.attributes = attributes;
        return this;
    };
    Irc27Metadata.prototype.asHex = function () {
        return utf8ToHex(JSON.stringify(this));
    };
    Irc27Metadata.prototype.asFeature = function () {
        return new MetadataFeature(this.asHex());
    };
    return Irc27Metadata;
}());
var Attribute = /** @class */ (function () {
    function Attribute(trait_type, value) {
        this.trait_type = trait_type;
        this.value = value;
    }
    Attribute.prototype.withDisplayType = function (display_type) {
        this.display_type = display_type;
        return this;
    };
    return Attribute;
}());
export { Irc27Metadata, Attribute };
//# sourceMappingURL=irc-27.js.map