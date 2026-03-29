// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
import { utf8ToHex } from '../../../utils/utf8';
import { MetadataFeature } from './feature';
/**
 * The IRC30 native token metadata standard schema.
 */
var Irc30Metadata = /** @class */ (function () {
    /**
     * @param name The human-readable name of the native token.
     * @param symbol The symbol/ticker of the token.
     * @param decimals Number of decimals the token uses.
     */
    function Irc30Metadata(name, symbol, decimals) {
        /** The IRC standard */
        this.standard = 'IRC30';
        this.name = name;
        this.symbol = symbol;
        this.decimals = decimals;
    }
    Irc30Metadata.prototype.withDescription = function (description) {
        this.description = description;
        return this;
    };
    Irc30Metadata.prototype.withUrl = function (url) {
        this.url = url;
        return this;
    };
    Irc30Metadata.prototype.withLogoUrl = function (logoUrl) {
        this.logoUrl = logoUrl;
        return this;
    };
    Irc30Metadata.prototype.withLogo = function (logo) {
        this.logo = logo;
        return this;
    };
    Irc30Metadata.prototype.asHex = function () {
        return utf8ToHex(JSON.stringify(this));
    };
    Irc30Metadata.prototype.asFeature = function () {
        return new MetadataFeature(this.asHex());
    };
    return Irc30Metadata;
}());
export { Irc30Metadata };
//# sourceMappingURL=irc-30.js.map