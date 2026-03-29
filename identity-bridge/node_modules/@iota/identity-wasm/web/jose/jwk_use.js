/** Supported algorithms for the JSON Web Key `use` property.
 *
 * [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-use) */
export var JwkUse;
(function (JwkUse) {
    /** Digital Signature or MAC. */
    JwkUse["Signature"] = "sig";
    /** Encryption. */
    JwkUse["Encryption"] = "enc";
})(JwkUse || (JwkUse = {}));
//# sourceMappingURL=jwk_use.js.map