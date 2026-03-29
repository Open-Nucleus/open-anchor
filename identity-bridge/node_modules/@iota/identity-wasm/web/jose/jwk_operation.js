/** Supported algorithms for the JSON Web Key `key_ops` property.
 *
 * [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-operations) */
export var JwkOperation;
(function (JwkOperation) {
    /** Compute digital signature or MAC. */
    JwkOperation["Sign"] = "sign";
    /** Verify digital signature or MAC. */
    JwkOperation["Verify"] = "verify";
    /** Encrypt content. */
    JwkOperation["Encrypt"] = "encrypt";
    /** Decrypt content and validate decryption, if applicable. */
    JwkOperation["Decrypt"] = "decrypt";
    /** Encrypt key. */
    JwkOperation["WrapKey"] = "wrapKey";
    /** Decrypt key and validate decryption, if applicable. */
    JwkOperation["UnwrapKey"] = "unwrapKey";
    /** Derive key. */
    JwkOperation["DeriveKey"] = "deriveKey";
    /** Derive bits not to be used as a key. */
    JwkOperation["DeriveBits"] = "deriveBits";
})(JwkOperation || (JwkOperation = {}));
//# sourceMappingURL=jwk_operation.js.map