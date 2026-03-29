/** Supported Elliptic Curves.
 *
 * [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve) */
export declare const enum EcCurve {
    /** P-256 Curve. */
    P256 = 0,
    /** P-384 Curve. */
    P384 = 1,
    /** P-521 Curve. */
    P521 = 2,
    /** SECG secp256k1 curve. */
    Secp256K1 = 3
}
