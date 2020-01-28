import * as wasm from './js_chain_libs_bg.wasm';

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachegetUint8Memory0 = null;
function getUint8Memory0() {
    if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

const heap = new Array(32);

heap.fill(undefined);

heap.push(undefined, null, true, false);

let heap_next = heap.length;

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function getObject(idx) { return heap[idx]; }

function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let WASM_VECTOR_LEN = 0;

let cachedTextEncoder = new TextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len);

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachegetInt32Memory0 = null;
function getInt32Memory0() {
    if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
        cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachegetInt32Memory0;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1);
    getUint8Memory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}
/**
* @param {any} input
* @returns {string}
*/
export function uint8array_to_hex(input) {
    try {
        wasm.uint8array_to_hex(8, addHeapObject(input));
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        return getStringFromWasm0(r0, r1);
    } finally {
        wasm.__wbindgen_free(r0, r1);
    }
}

/**
* Allow to differentiate between address in
* production and testing setting, so that
* one type of address is not used in another setting.
* Example
* ```javascript
* let discriminant = AddressDiscrimination.Test;
* let address = Address::single_from_public_key(public_key, discriminant);
* ```
*/
export const AddressDiscrimination = Object.freeze({ Production:0,Test:1, });
/**
*/
export const AddressKind = Object.freeze({ Single:0,Group:1,Account:2,Multisig:3, });
/**
*/
export const InputKind = Object.freeze({ Account:0,Utxo:1, });
/**
*/
export const DelegationKind = Object.freeze({ NonDelegated:0,Full:1,Ratio:2, });
/**
*/
export const CertificateKind = Object.freeze({ StakeDelegation:0,OwnerStakeDelegation:1,PoolRegistration:2,PoolRetirement:3,PoolUpdate:4, });
/**
* This is either an single account or a multisig account depending on the witness type
*/
export class Account {

    static __wrap(ptr) {
        const obj = Object.create(Account.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_account_free(ptr);
    }
    /**
    * @param {Address} address
    * @returns {Account}
    */
    static from_address(address) {
        _assertClass(address, Address);
        var ret = wasm.account_from_address(address.ptr);
        return Account.__wrap(ret);
    }
    /**
    * @param {number} discriminant
    * @returns {Address}
    */
    to_address(discriminant) {
        var ret = wasm.account_to_address(this.ptr, discriminant);
        return Address.__wrap(ret);
    }
    /**
    * @param {PublicKey} key
    * @returns {Account}
    */
    static single_from_public_key(key) {
        _assertClass(key, PublicKey);
        var ret = wasm.account_single_from_public_key(key.ptr);
        return Account.__wrap(ret);
    }
    /**
    * @returns {AccountIdentifier}
    */
    to_identifier() {
        var ret = wasm.account_to_identifier(this.ptr);
        return AccountIdentifier.__wrap(ret);
    }
}
/**
*/
export class AccountAddress {

    static __wrap(ptr) {
        const obj = Object.create(AccountAddress.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_accountaddress_free(ptr);
    }
    /**
    * @returns {PublicKey}
    */
    get_account_key() {
        var ret = wasm.accountaddress_get_account_key(this.ptr);
        return PublicKey.__wrap(ret);
    }
    /**
    * @returns {Address}
    */
    to_base_address() {
        var ret = wasm.accountaddress_to_base_address(this.ptr);
        return Address.__wrap(ret);
    }
}
/**
*/
export class AccountBindingSignature {

    static __wrap(ptr) {
        const obj = Object.create(AccountBindingSignature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_accountbindingsignature_free(ptr);
    }
    /**
    * @param {PrivateKey} private_key
    * @param {TransactionBindingAuthData} auth_data
    * @returns {AccountBindingSignature}
    */
    static new_single(private_key, auth_data) {
        _assertClass(private_key, PrivateKey);
        _assertClass(auth_data, TransactionBindingAuthData);
        var ret = wasm.accountbindingsignature_new_single(private_key.ptr, auth_data.ptr);
        return AccountBindingSignature.__wrap(ret);
    }
}
/**
*/
export class AccountIdentifier {

    static __wrap(ptr) {
        const obj = Object.create(AccountIdentifier.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_accountidentifier_free(ptr);
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.accountidentifier_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {AccountIdentifier}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.accountidentifier_from_bytes(ptr0, len0);
        return AccountIdentifier.__wrap(ret);
    }
    /**
    * @returns {Account}
    */
    to_account_single() {
        var ret = wasm.accountidentifier_to_account_single(this.ptr);
        return Account.__wrap(ret);
    }
    /**
    * @returns {Account}
    */
    to_account_multi() {
        var ret = wasm.accountidentifier_to_account_multi(this.ptr);
        return Account.__wrap(ret);
    }
}
/**
*/
export class AccountWitness {

    static __wrap(ptr) {
        const obj = Object.create(AccountWitness.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_accountwitness_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.accountwitness_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.accountwitness_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.accountwitness_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {AccountWitness}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.accountwitness_from_bytes(ptr0, len0);
        return AccountWitness.__wrap(ret);
    }
    /**
    * @param {string} bech32_str
    * @returns {AccountWitness}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.accountwitness_from_bech32(ptr0, len0);
        return AccountWitness.__wrap(ret);
    }
    /**
    * @param {string} input
    * @returns {AccountWitness}
    */
    static from_hex(input) {
        var ptr0 = passStringToWasm0(input, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.accountwitness_from_hex(ptr0, len0);
        return AccountWitness.__wrap(ret);
    }
}
/**
* An address of any type, this can be one of
* * A utxo-based address without delegation (single)
* * A utxo-based address with delegation (group)
* * An address for an account
*/
export class Address {

    static __wrap(ptr) {
        const obj = Object.create(Address.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_address_free(ptr);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {Address}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.address_from_bytes(ptr0, len0);
        return Address.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.address_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * Construct Address from its bech32 representation
    * Example
    * ```javascript
    * const address = Address.from_string(&#39;ca1q09u0nxmnfg7af8ycuygx57p5xgzmnmgtaeer9xun7hly6mlgt3pjyknplu&#39;);
    * ```
    * @param {string} s
    * @returns {Address}
    */
    static from_string(s) {
        var ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.address_from_string(ptr0, len0);
        return Address.__wrap(ret);
    }
    /**
    * Get Address bech32 (string) representation with a given prefix
    * ```javascript
    * let public_key = PublicKey.from_bech32(
    *     &#39;ed25519_pk1kj8yvfrh5tg7n62kdcw3kw6zvtcafgckz4z9s6vc608pzt7exzys4s9gs8&#39;
    * );
    * let discriminant = AddressDiscrimination.Test;
    * let address = Address.single_from_public_key(public_key, discriminant);
    * address.to_string(&#39;ta&#39;)
    * // ta1sj6gu33yw73dr60f2ehp6xemgf30r49rzc25gkrfnrfuuyf0mycgnj78ende550w5njvwzyr20q6rypdea597uu3jnwfltljddl59cseaq7yn9
    * ```
    * @param {string} prefix
    * @returns {string}
    */
    to_string(prefix) {
        try {
            var ptr0 = passStringToWasm0(prefix, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len0 = WASM_VECTOR_LEN;
            wasm.address_to_string(8, this.ptr, ptr0, len0);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * Construct a single non-account address from a public key
    * ```javascript
    * let public_key = PublicKey.from_bech32(
    *     &#39;ed25519_pk1kj8yvfrh5tg7n62kdcw3kw6zvtcafgckz4z9s6vc608pzt7exzys4s9gs8&#39;
    * );
    * let address = Address.single_from_public_key(public_key, AddressDiscrimination.Test);
    * ```
    * @param {PublicKey} key
    * @param {number} discrimination
    * @returns {Address}
    */
    static single_from_public_key(key, discrimination) {
        _assertClass(key, PublicKey);
        var ret = wasm.address_single_from_public_key(key.ptr, discrimination);
        return Address.__wrap(ret);
    }
    /**
    * Construct a non-account address from a pair of public keys, delegating founds from the first to the second
    * @param {PublicKey} key
    * @param {PublicKey} delegation
    * @param {number} discrimination
    * @returns {Address}
    */
    static delegation_from_public_key(key, delegation, discrimination) {
        _assertClass(key, PublicKey);
        _assertClass(delegation, PublicKey);
        var ret = wasm.address_delegation_from_public_key(key.ptr, delegation.ptr, discrimination);
        return Address.__wrap(ret);
    }
    /**
    * Construct address of account type from a public key
    * @param {PublicKey} key
    * @param {number} discrimination
    * @returns {Address}
    */
    static account_from_public_key(key, discrimination) {
        _assertClass(key, PublicKey);
        var ret = wasm.address_account_from_public_key(key.ptr, discrimination);
        return Address.__wrap(ret);
    }
    /**
    * @param {Uint8Array} merkle_root
    * @param {number} discrimination
    * @returns {Address}
    */
    static multisig_from_merkle_root(merkle_root, discrimination) {
        var ptr0 = passArray8ToWasm0(merkle_root, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.address_multisig_from_merkle_root(ptr0, len0, discrimination);
        return Address.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    get_discrimination() {
        var ret = wasm.address_get_discrimination(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {number}
    */
    get_kind() {
        var ret = wasm.address_get_kind(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {SingleAddress | undefined}
    */
    to_single_address() {
        var ret = wasm.address_to_single_address(this.ptr);
        return ret === 0 ? undefined : SingleAddress.__wrap(ret);
    }
    /**
    * @returns {GroupAddress | undefined}
    */
    to_group_address() {
        var ret = wasm.address_to_group_address(this.ptr);
        return ret === 0 ? undefined : GroupAddress.__wrap(ret);
    }
    /**
    * @returns {AccountAddress | undefined}
    */
    to_account_address() {
        var ret = wasm.address_to_account_address(this.ptr);
        return ret === 0 ? undefined : AccountAddress.__wrap(ret);
    }
    /**
    * @returns {MultisigAddress | undefined}
    */
    to_multisig_address() {
        var ret = wasm.address_to_multisig_address(this.ptr);
        return ret === 0 ? undefined : MultisigAddress.__wrap(ret);
    }
}
/**
* Amount of the balance in the transaction.
*/
export class Balance {

    static __wrap(ptr) {
        const obj = Object.create(Balance.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_balance_free(ptr);
    }
    /**
    * @returns {any}
    */
    get_sign() {
        var ret = wasm.balance_get_sign(this.ptr);
        return takeObject(ret);
    }
    /**
    * @returns {boolean}
    */
    is_positive() {
        var ret = wasm.balance_is_positive(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_negative() {
        var ret = wasm.balance_is_negative(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_zero() {
        var ret = wasm.balance_is_zero(this.ptr);
        return ret !== 0;
    }
    /**
    * Get value without taking into account if the balance is positive or negative
    * @returns {Value}
    */
    get_value() {
        var ret = wasm.balance_get_value(this.ptr);
        return Value.__wrap(ret);
    }
}
/**
*/
export class Bip32PrivateKey {

    static __wrap(ptr) {
        const obj = Object.create(Bip32PrivateKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_bip32privatekey_free(ptr);
    }
    /**
    * derive this private key with the given index.
    *
    * # Security considerations
    *
    * * hard derivation index cannot be soft derived with the public key
    *
    * # Hard derivation vs Soft derivation
    *
    * If you pass an index below 0x80000000 then it is a soft derivation.
    * The advantage of soft derivation is that it is possible to derive the
    * public key too. I.e. derivation the private key with a soft derivation
    * index and then retrieving the associated public key is equivalent to
    * deriving the public key associated to the parent private key.
    *
    * Hard derivation index does not allow public key derivation.
    *
    * This is why deriving the private key should not fail while deriving
    * the public key may fail (if the derivation index is invalid).
    * @param {number} index
    * @returns {Bip32PrivateKey}
    */
    derive(index) {
        var ret = wasm.bip32privatekey_derive(this.ptr, index);
        return Bip32PrivateKey.__wrap(ret);
    }
    /**
    * @returns {Bip32PrivateKey}
    */
    static generate_ed25519_bip32() {
        var ret = wasm.bip32privatekey_generate_ed25519_bip32();
        return Bip32PrivateKey.__wrap(ret);
    }
    /**
    * @returns {PrivateKey}
    */
    to_raw_key() {
        var ret = wasm.bip32privatekey_to_raw_key(this.ptr);
        return PrivateKey.__wrap(ret);
    }
    /**
    * @returns {Bip32PublicKey}
    */
    to_public() {
        var ret = wasm.bip32privatekey_to_public(this.ptr);
        return Bip32PublicKey.__wrap(ret);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {Bip32PrivateKey}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.bip32privatekey_from_bytes(ptr0, len0);
        return Bip32PrivateKey.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.bip32privatekey_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {string} bech32_str
    * @returns {Bip32PrivateKey}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.bip32privatekey_from_bech32(ptr0, len0);
        return Bip32PrivateKey.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.bip32privatekey_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {Uint8Array} entropy
    * @param {Uint8Array} password
    * @returns {Bip32PrivateKey}
    */
    static from_bip39_entropy(entropy, password) {
        var ptr0 = passArray8ToWasm0(entropy, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = passArray8ToWasm0(password, wasm.__wbindgen_malloc);
        var len1 = WASM_VECTOR_LEN;
        var ret = wasm.bip32privatekey_from_bip39_entropy(ptr0, len0, ptr1, len1);
        return Bip32PrivateKey.__wrap(ret);
    }
}
/**
*/
export class Bip32PublicKey {

    static __wrap(ptr) {
        const obj = Object.create(Bip32PublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_bip32publickey_free(ptr);
    }
    /**
    * derive this public key with the given index.
    *
    * # Errors
    *
    * If the index is not a soft derivation index (< 0x80000000) then
    * calling this method will fail.
    *
    * # Security considerations
    *
    * * hard derivation index cannot be soft derived with the public key
    *
    * # Hard derivation vs Soft derivation
    *
    * If you pass an index below 0x80000000 then it is a soft derivation.
    * The advantage of soft derivation is that it is possible to derive the
    * public key too. I.e. derivation the private key with a soft derivation
    * index and then retrieving the associated public key is equivalent to
    * deriving the public key associated to the parent private key.
    *
    * Hard derivation index does not allow public key derivation.
    *
    * This is why deriving the private key should not fail while deriving
    * the public key may fail (if the derivation index is invalid).
    * @param {number} index
    * @returns {Bip32PublicKey}
    */
    derive(index) {
        var ret = wasm.bip32publickey_derive(this.ptr, index);
        return Bip32PublicKey.__wrap(ret);
    }
    /**
    * @returns {PublicKey}
    */
    to_raw_key() {
        var ret = wasm.bip32publickey_to_raw_key(this.ptr);
        return PublicKey.__wrap(ret);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {Bip32PublicKey}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.bip32publickey_from_bytes(ptr0, len0);
        return Bip32PublicKey.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.bip32publickey_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {string} bech32_str
    * @returns {Bip32PublicKey}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.bip32publickey_from_bech32(ptr0, len0);
        return Bip32PublicKey.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.bip32publickey_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
* `Block` is an element of the blockchain it contains multiple
* transaction and a reference to the parent block. Alongside
* with the position of that block in the chain.
*/
export class Block {

    static __wrap(ptr) {
        const obj = Object.create(Block.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_block_free(ptr);
    }
    /**
    * Deserialize a block from a byte array
    * @param {any} bytes
    * @returns {Block}
    */
    static from_bytes(bytes) {
        var ret = wasm.block_from_bytes(addHeapObject(bytes));
        return Block.__wrap(ret);
    }
    /**
    * @returns {BlockId}
    */
    id() {
        var ret = wasm.block_id(this.ptr);
        return BlockId.__wrap(ret);
    }
    /**
    * @returns {BlockId}
    */
    parent_id() {
        var ret = wasm.block_parent_id(this.ptr);
        return BlockId.__wrap(ret);
    }
    /**
    *This involves copying all the fragments
    * @returns {Fragments}
    */
    fragments() {
        var ret = wasm.block_fragments(this.ptr);
        return Fragments.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    epoch() {
        var ret = wasm.block_epoch(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {number}
    */
    slot() {
        var ret = wasm.block_slot(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {number}
    */
    chain_length() {
        var ret = wasm.block_chain_length(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {PoolId | undefined}
    */
    leader_id() {
        var ret = wasm.block_leader_id(this.ptr);
        return ret === 0 ? undefined : PoolId.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    content_size() {
        var ret = wasm.block_content_size(this.ptr);
        return ret >>> 0;
    }
}
/**
*/
export class BlockId {

    static __wrap(ptr) {
        const obj = Object.create(BlockId.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_blockid_free(ptr);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {Hash}
    */
    static calculate(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.blockid_calculate(ptr0, len0);
        return Hash.__wrap(ret);
    }
    /**
    * @param {any} bytes
    * @returns {BlockId}
    */
    static from_bytes(bytes) {
        var ret = wasm.blockid_from_bytes(addHeapObject(bytes));
        return BlockId.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.blockid_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
}
/**
*/
export class Certificate {

    static __wrap(ptr) {
        const obj = Object.create(Certificate.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_certificate_free(ptr);
    }
    /**
    * Create a Certificate for StakeDelegation
    * @param {StakeDelegation} stake_delegation
    * @returns {Certificate}
    */
    static stake_delegation(stake_delegation) {
        _assertClass(stake_delegation, StakeDelegation);
        var ret = wasm.certificate_stake_delegation(stake_delegation.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * Create a Certificate for OwnerStakeDelegation
    * @param {OwnerStakeDelegation} owner_stake
    * @returns {Certificate}
    */
    static owner_stake_delegation(owner_stake) {
        _assertClass(owner_stake, OwnerStakeDelegation);
        var ret = wasm.certificate_owner_stake_delegation(owner_stake.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * Create a Certificate for PoolRegistration
    * @param {PoolRegistration} pool_registration
    * @returns {Certificate}
    */
    static stake_pool_registration(pool_registration) {
        _assertClass(pool_registration, PoolRegistration);
        var ret = wasm.certificate_stake_pool_registration(pool_registration.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * Create a Certificate for PoolRetirement
    * @param {PoolRetirement} pool_retirement
    * @returns {Certificate}
    */
    static stake_pool_retirement(pool_retirement) {
        _assertClass(pool_retirement, PoolRetirement);
        var ret = wasm.certificate_stake_pool_retirement(pool_retirement.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * Create a Certificate for PoolUpdate
    * @param {PoolUpdate} pool_update
    * @returns {Certificate}
    */
    static stake_pool_update(pool_update) {
        _assertClass(pool_update, PoolUpdate);
        var ret = wasm.certificate_stake_pool_update(pool_update.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    get_type() {
        var ret = wasm.certificate_get_type(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {StakeDelegation}
    */
    get_stake_delegation() {
        var ret = wasm.certificate_get_stake_delegation(this.ptr);
        return StakeDelegation.__wrap(ret);
    }
    /**
    * @returns {OwnerStakeDelegation}
    */
    get_owner_stake_delegation() {
        var ret = wasm.certificate_get_owner_stake_delegation(this.ptr);
        return OwnerStakeDelegation.__wrap(ret);
    }
    /**
    * @returns {PoolRegistration}
    */
    get_pool_registration() {
        var ret = wasm.certificate_get_pool_registration(this.ptr);
        return PoolRegistration.__wrap(ret);
    }
    /**
    * @returns {PoolRetirement}
    */
    get_pool_retirement() {
        var ret = wasm.certificate_get_pool_retirement(this.ptr);
        return PoolRetirement.__wrap(ret);
    }
    /**
    * @returns {PoolUpdate}
    */
    get_pool_update() {
        var ret = wasm.certificate_get_pool_update(this.ptr);
        return PoolUpdate.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.certificate_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
}
/**
* Delegation Ratio type express a number of parts
* and a list of pools and their individual parts
*
* E.g. parts: 7, pools: [(A,2), (B,1), (C,4)] means that
* A is associated with 2/7 of the stake, B has 1/7 of stake and C
* has 4/7 of the stake.
*
* It\'s invalid to have less than 2 elements in the array,
* and by extension parts need to be equal to the sum of individual
* pools parts.
*/
export class DelegationRatio {

    static __wrap(ptr) {
        const obj = Object.create(DelegationRatio.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_delegationratio_free(ptr);
    }
    /**
    * @param {number} parts
    * @param {PoolDelegationRatios} pools
    * @returns {DelegationRatio | undefined}
    */
    static new(parts, pools) {
        _assertClass(pools, PoolDelegationRatios);
        var ret = wasm.delegationratio_new(parts, pools.ptr);
        return ret === 0 ? undefined : DelegationRatio.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    parts() {
        var ret = wasm.delegationratio_parts(this.ptr);
        return ret;
    }
    /**
    * @returns {PoolDelegationRatios}
    */
    pools() {
        var ret = wasm.delegationratio_pools(this.ptr);
        return PoolDelegationRatios.__wrap(ret);
    }
}
/**
* Set the choice of delegation:
*
* * No delegation
* * Full delegation of this account to a specific pool
* * Ratio of stake to multiple pools
*/
export class DelegationType {

    static __wrap(ptr) {
        const obj = Object.create(DelegationType.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_delegationtype_free(ptr);
    }
    /**
    * @returns {DelegationType}
    */
    static non_delegated() {
        var ret = wasm.delegationtype_non_delegated();
        return DelegationType.__wrap(ret);
    }
    /**
    * @param {PoolId} pool_id
    * @returns {DelegationType}
    */
    static full(pool_id) {
        _assertClass(pool_id, PoolId);
        var ret = wasm.delegationtype_full(pool_id.ptr);
        return DelegationType.__wrap(ret);
    }
    /**
    * @param {DelegationRatio} r
    * @returns {DelegationType}
    */
    static ratio(r) {
        _assertClass(r, DelegationRatio);
        var ret = wasm.delegationtype_ratio(r.ptr);
        return DelegationType.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    get_kind() {
        var ret = wasm.delegationtype_get_kind(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {PoolId | undefined}
    */
    get_full() {
        var ret = wasm.delegationtype_get_full(this.ptr);
        return ret === 0 ? undefined : PoolId.__wrap(ret);
    }
    /**
    * @returns {DelegationRatio | undefined}
    */
    get_ratios() {
        var ret = wasm.delegationtype_get_ratios(this.ptr);
        return ret === 0 ? undefined : DelegationRatio.__wrap(ret);
    }
}
/**
*/
export class Ed25519Signature {

    static __wrap(ptr) {
        const obj = Object.create(Ed25519Signature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_ed25519signature_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.ed25519signature_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.ed25519signature_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.ed25519signature_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {Ed25519Signature}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.ed25519signature_from_bytes(ptr0, len0);
        return Ed25519Signature.__wrap(ret);
    }
    /**
    * @param {string} bech32_str
    * @returns {Ed25519Signature}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.ed25519signature_from_bech32(ptr0, len0);
        return Ed25519Signature.__wrap(ret);
    }
    /**
    * @param {string} input
    * @returns {Ed25519Signature}
    */
    static from_hex(input) {
        var ptr0 = passStringToWasm0(input, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.ed25519signature_from_hex(ptr0, len0);
        return Ed25519Signature.__wrap(ret);
    }
}
/**
* Algorithm used to compute transaction fees
* Currently the only implementation is the Linear one
*/
export class Fee {

    static __wrap(ptr) {
        const obj = Object.create(Fee.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_fee_free(ptr);
    }
    /**
    * Linear algorithm, this is formed by: `coefficient * (#inputs + #outputs) + constant + certificate * #certificate
    * @param {Value} constant
    * @param {Value} coefficient
    * @param {Value} certificate
    * @param {PerCertificateFee} per_certificate_fee
    * @returns {Fee}
    */
    static linear_fee(constant, coefficient, certificate, per_certificate_fee) {
        _assertClass(constant, Value);
        _assertClass(coefficient, Value);
        _assertClass(certificate, Value);
        _assertClass(per_certificate_fee, PerCertificateFee);
        var ret = wasm.fee_linear_fee(constant.ptr, coefficient.ptr, certificate.ptr, per_certificate_fee.ptr);
        return Fee.__wrap(ret);
    }
    /**
    * @param {Transaction} tx
    * @returns {Value}
    */
    calculate(tx) {
        _assertClass(tx, Transaction);
        var ret = wasm.fee_calculate(this.ptr, tx.ptr);
        return Value.__wrap(ret);
    }
}
/**
* All possible messages recordable in the Block content
*/
export class Fragment {

    static __wrap(ptr) {
        const obj = Object.create(Fragment.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_fragment_free(ptr);
    }
    /**
    * @param {Transaction} tx
    * @returns {Fragment}
    */
    static from_transaction(tx) {
        _assertClass(tx, Transaction);
        var ret = wasm.fragment_from_transaction(tx.ptr);
        return Fragment.__wrap(ret);
    }
    /**
    * Get a Transaction if the Fragment represents one
    * @returns {Transaction}
    */
    get_transaction() {
        var ret = wasm.fragment_get_transaction(this.ptr);
        return Transaction.__wrap(ret);
    }
    /**
    * @returns {OldUtxoDeclaration}
    */
    get_old_utxo_declaration() {
        var ret = wasm.fragment_get_old_utxo_declaration(this.ptr);
        return OldUtxoDeclaration.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.fragment_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {any} bytes
    * @returns {Fragment}
    */
    static from_bytes(bytes) {
        var ret = wasm.fragment_from_bytes(addHeapObject(bytes));
        return Fragment.__wrap(ret);
    }
    /**
    * @returns {boolean}
    */
    is_initial() {
        var ret = wasm.fragment_is_initial(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_transaction() {
        var ret = wasm.fragment_is_transaction(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_owner_stake_delegation() {
        var ret = wasm.fragment_is_owner_stake_delegation(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_stake_delegation() {
        var ret = wasm.fragment_is_stake_delegation(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_pool_registration() {
        var ret = wasm.fragment_is_pool_registration(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_pool_retirement() {
        var ret = wasm.fragment_is_pool_retirement(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_pool_update() {
        var ret = wasm.fragment_is_pool_update(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_old_utxo_declaration() {
        var ret = wasm.fragment_is_old_utxo_declaration(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_update_proposal() {
        var ret = wasm.fragment_is_update_proposal(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_update_vote() {
        var ret = wasm.fragment_is_update_vote(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {FragmentId}
    */
    id() {
        var ret = wasm.fragment_id(this.ptr);
        return FragmentId.__wrap(ret);
    }
}
/**
*/
export class FragmentId {

    static __wrap(ptr) {
        const obj = Object.create(FragmentId.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_fragmentid_free(ptr);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {FragmentId}
    */
    static calculate(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.fragmentid_calculate(ptr0, len0);
        return FragmentId.__wrap(ret);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {FragmentId}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.fragmentid_from_bytes(ptr0, len0);
        return FragmentId.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.fragmentid_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
}
/**
*/
export class Fragments {

    static __wrap(ptr) {
        const obj = Object.create(Fragments.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_fragments_free(ptr);
    }
    /**
    * @returns {Fragments}
    */
    static new() {
        var ret = wasm.fragments_new();
        return Fragments.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    size() {
        var ret = wasm.fragments_size(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {Fragment}
    */
    get(index) {
        var ret = wasm.fragments_get(this.ptr, index);
        return Fragment.__wrap(ret);
    }
    /**
    * @param {Fragment} item
    */
    add(item) {
        _assertClass(item, Fragment);
        var ptr0 = item.ptr;
        item.ptr = 0;
        wasm.fragments_add(this.ptr, ptr0);
    }
}
/**
*/
export class GenesisPraosLeader {

    static __wrap(ptr) {
        const obj = Object.create(GenesisPraosLeader.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_genesispraosleader_free(ptr);
    }
    /**
    * @param {KesPublicKey} kes_public_key
    * @param {VrfPublicKey} vrf_public_key
    * @returns {GenesisPraosLeader}
    */
    static new(kes_public_key, vrf_public_key) {
        _assertClass(kes_public_key, KesPublicKey);
        _assertClass(vrf_public_key, VrfPublicKey);
        var ret = wasm.genesispraosleader_new(kes_public_key.ptr, vrf_public_key.ptr);
        return GenesisPraosLeader.__wrap(ret);
    }
    /**
    * @returns {KesPublicKey}
    */
    kes_pubkey() {
        var ret = wasm.genesispraosleader_kes_pubkey(this.ptr);
        return KesPublicKey.__wrap(ret);
    }
    /**
    * @returns {VrfPublicKey}
    */
    vrf_pubkey() {
        var ret = wasm.genesispraosleader_vrf_pubkey(this.ptr);
        return VrfPublicKey.__wrap(ret);
    }
}
/**
*/
export class GenesisPraosLeaderHash {

    static __wrap(ptr) {
        const obj = Object.create(GenesisPraosLeaderHash.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_genesispraosleaderhash_free(ptr);
    }
    /**
    * @param {string} hex_string
    * @returns {GenesisPraosLeaderHash}
    */
    static from_hex(hex_string) {
        var ptr0 = passStringToWasm0(hex_string, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.genesispraosleaderhash_from_hex(ptr0, len0);
        return GenesisPraosLeaderHash.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_string() {
        try {
            wasm.genesispraosleaderhash_to_string(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
*/
export class GroupAddress {

    static __wrap(ptr) {
        const obj = Object.create(GroupAddress.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_groupaddress_free(ptr);
    }
    /**
    * @returns {PublicKey}
    */
    get_spending_key() {
        var ret = wasm.groupaddress_get_spending_key(this.ptr);
        return PublicKey.__wrap(ret);
    }
    /**
    * @returns {PublicKey}
    */
    get_account_key() {
        var ret = wasm.groupaddress_get_account_key(this.ptr);
        return PublicKey.__wrap(ret);
    }
    /**
    * @returns {Address}
    */
    to_base_address() {
        var ret = wasm.groupaddress_to_base_address(this.ptr);
        return Address.__wrap(ret);
    }
}
/**
* Type for representing a generic Hash
*/
export class Hash {

    static __wrap(ptr) {
        const obj = Object.create(Hash.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_hash_free(ptr);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {Hash}
    */
    static calculate(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.hash_calculate(ptr0, len0);
        return Hash.__wrap(ret);
    }
    /**
    * @param {string} hex_string
    * @returns {Hash}
    */
    static from_hex(hex_string) {
        var ptr0 = passStringToWasm0(hex_string, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.hash_from_hex(ptr0, len0);
        return Hash.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.hash_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
}
/**
*/
export class IndexSignatures {

    static __wrap(ptr) {
        const obj = Object.create(IndexSignatures.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_indexsignatures_free(ptr);
    }
    /**
    * @returns {IndexSignatures}
    */
    static new() {
        var ret = wasm.indexsignatures_new();
        return IndexSignatures.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    size() {
        var ret = wasm.indexsignatures_size(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {IndexedSignature}
    */
    get(index) {
        var ret = wasm.indexsignatures_get(this.ptr, index);
        return IndexedSignature.__wrap(ret);
    }
    /**
    * @param {IndexedSignature} item
    */
    add(item) {
        _assertClass(item, IndexedSignature);
        var ptr0 = item.ptr;
        item.ptr = 0;
        wasm.indexsignatures_add(this.ptr, ptr0);
    }
}
/**
*/
export class IndexedSignature {

    static __wrap(ptr) {
        const obj = Object.create(IndexedSignature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_indexedsignature_free(ptr);
    }
    /**
    * @param {number} index
    * @param {AccountBindingSignature} signature
    * @returns {IndexedSignature}
    */
    static new(index, signature) {
        _assertClass(signature, AccountBindingSignature);
        var ret = wasm.indexedsignature_new(index, signature.ptr);
        return IndexedSignature.__wrap(ret);
    }
}
/**
*/
export class Input {

    static __wrap(ptr) {
        const obj = Object.create(Input.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_input_free(ptr);
    }
    /**
    * @param {UtxoPointer} utxo_pointer
    * @returns {Input}
    */
    static from_utxo(utxo_pointer) {
        _assertClass(utxo_pointer, UtxoPointer);
        var ret = wasm.input_from_utxo(utxo_pointer.ptr);
        return Input.__wrap(ret);
    }
    /**
    * @param {Account} account
    * @param {Value} v
    * @returns {Input}
    */
    static from_account(account, v) {
        _assertClass(account, Account);
        _assertClass(v, Value);
        var ret = wasm.input_from_account(account.ptr, v.ptr);
        return Input.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    get_type() {
        var ret = wasm.input_get_type(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {boolean}
    */
    is_account() {
        var ret = wasm.input_is_account(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_utxo() {
        var ret = wasm.input_is_utxo(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {Value}
    */
    value() {
        var ret = wasm.input_value(this.ptr);
        return Value.__wrap(ret);
    }
    /**
    * Get the inner UtxoPointer if the Input type is Utxo
    * @returns {UtxoPointer}
    */
    get_utxo_pointer() {
        var ret = wasm.input_get_utxo_pointer(this.ptr);
        return UtxoPointer.__wrap(ret);
    }
    /**
    * Get the source Account if the Input type is Account
    * @returns {AccountIdentifier}
    */
    get_account_identifier() {
        var ret = wasm.input_get_account_identifier(this.ptr);
        return AccountIdentifier.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.input_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {any} bytes
    * @returns {Input}
    */
    static from_bytes(bytes) {
        var ret = wasm.input_from_bytes(addHeapObject(bytes));
        return Input.__wrap(ret);
    }
}
/**
*/
export class InputOutput {

    static __wrap(ptr) {
        const obj = Object.create(InputOutput.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_inputoutput_free(ptr);
    }
    /**
    * @returns {Inputs}
    */
    inputs() {
        var ret = wasm.inputoutput_inputs(this.ptr);
        return Inputs.__wrap(ret);
    }
    /**
    * @returns {Outputs}
    */
    outputs() {
        var ret = wasm.inputoutput_outputs(this.ptr);
        return Outputs.__wrap(ret);
    }
}
/**
*/
export class InputOutputBuilder {

    static __wrap(ptr) {
        const obj = Object.create(InputOutputBuilder.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_inputoutputbuilder_free(ptr);
    }
    /**
    * @returns {InputOutputBuilder}
    */
    static empty() {
        var ret = wasm.inputoutputbuilder_empty();
        return InputOutputBuilder.__wrap(ret);
    }
    /**
    * Add input to the IO Builder
    * @param {Input} input
    */
    add_input(input) {
        _assertClass(input, Input);
        wasm.inputoutputbuilder_add_input(this.ptr, input.ptr);
    }
    /**
    * Add output to the IO Builder
    * @param {Address} address
    * @param {Value} value
    */
    add_output(address, value) {
        _assertClass(address, Address);
        _assertClass(value, Value);
        wasm.inputoutputbuilder_add_output(this.ptr, address.ptr, value.ptr);
    }
    /**
    * Estimate fee with the currently added inputs, outputs and certificate based on the given algorithm
    * @param {Fee} fee
    * @param {Payload} payload
    * @returns {Value}
    */
    estimate_fee(fee, payload) {
        _assertClass(fee, Fee);
        _assertClass(payload, Payload);
        var ret = wasm.inputoutputbuilder_estimate_fee(this.ptr, fee.ptr, payload.ptr);
        return Value.__wrap(ret);
    }
    /**
    * @param {Payload} payload
    * @param {Fee} fee
    * @returns {Balance}
    */
    get_balance(payload, fee) {
        _assertClass(payload, Payload);
        _assertClass(fee, Fee);
        var ret = wasm.inputoutputbuilder_get_balance(this.ptr, payload.ptr, fee.ptr);
        return Balance.__wrap(ret);
    }
    /**
    * @returns {Balance}
    */
    get_balance_without_fee() {
        var ret = wasm.inputoutputbuilder_get_balance_without_fee(this.ptr);
        return Balance.__wrap(ret);
    }
    /**
    * @returns {InputOutput}
    */
    build() {
        var ptr = this.ptr;
        this.ptr = 0;
        var ret = wasm.inputoutputbuilder_build(ptr);
        return InputOutput.__wrap(ret);
    }
    /**
    * Seal the transaction by passing fee rule
    * @param {Payload} payload
    * @param {Fee} fee_algorithm
    * @returns {InputOutput}
    */
    seal(payload, fee_algorithm) {
        var ptr = this.ptr;
        this.ptr = 0;
        _assertClass(payload, Payload);
        _assertClass(fee_algorithm, Fee);
        var ret = wasm.inputoutputbuilder_seal(ptr, payload.ptr, fee_algorithm.ptr);
        return InputOutput.__wrap(ret);
    }
    /**
    * Seal the transaction by passing fee rule and the output policy
    * @param {Payload} payload
    * @param {Fee} fee_algorithm
    * @param {OutputPolicy} policy
    * @returns {InputOutput}
    */
    seal_with_output_policy(payload, fee_algorithm, policy) {
        var ptr = this.ptr;
        this.ptr = 0;
        _assertClass(payload, Payload);
        _assertClass(fee_algorithm, Fee);
        _assertClass(policy, OutputPolicy);
        var ret = wasm.inputoutputbuilder_seal_with_output_policy(ptr, payload.ptr, fee_algorithm.ptr, policy.ptr);
        return InputOutput.__wrap(ret);
    }
}
/**
*/
export class Inputs {

    static __wrap(ptr) {
        const obj = Object.create(Inputs.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_inputs_free(ptr);
    }
    /**
    * @returns {Inputs}
    */
    static new() {
        var ret = wasm.inputs_new();
        return Inputs.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    size() {
        var ret = wasm.inputs_size(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {Input}
    */
    get(index) {
        var ret = wasm.inputs_get(this.ptr, index);
        return Input.__wrap(ret);
    }
    /**
    * @param {Input} item
    */
    add(item) {
        _assertClass(item, Input);
        var ptr0 = item.ptr;
        item.ptr = 0;
        wasm.inputs_add(this.ptr, ptr0);
    }
}
/**
*/
export class KesPublicKey {

    static __wrap(ptr) {
        const obj = Object.create(KesPublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_kespublickey_free(ptr);
    }
    /**
    * @param {string} bech32_str
    * @returns {KesPublicKey}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.kespublickey_from_bech32(ptr0, len0);
        return KesPublicKey.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.kespublickey_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
*/
export class LegacyDaedalusPrivateKey {

    static __wrap(ptr) {
        const obj = Object.create(LegacyDaedalusPrivateKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_legacydaedalusprivatekey_free(ptr);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {LegacyDaedalusPrivateKey}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.legacydaedalusprivatekey_from_bytes(ptr0, len0);
        return LegacyDaedalusPrivateKey.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.legacydaedalusprivatekey_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
}
/**
*/
export class LegacyUtxoWitness {

    static __wrap(ptr) {
        const obj = Object.create(LegacyUtxoWitness.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_legacyutxowitness_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.legacyutxowitness_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.legacyutxowitness_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.legacyutxowitness_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {LegacyUtxoWitness}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.legacyutxowitness_from_bytes(ptr0, len0);
        return LegacyUtxoWitness.__wrap(ret);
    }
    /**
    * @param {string} bech32_str
    * @returns {LegacyUtxoWitness}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.legacyutxowitness_from_bech32(ptr0, len0);
        return LegacyUtxoWitness.__wrap(ret);
    }
    /**
    * @param {string} input
    * @returns {LegacyUtxoWitness}
    */
    static from_hex(input) {
        var ptr0 = passStringToWasm0(input, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.legacyutxowitness_from_hex(ptr0, len0);
        return LegacyUtxoWitness.__wrap(ret);
    }
}
/**
*/
export class MultisigAddress {

    static __wrap(ptr) {
        const obj = Object.create(MultisigAddress.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_multisigaddress_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    get_merkle_root() {
        wasm.multisigaddress_get_merkle_root(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @returns {Address}
    */
    to_base_address() {
        var ret = wasm.multisigaddress_to_base_address(this.ptr);
        return Address.__wrap(ret);
    }
}
/**
*/
export class OldUtxoDeclaration {

    static __wrap(ptr) {
        const obj = Object.create(OldUtxoDeclaration.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_oldutxodeclaration_free(ptr);
    }
    /**
    * @returns {number}
    */
    size() {
        var ret = wasm.oldutxodeclaration_size(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {string}
    */
    get_address(index) {
        try {
            wasm.oldutxodeclaration_get_address(8, this.ptr, index);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {number} index
    * @returns {Value}
    */
    get_value(index) {
        var ret = wasm.oldutxodeclaration_get_value(this.ptr, index);
        return Value.__wrap(ret);
    }
}
/**
* Type for representing a Transaction Output, composed of an Address and a Value
*/
export class Output {

    static __wrap(ptr) {
        const obj = Object.create(Output.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_output_free(ptr);
    }
    /**
    * @returns {Address}
    */
    address() {
        var ret = wasm.output_address(this.ptr);
        return Address.__wrap(ret);
    }
    /**
    * @returns {Value}
    */
    value() {
        var ret = wasm.output_value(this.ptr);
        return Value.__wrap(ret);
    }
}
/**
* Helper to add change addresses when finalizing a transaction, there are currently two options
* * forget: use all the excess money as fee
* * one: send all the excess money to the given address
*/
export class OutputPolicy {

    static __wrap(ptr) {
        const obj = Object.create(OutputPolicy.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_outputpolicy_free(ptr);
    }
    /**
    * don\'t do anything with the excess money in transaction
    * @returns {OutputPolicy}
    */
    static forget() {
        var ret = wasm.outputpolicy_forget();
        return OutputPolicy.__wrap(ret);
    }
    /**
    * use the given address as the only change address
    * @param {Address} address
    * @returns {OutputPolicy}
    */
    static one(address) {
        _assertClass(address, Address);
        var ret = wasm.outputpolicy_one(address.ptr);
        return OutputPolicy.__wrap(ret);
    }
}
/**
*/
export class Outputs {

    static __wrap(ptr) {
        const obj = Object.create(Outputs.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_outputs_free(ptr);
    }
    /**
    * @returns {Outputs}
    */
    static new() {
        var ret = wasm.outputs_new();
        return Outputs.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    size() {
        var ret = wasm.outputs_size(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {Output}
    */
    get(index) {
        var ret = wasm.outputs_get(this.ptr, index);
        return Output.__wrap(ret);
    }
    /**
    * @param {Output} item
    */
    add(item) {
        _assertClass(item, Output);
        var ptr0 = item.ptr;
        item.ptr = 0;
        wasm.outputs_add(this.ptr, ptr0);
    }
}
/**
*/
export class OwnerStakeDelegation {

    static __wrap(ptr) {
        const obj = Object.create(OwnerStakeDelegation.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_ownerstakedelegation_free(ptr);
    }
    /**
    * @param {DelegationType} delegation_type
    * @returns {OwnerStakeDelegation}
    */
    static new(delegation_type) {
        _assertClass(delegation_type, DelegationType);
        var ret = wasm.ownerstakedelegation_new(delegation_type.ptr);
        return OwnerStakeDelegation.__wrap(ret);
    }
    /**
    * @returns {DelegationType}
    */
    delegation_type() {
        var ret = wasm.ownerstakedelegation_delegation_type(this.ptr);
        return DelegationType.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.ownerstakedelegation_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {OwnerStakeDelegation}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.ownerstakedelegation_from_bytes(ptr0, len0);
        return OwnerStakeDelegation.__wrap(ret);
    }
}
/**
*/
export class Payload {

    static __wrap(ptr) {
        const obj = Object.create(Payload.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_payload_free(ptr);
    }
    /**
    * @returns {Payload}
    */
    static no_payload() {
        var ret = wasm.payload_no_payload();
        return Payload.__wrap(ret);
    }
    /**
    * @param {Certificate} certificate
    * @returns {Payload}
    */
    static certificate(certificate) {
        _assertClass(certificate, Certificate);
        var ret = wasm.payload_certificate(certificate.ptr);
        return Payload.__wrap(ret);
    }
}
/**
*/
export class PayloadAuthData {

    static __wrap(ptr) {
        const obj = Object.create(PayloadAuthData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_payloadauthdata_free(ptr);
    }
    /**
    * @returns {PayloadAuthData}
    */
    static for_no_payload() {
        var ret = wasm.payloadauthdata_for_no_payload();
        return PayloadAuthData.__wrap(ret);
    }
    /**
    * @returns {PayloadAuthData}
    */
    static for_owner_stake_delegation() {
        var ret = wasm.payloadauthdata_for_owner_stake_delegation();
        return PayloadAuthData.__wrap(ret);
    }
    /**
    * @param {StakeDelegationAuthData} auth_data
    * @returns {PayloadAuthData}
    */
    static for_stake_delegation(auth_data) {
        _assertClass(auth_data, StakeDelegationAuthData);
        var ret = wasm.payloadauthdata_for_stake_delegation(auth_data.ptr);
        return PayloadAuthData.__wrap(ret);
    }
    /**
    * @param {PoolRegistrationAuthData} auth_data
    * @returns {PayloadAuthData}
    */
    static for_pool_registration(auth_data) {
        _assertClass(auth_data, PoolRegistrationAuthData);
        var ret = wasm.payloadauthdata_for_pool_registration(auth_data.ptr);
        return PayloadAuthData.__wrap(ret);
    }
    /**
    * @param {PoolRetirementAuthData} auth_data
    * @returns {PayloadAuthData}
    */
    static for_pool_retirement(auth_data) {
        _assertClass(auth_data, PoolRetirementAuthData);
        var ret = wasm.payloadauthdata_for_pool_retirement(auth_data.ptr);
        return PayloadAuthData.__wrap(ret);
    }
    /**
    * @param {PoolUpdateAuthData} auth_data
    * @returns {PayloadAuthData}
    */
    static for_pool_update(auth_data) {
        _assertClass(auth_data, PoolUpdateAuthData);
        var ret = wasm.payloadauthdata_for_pool_update(auth_data.ptr);
        return PayloadAuthData.__wrap(ret);
    }
}
/**
*/
export class PerCertificateFee {

    static __wrap(ptr) {
        const obj = Object.create(PerCertificateFee.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_percertificatefee_free(ptr);
    }
    /**
    * @returns {PerCertificateFee}
    */
    static new() {
        var ret = wasm.percertificatefee_new();
        return PerCertificateFee.__wrap(ret);
    }
    /**
    * @param {Value} val
    */
    set_pool_registration(val) {
        _assertClass(val, Value);
        wasm.percertificatefee_set_pool_registration(this.ptr, val.ptr);
    }
    /**
    * @param {Value} val
    */
    set_stake_delegation(val) {
        _assertClass(val, Value);
        wasm.percertificatefee_set_stake_delegation(this.ptr, val.ptr);
    }
    /**
    * @param {Value} val
    */
    set_owner_stake_delegation(val) {
        _assertClass(val, Value);
        wasm.percertificatefee_set_owner_stake_delegation(this.ptr, val.ptr);
    }
}
/**
*/
export class PoolDelegationRatio {

    static __wrap(ptr) {
        const obj = Object.create(PoolDelegationRatio.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_pooldelegationratio_free(ptr);
    }
    /**
    * @param {PoolId} pool
    * @param {number} part
    * @returns {PoolDelegationRatio}
    */
    static new(pool, part) {
        _assertClass(pool, PoolId);
        var ret = wasm.pooldelegationratio_new(pool.ptr, part);
        return PoolDelegationRatio.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    parts() {
        var ret = wasm.pooldelegationratio_parts(this.ptr);
        return ret;
    }
    /**
    * @returns {PoolId}
    */
    pool() {
        var ret = wasm.pooldelegationratio_pool(this.ptr);
        return PoolId.__wrap(ret);
    }
}
/**
*/
export class PoolDelegationRatios {

    static __wrap(ptr) {
        const obj = Object.create(PoolDelegationRatios.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_pooldelegationratios_free(ptr);
    }
    /**
    * @returns {PoolDelegationRatios}
    */
    static new() {
        var ret = wasm.pooldelegationratios_new();
        return PoolDelegationRatios.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    size() {
        var ret = wasm.pooldelegationratios_size(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {PoolDelegationRatio}
    */
    get(index) {
        var ret = wasm.pooldelegationratios_get(this.ptr, index);
        return PoolDelegationRatio.__wrap(ret);
    }
    /**
    * @param {PoolDelegationRatio} item
    */
    add(item) {
        _assertClass(item, PoolDelegationRatio);
        var ptr0 = item.ptr;
        item.ptr = 0;
        wasm.pooldelegationratios_add(this.ptr, ptr0);
    }
}
/**
*/
export class PoolId {

    static __wrap(ptr) {
        const obj = Object.create(PoolId.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_poolid_free(ptr);
    }
    /**
    * @param {string} hex_string
    * @returns {PoolId}
    */
    static from_hex(hex_string) {
        var ptr0 = passStringToWasm0(hex_string, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.poolid_from_hex(ptr0, len0);
        return PoolId.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_string() {
        try {
            wasm.poolid_to_string(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
*/
export class PoolRegistration {

    static __wrap(ptr) {
        const obj = Object.create(PoolRegistration.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_poolregistration_free(ptr);
    }
    /**
    * @param {U128} serial
    * @param {PublicKeys} owners
    * @param {PublicKeys} operators
    * @param {number} management_threshold
    * @param {TimeOffsetSeconds} start_validity
    * @param {GenesisPraosLeader} leader_keys
    */
    constructor(serial, owners, operators, management_threshold, start_validity, leader_keys) {
        _assertClass(serial, U128);
        _assertClass(owners, PublicKeys);
        _assertClass(operators, PublicKeys);
        _assertClass(start_validity, TimeOffsetSeconds);
        _assertClass(leader_keys, GenesisPraosLeader);
        var ret = wasm.poolregistration_new(serial.ptr, owners.ptr, operators.ptr, management_threshold, start_validity.ptr, leader_keys.ptr);
        return PoolRegistration.__wrap(ret);
    }
    /**
    * @returns {PoolId}
    */
    id() {
        var ret = wasm.poolregistration_id(this.ptr);
        return PoolId.__wrap(ret);
    }
    /**
    * @returns {TimeOffsetSeconds}
    */
    start_validity() {
        var ret = wasm.poolregistration_start_validity(this.ptr);
        return TimeOffsetSeconds.__wrap(ret);
    }
    /**
    * @returns {PublicKeys}
    */
    owners() {
        var ret = wasm.poolregistration_owners(this.ptr);
        return PublicKeys.__wrap(ret);
    }
    /**
    * @returns {PublicKeys}
    */
    operators() {
        var ret = wasm.poolregistration_operators(this.ptr);
        return PublicKeys.__wrap(ret);
    }
    /**
    * @returns {TaxType}
    */
    rewards() {
        var ret = wasm.poolregistration_rewards(this.ptr);
        return TaxType.__wrap(ret);
    }
    /**
    * @returns {Account | undefined}
    */
    reward_account() {
        var ret = wasm.poolregistration_reward_account(this.ptr);
        return ret === 0 ? undefined : Account.__wrap(ret);
    }
    /**
    * @returns {GenesisPraosLeader}
    */
    keys() {
        var ret = wasm.poolregistration_keys(this.ptr);
        return GenesisPraosLeader.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.poolregistration_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {PoolRegistration}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.poolregistration_from_bytes(ptr0, len0);
        return PoolRegistration.__wrap(ret);
    }
}
/**
*/
export class PoolRegistrationAuthData {

    static __wrap(ptr) {
        const obj = Object.create(PoolRegistrationAuthData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_poolregistrationauthdata_free(ptr);
    }
    /**
    * @param {IndexSignatures} signatures
    * @returns {PoolRegistrationAuthData}
    */
    static new(signatures) {
        _assertClass(signatures, IndexSignatures);
        var ret = wasm.poolregistrationauthdata_new(signatures.ptr);
        return PoolRegistrationAuthData.__wrap(ret);
    }
}
/**
*/
export class PoolRetirement {

    static __wrap(ptr) {
        const obj = Object.create(PoolRetirement.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_poolretirement_free(ptr);
    }
    /**
    * @param {PoolId} pool_id
    * @param {TimeOffsetSeconds} retirement_time_offset
    * @returns {PoolRetirement}
    */
    static new(pool_id, retirement_time_offset) {
        _assertClass(pool_id, PoolId);
        _assertClass(retirement_time_offset, TimeOffsetSeconds);
        var ret = wasm.poolretirement_new(pool_id.ptr, retirement_time_offset.ptr);
        return PoolRetirement.__wrap(ret);
    }
    /**
    * @returns {PoolId}
    */
    pool_id() {
        var ret = wasm.poolretirement_pool_id(this.ptr);
        return PoolId.__wrap(ret);
    }
    /**
    * @returns {TimeOffsetSeconds}
    */
    retirement_time() {
        var ret = wasm.poolretirement_retirement_time(this.ptr);
        return TimeOffsetSeconds.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.poolretirement_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {PoolRetirement}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.poolretirement_from_bytes(ptr0, len0);
        return PoolRetirement.__wrap(ret);
    }
}
/**
*/
export class PoolRetirementAuthData {

    static __wrap(ptr) {
        const obj = Object.create(PoolRetirementAuthData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_poolretirementauthdata_free(ptr);
    }
    /**
    * @param {IndexSignatures} signatures
    * @returns {PoolRetirementAuthData}
    */
    static new(signatures) {
        _assertClass(signatures, IndexSignatures);
        var ret = wasm.poolretirementauthdata_new(signatures.ptr);
        return PoolRetirementAuthData.__wrap(ret);
    }
}
/**
*/
export class PoolUpdate {

    static __wrap(ptr) {
        const obj = Object.create(PoolUpdate.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_poolupdate_free(ptr);
    }
    /**
    * @param {PoolId} pool_id
    * @param {TimeOffsetSeconds} start_validity
    * @param {GenesisPraosLeaderHash} previous_keys
    * @param {GenesisPraosLeader} updated_keys
    * @returns {PoolUpdate}
    */
    static new(pool_id, start_validity, previous_keys, updated_keys) {
        _assertClass(pool_id, PoolId);
        _assertClass(start_validity, TimeOffsetSeconds);
        _assertClass(previous_keys, GenesisPraosLeaderHash);
        _assertClass(updated_keys, GenesisPraosLeader);
        var ret = wasm.poolupdate_new(pool_id.ptr, start_validity.ptr, previous_keys.ptr, updated_keys.ptr);
        return PoolUpdate.__wrap(ret);
    }
    /**
    * @returns {PoolId}
    */
    pool_id() {
        var ret = wasm.poolupdate_pool_id(this.ptr);
        return PoolId.__wrap(ret);
    }
    /**
    * @returns {TimeOffsetSeconds}
    */
    start_validity() {
        var ret = wasm.poolupdate_start_validity(this.ptr);
        return TimeOffsetSeconds.__wrap(ret);
    }
    /**
    * @returns {GenesisPraosLeaderHash}
    */
    previous_keys() {
        var ret = wasm.poolupdate_previous_keys(this.ptr);
        return GenesisPraosLeaderHash.__wrap(ret);
    }
    /**
    * @returns {GenesisPraosLeader}
    */
    updated_keys() {
        var ret = wasm.poolupdate_updated_keys(this.ptr);
        return GenesisPraosLeader.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.poolupdate_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {PoolUpdate}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.poolupdate_from_bytes(ptr0, len0);
        return PoolUpdate.__wrap(ret);
    }
}
/**
*/
export class PoolUpdateAuthData {

    static __wrap(ptr) {
        const obj = Object.create(PoolUpdateAuthData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_poolupdateauthdata_free(ptr);
    }
    /**
    * @param {IndexSignatures} signatures
    * @returns {PoolUpdateAuthData}
    */
    static new(signatures) {
        _assertClass(signatures, IndexSignatures);
        var ret = wasm.poolupdateauthdata_new(signatures.ptr);
        return PoolUpdateAuthData.__wrap(ret);
    }
}
/**
* ED25519 signing key, either normal or extended
*/
export class PrivateKey {

    static __wrap(ptr) {
        const obj = Object.create(PrivateKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_privatekey_free(ptr);
    }
    /**
    * Get private key from its bech32 representation
    * ```javascript
    * PrivateKey.from_bech32(&#39;ed25519_sk1ahfetf02qwwg4dkq7mgp4a25lx5vh9920cr5wnxmpzz9906qvm8qwvlts0&#39;);
    * ```
    * For an extended 25519 key
    * ```javascript
    * PrivateKey.from_bech32(&#39;ed25519e_sk1gqwl4szuwwh6d0yk3nsqcc6xxc3fpvjlevgwvt60df59v8zd8f8prazt8ln3lmz096ux3xvhhvm3ca9wj2yctdh3pnw0szrma07rt5gl748fp&#39;);
    * ```
    * @param {string} bech32_str
    * @returns {PrivateKey}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privatekey_from_bech32(ptr0, len0);
        return PrivateKey.__wrap(ret);
    }
    /**
    * @returns {PublicKey}
    */
    to_public() {
        var ret = wasm.privatekey_to_public(this.ptr);
        return PublicKey.__wrap(ret);
    }
    /**
    * @returns {PrivateKey}
    */
    static generate_ed25519() {
        var ret = wasm.privatekey_generate_ed25519();
        return PrivateKey.__wrap(ret);
    }
    /**
    * @returns {PrivateKey}
    */
    static generate_ed25519extended() {
        var ret = wasm.privatekey_generate_ed25519extended();
        return PrivateKey.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.privatekey_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.privatekey_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {PrivateKey}
    */
    static from_extended_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privatekey_from_extended_bytes(ptr0, len0);
        return PrivateKey.__wrap(ret);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {PrivateKey}
    */
    static from_normal_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privatekey_from_normal_bytes(ptr0, len0);
        return PrivateKey.__wrap(ret);
    }
    /**
    * @param {Uint8Array} message
    * @returns {Ed25519Signature}
    */
    sign(message) {
        var ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.privatekey_sign(this.ptr, ptr0, len0);
        return Ed25519Signature.__wrap(ret);
    }
}
/**
* ED25519 key used as public key
*/
export class PublicKey {

    static __wrap(ptr) {
        const obj = Object.create(PublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_publickey_free(ptr);
    }
    /**
    * Get private key from its bech32 representation
    * Example:
    * ```javascript
    * const pkey = PublicKey.from_bech32(&#39;ed25519_pk1dgaagyh470y66p899txcl3r0jaeaxu6yd7z2dxyk55qcycdml8gszkxze2&#39;);
    * ```
    * @param {string} bech32_str
    * @returns {PublicKey}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.publickey_from_bech32(ptr0, len0);
        return PublicKey.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.publickey_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.publickey_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {PublicKey}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.publickey_from_bytes(ptr0, len0);
        return PublicKey.__wrap(ret);
    }
    /**
    * @param {Uint8Array} data
    * @param {Ed25519Signature} signature
    * @returns {boolean}
    */
    verify(data, signature) {
        var ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        _assertClass(signature, Ed25519Signature);
        var ret = wasm.publickey_verify(this.ptr, ptr0, len0, signature.ptr);
        return ret !== 0;
    }
}
/**
*/
export class PublicKeys {

    static __wrap(ptr) {
        const obj = Object.create(PublicKeys.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_publickeys_free(ptr);
    }
    /**
    */
    constructor() {
        var ret = wasm.publickeys_new();
        return PublicKeys.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    size() {
        var ret = wasm.publickeys_size(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {PublicKey}
    */
    get(index) {
        var ret = wasm.publickeys_get(this.ptr, index);
        return PublicKey.__wrap(ret);
    }
    /**
    * @param {PublicKey} key
    */
    add(key) {
        _assertClass(key, PublicKey);
        wasm.publickeys_add(this.ptr, key.ptr);
    }
}
/**
*/
export class SingleAddress {

    static __wrap(ptr) {
        const obj = Object.create(SingleAddress.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_singleaddress_free(ptr);
    }
    /**
    * @returns {PublicKey}
    */
    get_spending_key() {
        var ret = wasm.singleaddress_get_spending_key(this.ptr);
        return PublicKey.__wrap(ret);
    }
    /**
    * @returns {Address}
    */
    to_base_address() {
        var ret = wasm.singleaddress_to_base_address(this.ptr);
        return Address.__wrap(ret);
    }
}
/**
*/
export class SpendingCounter {

    static __wrap(ptr) {
        const obj = Object.create(SpendingCounter.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_spendingcounter_free(ptr);
    }
    /**
    * @returns {SpendingCounter}
    */
    static zero() {
        var ret = wasm.spendingcounter_zero();
        return SpendingCounter.__wrap(ret);
    }
    /**
    * @param {number} counter
    * @returns {SpendingCounter}
    */
    static from_u32(counter) {
        var ret = wasm.spendingcounter_from_u32(counter);
        return SpendingCounter.__wrap(ret);
    }
}
/**
*/
export class StakeDelegation {

    static __wrap(ptr) {
        const obj = Object.create(StakeDelegation.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_stakedelegation_free(ptr);
    }
    /**
    * Create a stake delegation object from account (stake key) to pool_id
    * @param {DelegationType} delegation_type
    * @param {PublicKey} account
    * @returns {StakeDelegation}
    */
    static new(delegation_type, account) {
        _assertClass(delegation_type, DelegationType);
        _assertClass(account, PublicKey);
        var ret = wasm.stakedelegation_new(delegation_type.ptr, account.ptr);
        return StakeDelegation.__wrap(ret);
    }
    /**
    * @returns {DelegationType}
    */
    delegation_type() {
        var ret = wasm.stakedelegation_delegation_type(this.ptr);
        return DelegationType.__wrap(ret);
    }
    /**
    * @returns {AccountIdentifier}
    */
    account() {
        var ret = wasm.stakedelegation_account(this.ptr);
        return AccountIdentifier.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.stakedelegation_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {StakeDelegation}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.stakedelegation_from_bytes(ptr0, len0);
        return StakeDelegation.__wrap(ret);
    }
}
/**
*/
export class StakeDelegationAuthData {

    static __wrap(ptr) {
        const obj = Object.create(StakeDelegationAuthData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_stakedelegationauthdata_free(ptr);
    }
    /**
    * @param {AccountBindingSignature} signature
    * @returns {StakeDelegationAuthData}
    */
    static new(signature) {
        _assertClass(signature, AccountBindingSignature);
        var ret = wasm.stakedelegationauthdata_new(signature.ptr);
        return StakeDelegationAuthData.__wrap(ret);
    }
}
/**
*/
export class TaxType {

    static __wrap(ptr) {
        const obj = Object.create(TaxType.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_taxtype_free(ptr);
    }
    /**
    * @returns {Value}
    */
    fixed() {
        var ret = wasm.taxtype_fixed(this.ptr);
        return Value.__wrap(ret);
    }
    /**
    * @returns {Value}
    */
    ratio_numerator() {
        var ret = wasm.taxtype_ratio_numerator(this.ptr);
        return Value.__wrap(ret);
    }
    /**
    * @returns {Value}
    */
    ratio_denominator() {
        var ret = wasm.taxtype_ratio_denominator(this.ptr);
        return Value.__wrap(ret);
    }
    /**
    * @returns {Value | undefined}
    */
    max_limit() {
        var ret = wasm.taxtype_max_limit(this.ptr);
        return ret === 0 ? undefined : Value.__wrap(ret);
    }
}
/**
*/
export class TimeOffsetSeconds {

    static __wrap(ptr) {
        const obj = Object.create(TimeOffsetSeconds.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_timeoffsetseconds_free(ptr);
    }
    /**
    * Parse the given string into a 64 bits unsigned number
    * @param {string} number
    * @returns {TimeOffsetSeconds}
    */
    static from_string(number) {
        var ptr0 = passStringToWasm0(number, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.timeoffsetseconds_from_string(ptr0, len0);
        return TimeOffsetSeconds.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_string() {
        try {
            wasm.timeoffsetseconds_to_string(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
*/
export class Transaction {

    static __wrap(ptr) {
        const obj = Object.create(Transaction.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transaction_free(ptr);
    }
    /**
    * Get the transaction id, needed to compute its signature
    * @returns {TransactionSignDataHash}
    */
    id() {
        var ret = wasm.transaction_id(this.ptr);
        return TransactionSignDataHash.__wrap(ret);
    }
    /**
    * Get collection of the inputs in the transaction (this allocates new copies of all the values)
    * @returns {Inputs}
    */
    inputs() {
        var ret = wasm.transaction_inputs(this.ptr);
        return Inputs.__wrap(ret);
    }
    /**
    * Get collection of the outputs in the transaction (this allocates new copies of all the values)
    * @returns {Outputs}
    */
    outputs() {
        var ret = wasm.transaction_outputs(this.ptr);
        return Outputs.__wrap(ret);
    }
    /**
    * @returns {Certificate | undefined}
    */
    certificate() {
        var ret = wasm.transaction_certificate(this.ptr);
        return ret === 0 ? undefined : Certificate.__wrap(ret);
    }
    /**
    * @returns {Witnesses}
    */
    witnesses() {
        var ret = wasm.transaction_witnesses(this.ptr);
        return Witnesses.__wrap(ret);
    }
}
/**
*/
export class TransactionBindingAuthData {

    static __wrap(ptr) {
        const obj = Object.create(TransactionBindingAuthData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionbindingauthdata_free(ptr);
    }
}
/**
* Builder pattern implementation for making a Transaction
*
* Example
*
* ```javascript
* ```
*/
export class TransactionBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TransactionBuilder.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionbuilder_free(ptr);
    }
    /**
    */
    constructor() {
        var ret = wasm.transactionbuilder_new();
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @param {Certificate} cert
    * @returns {TransactionBuilderSetIOs}
    */
    payload(cert) {
        var ptr = this.ptr;
        this.ptr = 0;
        _assertClass(cert, Certificate);
        var ret = wasm.transactionbuilder_payload(ptr, cert.ptr);
        return TransactionBuilderSetIOs.__wrap(ret);
    }
    /**
    * @returns {TransactionBuilderSetIOs}
    */
    no_payload() {
        var ptr = this.ptr;
        this.ptr = 0;
        var ret = wasm.transactionbuilder_no_payload(ptr);
        return TransactionBuilderSetIOs.__wrap(ret);
    }
}
/**
*/
export class TransactionBuilderSetAuthData {

    static __wrap(ptr) {
        const obj = Object.create(TransactionBuilderSetAuthData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionbuildersetauthdata_free(ptr);
    }
    /**
    * @returns {TransactionBindingAuthData}
    */
    get_auth_data() {
        var ret = wasm.transactionbuildersetauthdata_get_auth_data(this.ptr);
        return TransactionBindingAuthData.__wrap(ret);
    }
    /**
    * Set the authenticated data
    * @param {PayloadAuthData} auth
    * @returns {Transaction}
    */
    set_payload_auth(auth) {
        var ptr = this.ptr;
        this.ptr = 0;
        _assertClass(auth, PayloadAuthData);
        var ret = wasm.transactionbuildersetauthdata_set_payload_auth(ptr, auth.ptr);
        return Transaction.__wrap(ret);
    }
}
/**
*/
export class TransactionBuilderSetIOs {

    static __wrap(ptr) {
        const obj = Object.create(TransactionBuilderSetIOs.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionbuildersetios_free(ptr);
    }
    /**
    * @param {Inputs} inputs
    * @param {Outputs} outputs
    * @returns {TransactionBuilderSetWitness}
    */
    set_ios(inputs, outputs) {
        var ptr = this.ptr;
        this.ptr = 0;
        _assertClass(inputs, Inputs);
        _assertClass(outputs, Outputs);
        var ret = wasm.transactionbuildersetios_set_ios(ptr, inputs.ptr, outputs.ptr);
        return TransactionBuilderSetWitness.__wrap(ret);
    }
}
/**
*/
export class TransactionBuilderSetWitness {

    static __wrap(ptr) {
        const obj = Object.create(TransactionBuilderSetWitness.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionbuildersetwitness_free(ptr);
    }
    /**
    * @returns {TransactionSignDataHash}
    */
    get_auth_data_for_witness() {
        var ret = wasm.transactionbuildersetwitness_get_auth_data_for_witness(this.ptr);
        return TransactionSignDataHash.__wrap(ret);
    }
    /**
    * @param {Witnesses} witnesses
    * @returns {TransactionBuilderSetAuthData}
    */
    set_witnesses(witnesses) {
        var ptr = this.ptr;
        this.ptr = 0;
        _assertClass(witnesses, Witnesses);
        var ret = wasm.transactionbuildersetwitness_set_witnesses(ptr, witnesses.ptr);
        return TransactionBuilderSetAuthData.__wrap(ret);
    }
}
/**
* Type for representing the hash of a Transaction, necessary for signing it
*/
export class TransactionSignDataHash {

    static __wrap(ptr) {
        const obj = Object.create(TransactionSignDataHash.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_transactionsigndatahash_free(ptr);
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {TransactionSignDataHash}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.transactionsigndatahash_from_bytes(ptr0, len0);
        return TransactionSignDataHash.__wrap(ret);
    }
    /**
    * @param {string} input
    * @returns {TransactionSignDataHash}
    */
    static from_hex(input) {
        var ptr0 = passStringToWasm0(input, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.transactionsigndatahash_from_hex(ptr0, len0);
        return TransactionSignDataHash.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.transactionsigndatahash_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
}
/**
*/
export class U128 {

    static __wrap(ptr) {
        const obj = Object.create(U128.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_u128_free(ptr);
    }
    /**
    * @param {any} bytes
    * @returns {U128}
    */
    static from_be_bytes(bytes) {
        var ret = wasm.u128_from_be_bytes(addHeapObject(bytes));
        return U128.__wrap(ret);
    }
    /**
    * @param {any} bytes
    * @returns {U128}
    */
    static from_le_bytes(bytes) {
        var ret = wasm.u128_from_le_bytes(addHeapObject(bytes));
        return U128.__wrap(ret);
    }
    /**
    * @param {string} s
    * @returns {U128}
    */
    static from_str(s) {
        var ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.u128_from_str(ptr0, len0);
        return U128.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_str() {
        try {
            wasm.u128_to_str(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
* Unspent transaction pointer. This is composed of:
* * the transaction identifier where the unspent output is (a FragmentId)
* * the output index within the pointed transaction\'s outputs
* * the value we expect to read from this output, this setting is added in order to protect undesired withdrawal
* and to set the actual fee in the transaction.
*/
export class UtxoPointer {

    static __wrap(ptr) {
        const obj = Object.create(UtxoPointer.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_utxopointer_free(ptr);
    }
    /**
    * @param {FragmentId} fragment_id
    * @param {number} output_index
    * @param {Value} value
    * @returns {UtxoPointer}
    */
    static new(fragment_id, output_index, value) {
        _assertClass(fragment_id, FragmentId);
        _assertClass(value, Value);
        var ret = wasm.utxopointer_new(fragment_id.ptr, output_index, value.ptr);
        return UtxoPointer.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    output_index() {
        var ret = wasm.utxopointer_output_index(this.ptr);
        return ret;
    }
    /**
    * @returns {FragmentId}
    */
    fragment_id() {
        var ret = wasm.utxopointer_fragment_id(this.ptr);
        return FragmentId.__wrap(ret);
    }
}
/**
*/
export class UtxoWitness {

    static __wrap(ptr) {
        const obj = Object.create(UtxoWitness.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_utxowitness_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    as_bytes() {
        wasm.utxowitness_as_bytes(8, this.ptr);
        var r0 = getInt32Memory0()[8 / 4 + 0];
        var r1 = getInt32Memory0()[8 / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.utxowitness_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @returns {string}
    */
    to_hex() {
        try {
            wasm.utxowitness_to_hex(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {UtxoWitness}
    */
    static from_bytes(bytes) {
        var ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.utxowitness_from_bytes(ptr0, len0);
        return UtxoWitness.__wrap(ret);
    }
    /**
    * @param {string} bech32_str
    * @returns {UtxoWitness}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.utxowitness_from_bech32(ptr0, len0);
        return UtxoWitness.__wrap(ret);
    }
    /**
    * @param {string} input
    * @returns {UtxoWitness}
    */
    static from_hex(input) {
        var ptr0 = passStringToWasm0(input, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.utxowitness_from_hex(ptr0, len0);
        return UtxoWitness.__wrap(ret);
    }
}
/**
* Type used for representing certain amount of lovelaces.
* It wraps an unsigned 64 bits number.
* Strings are used for passing to and from javascript,
* as the native javascript Number type can\'t hold the entire u64 range
* and BigInt is not yet implemented in all the browsers
*/
export class Value {

    static __wrap(ptr) {
        const obj = Object.create(Value.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_value_free(ptr);
    }
    /**
    * Parse the given string into a rust u64 numeric type.
    * @param {string} s
    * @returns {Value}
    */
    static from_str(s) {
        var ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.value_from_str(ptr0, len0);
        return Value.__wrap(ret);
    }
    /**
    * Return the wrapped u64 formatted as a string.
    * @returns {string}
    */
    to_str() {
        try {
            wasm.value_to_str(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @param {Value} other
    * @returns {Value}
    */
    checked_add(other) {
        _assertClass(other, Value);
        var ret = wasm.value_checked_add(this.ptr, other.ptr);
        return Value.__wrap(ret);
    }
    /**
    * @param {Value} other
    * @returns {Value}
    */
    checked_sub(other) {
        _assertClass(other, Value);
        var ret = wasm.value_checked_sub(this.ptr, other.ptr);
        return Value.__wrap(ret);
    }
}
/**
*/
export class VrfPublicKey {

    static __wrap(ptr) {
        const obj = Object.create(VrfPublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_vrfpublickey_free(ptr);
    }
    /**
    * @param {string} bech32_str
    * @returns {VrfPublicKey}
    */
    static from_bech32(bech32_str) {
        var ptr0 = passStringToWasm0(bech32_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ret = wasm.vrfpublickey_from_bech32(ptr0, len0);
        return VrfPublicKey.__wrap(ret);
    }
    /**
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.vrfpublickey_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
* Structure that proofs that certain user agrees with
* some data. This structure is used to sign `Transaction`
* and get `SignedTransaction` out.
*
* It\'s important that witness works with opaque structures
* and may not know the contents of the internal transaction.
*/
export class Witness {

    static __wrap(ptr) {
        const obj = Object.create(Witness.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_witness_free(ptr);
    }
    /**
    * Generate Witness for an utxo-based transaction Input
    * @param {Hash} genesis_hash
    * @param {TransactionSignDataHash} transaction_id
    * @param {PrivateKey} secret_key
    * @returns {Witness}
    */
    static for_utxo(genesis_hash, transaction_id, secret_key) {
        _assertClass(genesis_hash, Hash);
        _assertClass(transaction_id, TransactionSignDataHash);
        _assertClass(secret_key, PrivateKey);
        var ret = wasm.witness_for_utxo(genesis_hash.ptr, transaction_id.ptr, secret_key.ptr);
        return Witness.__wrap(ret);
    }
    /**
    * @param {UtxoWitness} witness
    * @returns {Witness}
    */
    static from_external_utxo(witness) {
        _assertClass(witness, UtxoWitness);
        var ret = wasm.witness_from_external_utxo(witness.ptr);
        return Witness.__wrap(ret);
    }
    /**
    * Generate Witness for an account based transaction Input
    * the account-spending-counter should be incremented on each transaction from this account
    * @param {Hash} genesis_hash
    * @param {TransactionSignDataHash} transaction_id
    * @param {PrivateKey} secret_key
    * @param {SpendingCounter} account_spending_counter
    * @returns {Witness}
    */
    static for_account(genesis_hash, transaction_id, secret_key, account_spending_counter) {
        _assertClass(genesis_hash, Hash);
        _assertClass(transaction_id, TransactionSignDataHash);
        _assertClass(secret_key, PrivateKey);
        _assertClass(account_spending_counter, SpendingCounter);
        var ret = wasm.witness_for_account(genesis_hash.ptr, transaction_id.ptr, secret_key.ptr, account_spending_counter.ptr);
        return Witness.__wrap(ret);
    }
    /**
    * @param {AccountWitness} witness
    * @returns {Witness}
    */
    static from_external_account(witness) {
        _assertClass(witness, AccountWitness);
        var ret = wasm.witness_from_external_account(witness.ptr);
        return Witness.__wrap(ret);
    }
    /**
    * Generate Witness for a legacy icarus utxo-based transaction Input
    * @param {Hash} genesis_hash
    * @param {TransactionSignDataHash} transaction_id
    * @param {Bip32PrivateKey} secret_key
    * @returns {Witness}
    */
    static for_legacy_icarus_utxo(genesis_hash, transaction_id, secret_key) {
        _assertClass(genesis_hash, Hash);
        _assertClass(transaction_id, TransactionSignDataHash);
        _assertClass(secret_key, Bip32PrivateKey);
        var ret = wasm.witness_for_legacy_icarus_utxo(genesis_hash.ptr, transaction_id.ptr, secret_key.ptr);
        return Witness.__wrap(ret);
    }
    /**
    * @param {Bip32PublicKey} key
    * @param {LegacyUtxoWitness} witness
    * @returns {Witness}
    */
    static from_external_legacy_icarus_utxo(key, witness) {
        _assertClass(key, Bip32PublicKey);
        _assertClass(witness, LegacyUtxoWitness);
        var ret = wasm.witness_from_external_legacy_icarus_utxo(key.ptr, witness.ptr);
        return Witness.__wrap(ret);
    }
    /**
    * Generate Witness for a legacy daedalus utxo-based transaction Input
    * @param {Hash} genesis_hash
    * @param {TransactionSignDataHash} transaction_id
    * @param {LegacyDaedalusPrivateKey} secret_key
    * @returns {Witness}
    */
    static for_legacy_daedalus_utxo(genesis_hash, transaction_id, secret_key) {
        _assertClass(genesis_hash, Hash);
        _assertClass(transaction_id, TransactionSignDataHash);
        _assertClass(secret_key, LegacyDaedalusPrivateKey);
        var ret = wasm.witness_for_legacy_daedalus_utxo(genesis_hash.ptr, transaction_id.ptr, secret_key.ptr);
        return Witness.__wrap(ret);
    }
    /**
    * Get string representation
    * @returns {string}
    */
    to_bech32() {
        try {
            wasm.witness_to_bech32(8, this.ptr);
            var r0 = getInt32Memory0()[8 / 4 + 0];
            var r1 = getInt32Memory0()[8 / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_free(r0, r1);
        }
    }
}
/**
*/
export class Witnesses {

    static __wrap(ptr) {
        const obj = Object.create(Witnesses.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;

        wasm.__wbg_witnesses_free(ptr);
    }
    /**
    * @returns {Witnesses}
    */
    static new() {
        var ret = wasm.witnesses_new();
        return Witnesses.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    size() {
        var ret = wasm.witnesses_size(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {Witness}
    */
    get(index) {
        var ret = wasm.witnesses_get(this.ptr, index);
        return Witness.__wrap(ret);
    }
    /**
    * @param {Witness} item
    */
    add(item) {
        _assertClass(item, Witness);
        var ptr0 = item.ptr;
        item.ptr = 0;
        wasm.witnesses_add(this.ptr, ptr0);
    }
}

export const __wbindgen_string_new = function(arg0, arg1) {
    var ret = getStringFromWasm0(arg0, arg1);
    return addHeapObject(ret);
};

export const __wbindgen_object_drop_ref = function(arg0) {
    takeObject(arg0);
};

export const __wbindgen_json_serialize = function(arg0, arg1) {
    const obj = getObject(arg1);
    var ret = JSON.stringify(obj === undefined ? null : obj);
    var ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len0;
    getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

export const __wbindgen_is_undefined = function(arg0) {
    var ret = getObject(arg0) === undefined;
    return ret;
};

export const __wbg_buffer_1bb127df6348017b = function(arg0) {
    var ret = getObject(arg0).buffer;
    return addHeapObject(ret);
};

export const __wbg_new_dca22b33e64c73c1 = function(arg0) {
    var ret = new Uint8Array(getObject(arg0));
    return addHeapObject(ret);
};

export const __wbg_set_73d74d5ab6493dfb = function(arg0, arg1, arg2) {
    getObject(arg0).set(getObject(arg1), arg2 >>> 0);
};

export const __wbg_length_95b24a2f871acd5e = function(arg0) {
    var ret = getObject(arg0).length;
    return ret;
};

export const __wbg_new_3a746f2619705add = function(arg0, arg1) {
    var ret = new Function(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
};

export const __wbg_call_f54d3a6dadb199ca = function(arg0, arg1) {
    var ret = getObject(arg0).call(getObject(arg1));
    return addHeapObject(ret);
};

export const __wbindgen_jsval_eq = function(arg0, arg1) {
    var ret = getObject(arg0) === getObject(arg1);
    return ret;
};

export const __wbg_self_ac379e780a0d8b94 = function(arg0) {
    var ret = getObject(arg0).self;
    return addHeapObject(ret);
};

export const __wbg_crypto_1e4302b85d4f64a2 = function(arg0) {
    var ret = getObject(arg0).crypto;
    return addHeapObject(ret);
};

export const __wbg_getRandomValues_1b4ba144162a5c9e = function(arg0) {
    var ret = getObject(arg0).getRandomValues;
    return addHeapObject(ret);
};

export const __wbg_require_6461b1e9a0d7c34a = function(arg0, arg1) {
    var ret = require(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
};

export const __wbg_randomFillSync_1b52c8482374c55b = function(arg0, arg1, arg2) {
    getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
};

export const __wbg_getRandomValues_1ef11e888e5228e9 = function(arg0, arg1, arg2) {
    getObject(arg0).getRandomValues(getArrayU8FromWasm0(arg1, arg2));
};

export const __wbindgen_throw = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

export const __wbindgen_rethrow = function(arg0) {
    throw takeObject(arg0);
};

export const __wbindgen_memory = function() {
    var ret = wasm.memory;
    return addHeapObject(ret);
};

