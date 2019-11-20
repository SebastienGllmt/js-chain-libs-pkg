/* tslint:disable */
/**
* @param {any} input 
* @returns {string} 
*/
export function uint8array_to_hex(input: any): string;
export enum AddressDiscrimination {
  Production,
  Test,
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
export enum AddressKind {
  Single,
  Group,
  Account,
  Multisig,
}
/**
*/
export enum CertificateType {
  StakeDelegation,
  OwnerStakeDelegation,
  PoolRegistration,
  PoolRetirement,
  PoolUpdate,
}
/**
*/
/**
* This is either an single account or a multisig account depending on the witness type
*/
export class Account {
  free(): void;
/**
* @param {Address} address 
* @returns {Account} 
*/
  static from_address(address: Address): Account;
/**
* @param {number} discriminant 
* @returns {Address} 
*/
  to_address(discriminant: number): Address;
/**
* @param {PublicKey} key 
* @returns {Account} 
*/
  static single_from_public_key(key: PublicKey): Account;
/**
* @returns {AccountIdentifier} 
*/
  to_identifier(): AccountIdentifier;
}
/**
*/
export class AccountAddress {
  free(): void;
/**
* @returns {PublicKey} 
*/
  get_account_key(): PublicKey;
/**
* @returns {Address} 
*/
  to_base_address(): Address;
}
/**
*/
export class AccountBindingSignature {
  free(): void;
/**
* @param {PrivateKey} private_key 
* @param {TransactionBindingAuthData} auth_data 
* @returns {AccountBindingSignature} 
*/
  static new_single(private_key: PrivateKey, auth_data: TransactionBindingAuthData): AccountBindingSignature;
}
/**
*/
export class AccountIdentifier {
  free(): void;
/**
* @returns {string} 
*/
  to_hex(): string;
/**
* @returns {Account} 
*/
  to_account_single(): Account;
/**
* @returns {Account} 
*/
  to_account_multi(): Account;
}
/**
*/
export class AccountWitness {
  free(): void;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* @returns {string} 
*/
  to_bech32(): string;
/**
* @returns {string} 
*/
  to_hex(): string;
/**
* @param {Uint8Array} bytes 
* @returns {AccountWitness} 
*/
  static from_bytes(bytes: Uint8Array): AccountWitness;
/**
* @param {string} bech32_str 
* @returns {AccountWitness} 
*/
  static from_bech32(bech32_str: string): AccountWitness;
/**
* @param {string} input 
* @returns {AccountWitness} 
*/
  static from_hex(input: string): AccountWitness;
}
/**
* An address of any type, this can be one of
* * A utxo-based address without delegation (single)
* * A utxo-based address with delegation (group)
* * An address for an account
*/
export class Address {
  free(): void;
/**
* @param {any} bytes 
* @returns {Address} 
*/
  static from_bytes(bytes: any): Address;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* Construct Address from its bech32 representation
* Example
* ```javascript
* const address = Address.from_string(&#39;ca1q09u0nxmnfg7af8ycuygx57p5xgzmnmgtaeer9xun7hly6mlgt3pjyknplu&#39;);
* ```
* @param {string} s 
* @returns {Address} 
*/
  static from_string(s: string): Address;
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
  to_string(prefix: string): string;
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
  static single_from_public_key(key: PublicKey, discrimination: number): Address;
/**
* Construct a non-account address from a pair of public keys, delegating founds from the first to the second
* @param {PublicKey} key 
* @param {PublicKey} delegation 
* @param {number} discrimination 
* @returns {Address} 
*/
  static delegation_from_public_key(key: PublicKey, delegation: PublicKey, discrimination: number): Address;
/**
* Construct address of account type from a public key
* @param {PublicKey} key 
* @param {number} discrimination 
* @returns {Address} 
*/
  static account_from_public_key(key: PublicKey, discrimination: number): Address;
/**
* @param {Uint8Array} merkle_root 
* @param {number} discrimination 
* @returns {Address} 
*/
  static multisig_from_merkle_root(merkle_root: Uint8Array, discrimination: number): Address;
/**
* @returns {number} 
*/
  get_discrimination(): number;
/**
* @returns {number} 
*/
  get_kind(): number;
/**
* @returns {SingleAddress} 
*/
  to_single_address(): SingleAddress | undefined;
/**
* @returns {GroupAddress} 
*/
  to_group_address(): GroupAddress | undefined;
/**
* @returns {AccountAddress} 
*/
  to_account_address(): AccountAddress | undefined;
/**
* @returns {MultisigAddress} 
*/
  to_multisig_address(): MultisigAddress | undefined;
}
/**
* Amount of the balance in the transaction.
*/
export class Balance {
  free(): void;
/**
* @returns {any} 
*/
  get_sign(): any;
/**
* @returns {boolean} 
*/
  is_positive(): boolean;
/**
* @returns {boolean} 
*/
  is_negative(): boolean;
/**
* @returns {boolean} 
*/
  is_zero(): boolean;
/**
* Get value without taking into account if the balance is positive or negative
* @returns {Value} 
*/
  get_value(): Value;
}
/**
*/
export class Bip32PrivateKey {
  free(): void;
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
  derive(index: number): Bip32PrivateKey;
/**
* @returns {Bip32PrivateKey} 
*/
  static generate_ed25519_bip32(): Bip32PrivateKey;
/**
* @returns {PrivateKey} 
*/
  to_raw_key(): PrivateKey;
/**
* @returns {Bip32PublicKey} 
*/
  to_public(): Bip32PublicKey;
/**
* @param {Uint8Array} bytes 
* @returns {Bip32PrivateKey} 
*/
  static from_bytes(bytes: Uint8Array): Bip32PrivateKey;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* @param {string} bech32_str 
* @returns {Bip32PrivateKey} 
*/
  static from_bech32(bech32_str: string): Bip32PrivateKey;
/**
* @returns {string} 
*/
  to_bech32(): string;
/**
* @param {Uint8Array} entropy 
* @param {Uint8Array} password 
* @returns {Bip32PrivateKey} 
*/
  static from_bip39_entropy(entropy: Uint8Array, password: Uint8Array): Bip32PrivateKey;
}
/**
*/
export class Bip32PublicKey {
  free(): void;
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
  derive(index: number): Bip32PublicKey;
/**
* @returns {PublicKey} 
*/
  to_raw_key(): PublicKey;
/**
* @param {Uint8Array} bytes 
* @returns {Bip32PublicKey} 
*/
  static from_bytes(bytes: Uint8Array): Bip32PublicKey;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* @param {string} bech32_str 
* @returns {Bip32PublicKey} 
*/
  static from_bech32(bech32_str: string): Bip32PublicKey;
/**
* @returns {string} 
*/
  to_bech32(): string;
}
/**
* `Block` is an element of the blockchain it contains multiple
* transaction and a reference to the parent block. Alongside
* with the position of that block in the chain.
*/
export class Block {
  free(): void;
/**
* Deserialize a block from a byte array
* @param {any} bytes 
* @returns {Block} 
*/
  static from_bytes(bytes: any): Block;
/**
* @returns {BlockId} 
*/
  id(): BlockId;
/**
* @returns {BlockId} 
*/
  parent_id(): BlockId;
/**
*This involves copying all the fragments
* @returns {Fragments} 
*/
  fragments(): Fragments;
/**
* @returns {number} 
*/
  epoch(): number;
/**
* @returns {number} 
*/
  slot(): number;
/**
* @returns {number} 
*/
  chain_length(): number;
/**
* @returns {PoolId} 
*/
  leader_id(): PoolId | undefined;
/**
* @returns {number} 
*/
  content_size(): number;
}
/**
*/
export class BlockId {
  free(): void;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
}
/**
*/
export class Certificate {
  free(): void;
/**
* Create a Certificate for StakeDelegation
* @param {StakeDelegation} stake_delegation 
* @returns {Certificate} 
*/
  static stake_delegation(stake_delegation: StakeDelegation): Certificate;
/**
* Create a Certificate for PoolRegistration
* @param {PoolRegistration} pool_registration 
* @returns {Certificate} 
*/
  static stake_pool_registration(pool_registration: PoolRegistration): Certificate;
/**
* Create a Certificate for PoolRetirement
* @param {PoolRetirement} pool_retirement 
* @returns {Certificate} 
*/
  static stake_pool_retirement(pool_retirement: PoolRetirement): Certificate;
/**
* @returns {number} 
*/
  get_type(): number;
/**
* @returns {StakeDelegation} 
*/
  get_stake_delegation(): StakeDelegation;
/**
* @returns {OwnerStakeDelegation} 
*/
  get_owner_stake_delegation(): OwnerStakeDelegation;
/**
* @returns {PoolRegistration} 
*/
  get_pool_registration(): PoolRegistration;
/**
* @returns {PoolRetirement} 
*/
  get_pool_retirement(): PoolRetirement;
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
  free(): void;
/**
* @param {number} parts 
* @param {PoolDelegationRatios} pools 
* @returns {DelegationRatio} 
*/
  static new(parts: number, pools: PoolDelegationRatios): DelegationRatio | undefined;
}
/**
* Set the choice of delegation:
*
* * No delegation
* * Full delegation of this account to a specific pool
* * Ratio of stake to multiple pools
*/
export class DelegationType {
  free(): void;
/**
* @returns {DelegationType} 
*/
  static non_delegated(): DelegationType;
/**
* @param {PoolId} pool_id 
* @returns {DelegationType} 
*/
  static full(pool_id: PoolId): DelegationType;
/**
* @param {DelegationRatio} r 
* @returns {DelegationType} 
*/
  static ratio(r: DelegationRatio): DelegationType;
}
/**
*/
export class Ed25519Signature {
  free(): void;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* @returns {string} 
*/
  to_bech32(): string;
/**
* @returns {string} 
*/
  to_hex(): string;
/**
* @param {Uint8Array} bytes 
* @returns {Ed25519Signature} 
*/
  static from_bytes(bytes: Uint8Array): Ed25519Signature;
/**
* @param {string} bech32_str 
* @returns {Ed25519Signature} 
*/
  static from_bech32(bech32_str: string): Ed25519Signature;
/**
* @param {string} input 
* @returns {Ed25519Signature} 
*/
  static from_hex(input: string): Ed25519Signature;
}
/**
* Algorithm used to compute transaction fees
* Currently the only implementation is the Linear one
*/
export class Fee {
  free(): void;
/**
* Linear algorithm, this is formed by: `coefficient * (#inputs + #outputs) + constant + certificate * #certificate
* @param {Value} constant 
* @param {Value} coefficient 
* @param {Value} certificate 
* @returns {Fee} 
*/
  static linear_fee(constant: Value, coefficient: Value, certificate: Value): Fee;
/**
* @param {Transaction} tx 
* @returns {Value} 
*/
  calculate(tx: Transaction): Value;
}
/**
* All possible messages recordable in the Block content
*/
export class Fragment {
  free(): void;
/**
* @param {Transaction} tx 
* @returns {Fragment} 
*/
  static from_transaction(tx: Transaction): Fragment;
/**
* Get a Transaction if the Fragment represents one
* @returns {Transaction} 
*/
  get_transaction(): Transaction;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* @returns {boolean} 
*/
  is_initial(): boolean;
/**
* @returns {boolean} 
*/
  is_transaction(): boolean;
/**
* @returns {boolean} 
*/
  is_owner_stake_delegation(): boolean;
/**
* @returns {boolean} 
*/
  is_stake_delegation(): boolean;
/**
* @returns {boolean} 
*/
  is_pool_registration(): boolean;
/**
* @returns {boolean} 
*/
  is_pool_retirement(): boolean;
/**
* @returns {boolean} 
*/
  is_pool_update(): boolean;
/**
* @returns {boolean} 
*/
  is_old_utxo_declaration(): boolean;
/**
* @returns {boolean} 
*/
  is_update_proposal(): boolean;
/**
* @returns {boolean} 
*/
  is_update_vote(): boolean;
/**
* @returns {FragmentId} 
*/
  id(): FragmentId;
}
/**
*/
export class FragmentId {
  free(): void;
/**
* @param {Uint8Array} bytes 
* @returns {FragmentId} 
*/
  static from_bytes(bytes: Uint8Array): FragmentId;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
}
/**
*/
export class Fragments {
  free(): void;
/**
* @returns {Fragments} 
*/
  static new(): Fragments;
/**
* @returns {number} 
*/
  size(): number;
/**
* @param {number} index 
* @returns {Fragment} 
*/
  get(index: number): Fragment;
/**
* @param {Fragment} item 
*/
  add(item: Fragment): void;
}
/**
*/
export class GroupAddress {
  free(): void;
/**
* @returns {PublicKey} 
*/
  get_spending_key(): PublicKey;
/**
* @returns {PublicKey} 
*/
  get_account_key(): PublicKey;
/**
* @returns {Address} 
*/
  to_base_address(): Address;
}
/**
* Type for representing a generic Hash
*/
export class Hash {
  free(): void;
/**
* @param {Uint8Array} bytes 
* @returns {Hash} 
*/
  static from_bytes(bytes: Uint8Array): Hash;
/**
* @param {string} hex_string 
* @returns {Hash} 
*/
  static from_hex(hex_string: string): Hash;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
}
/**
*/
export class IndexSignatures {
  free(): void;
/**
* @returns {IndexSignatures} 
*/
  static new(): IndexSignatures;
/**
* @returns {number} 
*/
  size(): number;
/**
* @param {number} index 
* @returns {IndexedSignature} 
*/
  get(index: number): IndexedSignature;
/**
* @param {IndexedSignature} item 
*/
  add(item: IndexedSignature): void;
}
/**
*/
export class IndexedSignature {
  free(): void;
/**
* @param {number} index 
* @param {AccountBindingSignature} signature 
* @returns {IndexedSignature} 
*/
  static new(index: number, signature: AccountBindingSignature): IndexedSignature;
}
/**
*/
export class Input {
  free(): void;
/**
* @param {UtxoPointer} utxo_pointer 
* @returns {Input} 
*/
  static from_utxo(utxo_pointer: UtxoPointer): Input;
/**
* @param {Account} account 
* @param {Value} v 
* @returns {Input} 
*/
  static from_account(account: Account, v: Value): Input;
/**
* Get the kind of Input, this can be either \"Account\" or \"Utxo\
* @returns {string} 
*/
  get_type(): string;
/**
* @returns {boolean} 
*/
  is_account(): boolean;
/**
* @returns {boolean} 
*/
  is_utxo(): boolean;
/**
* @returns {Value} 
*/
  value(): Value;
/**
* Get the inner UtxoPointer if the Input type is Utxo
* @returns {UtxoPointer} 
*/
  get_utxo_pointer(): UtxoPointer;
/**
* Get the source Account if the Input type is Account
* @returns {AccountIdentifier} 
*/
  get_account_identifier(): AccountIdentifier;
}
/**
*/
export class InputOutput {
  free(): void;
/**
* @returns {Inputs} 
*/
  inputs(): Inputs;
/**
* @returns {Outputs} 
*/
  outputs(): Outputs;
}
/**
*/
export class InputOutputBuilder {
  free(): void;
/**
* @returns {InputOutputBuilder} 
*/
  static empty(): InputOutputBuilder;
/**
* Add input to the IO Builder
* @param {Input} input 
*/
  add_input(input: Input): void;
/**
* Add output to the IO Builder
* @param {Address} address 
* @param {Value} value 
*/
  add_output(address: Address, value: Value): void;
/**
* Estimate fee with the currently added inputs, outputs and certificate based on the given algorithm
* @param {Fee} fee 
* @param {Payload} payload 
* @returns {Value} 
*/
  estimate_fee(fee: Fee, payload: Payload): Value;
/**
* @param {Payload} payload 
* @param {Fee} fee 
* @returns {Balance} 
*/
  get_balance(payload: Payload, fee: Fee): Balance;
/**
* @returns {Balance} 
*/
  get_balance_without_fee(): Balance;
/**
* @returns {InputOutput} 
*/
  build(): InputOutput;
/**
* Seal the transaction by passing fee rule
* @param {Payload} payload 
* @param {Fee} fee_algorithm 
* @returns {InputOutput} 
*/
  seal(payload: Payload, fee_algorithm: Fee): InputOutput;
/**
* Seal the transaction by passing fee rule and the output policy
* @param {Payload} payload 
* @param {Fee} fee_algorithm 
* @param {OutputPolicy} policy 
* @returns {InputOutput} 
*/
  seal_with_output_policy(payload: Payload, fee_algorithm: Fee, policy: OutputPolicy): InputOutput;
}
/**
*/
export class Inputs {
  free(): void;
/**
* @returns {Inputs} 
*/
  static new(): Inputs;
/**
* @returns {number} 
*/
  size(): number;
/**
* @param {number} index 
* @returns {Input} 
*/
  get(index: number): Input;
/**
* @param {Input} item 
*/
  add(item: Input): void;
}
/**
*/
export class KesPublicKey {
  free(): void;
/**
* @param {string} bech32_str 
* @returns {KesPublicKey} 
*/
  static from_bech32(bech32_str: string): KesPublicKey;
}
/**
*/
export class LegacyUtxoWitness {
  free(): void;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* @returns {string} 
*/
  to_bech32(): string;
/**
* @returns {string} 
*/
  to_hex(): string;
/**
* @param {Uint8Array} bytes 
* @returns {LegacyUtxoWitness} 
*/
  static from_bytes(bytes: Uint8Array): LegacyUtxoWitness;
/**
* @param {string} bech32_str 
* @returns {LegacyUtxoWitness} 
*/
  static from_bech32(bech32_str: string): LegacyUtxoWitness;
/**
* @param {string} input 
* @returns {LegacyUtxoWitness} 
*/
  static from_hex(input: string): LegacyUtxoWitness;
}
/**
*/
export class MultisigAddress {
  free(): void;
/**
* @returns {Uint8Array} 
*/
  get_merkle_root(): Uint8Array;
/**
* @returns {Address} 
*/
  to_base_address(): Address;
}
/**
* Type for representing a Transaction Output, composed of an Address and a Value
*/
export class Output {
  free(): void;
/**
* @returns {Address} 
*/
  address(): Address;
/**
* @returns {Value} 
*/
  value(): Value;
}
/**
* Helper to add change addresses when finalizing a transaction, there are currently two options
* * forget: use all the excess money as fee
* * one: send all the excess money to the given address
*/
export class OutputPolicy {
  free(): void;
/**
* don\'t do anything with the excess money in transaction
* @returns {OutputPolicy} 
*/
  static forget(): OutputPolicy;
/**
* use the given address as the only change address
* @param {Address} address 
* @returns {OutputPolicy} 
*/
  static one(address: Address): OutputPolicy;
}
/**
*/
export class Outputs {
  free(): void;
/**
* @returns {Outputs} 
*/
  static new(): Outputs;
/**
* @returns {number} 
*/
  size(): number;
/**
* @param {number} index 
* @returns {Output} 
*/
  get(index: number): Output;
/**
* @param {Output} item 
*/
  add(item: Output): void;
}
/**
*/
export class OwnerStakeDelegation {
  free(): void;
/**
* @param {DelegationType} delegation_type 
* @returns {OwnerStakeDelegation} 
*/
  static new(delegation_type: DelegationType): OwnerStakeDelegation;
/**
* @returns {DelegationType} 
*/
  delegation_type(): DelegationType;
}
/**
*/
export class Payload {
  free(): void;
/**
* @returns {Payload} 
*/
  static no_payload(): Payload;
/**
* @param {Certificate} certificate 
* @returns {Payload} 
*/
  static certificate(certificate: Certificate): Payload;
}
/**
*/
export class PayloadAuthData {
  free(): void;
/**
* @returns {PayloadAuthData} 
*/
  static for_no_payload(): PayloadAuthData;
/**
* @returns {PayloadAuthData} 
*/
  static for_owner_stake_delegation(): PayloadAuthData;
/**
* @param {StakeDelegationAuthData} auth_data 
* @returns {PayloadAuthData} 
*/
  static for_stake_delegation(auth_data: StakeDelegationAuthData): PayloadAuthData;
/**
* @param {PoolRegistrationAuthData} auth_data 
* @returns {PayloadAuthData} 
*/
  static for_pool_registration(auth_data: PoolRegistrationAuthData): PayloadAuthData;
/**
* @param {PoolRetirementAuthData} auth_data 
* @returns {PayloadAuthData} 
*/
  static for_pool_retirement(auth_data: PoolRetirementAuthData): PayloadAuthData;
/**
* @param {PoolUpdateAuthData} auth_data 
* @returns {PayloadAuthData} 
*/
  static for_pool_update(auth_data: PoolUpdateAuthData): PayloadAuthData;
}
/**
*/
export class PoolDelegationRatio {
  free(): void;
/**
* @param {PoolId} pool 
* @param {number} part 
* @returns {PoolDelegationRatio} 
*/
  static new(pool: PoolId, part: number): PoolDelegationRatio;
}
/**
*/
export class PoolDelegationRatios {
  free(): void;
/**
* @returns {PoolDelegationRatios} 
*/
  static new(): PoolDelegationRatios;
/**
* @returns {number} 
*/
  size(): number;
/**
* @param {number} index 
* @returns {PoolDelegationRatio} 
*/
  get(index: number): PoolDelegationRatio;
/**
* @param {PoolDelegationRatio} item 
*/
  add(item: PoolDelegationRatio): void;
}
/**
*/
export class PoolId {
  free(): void;
/**
* @param {string} hex_string 
* @returns {PoolId} 
*/
  static from_hex(hex_string: string): PoolId;
/**
* @returns {string} 
*/
  to_string(): string;
}
/**
*/
export class PoolRegistration {
  free(): void;
/**
* @param {U128} serial 
* @param {PublicKeys} owners 
* @param {PublicKeys} operators 
* @param {number} management_threshold 
* @param {TimeOffsetSeconds} start_validity 
* @param {KesPublicKey} kes_public_key 
* @param {VrfPublicKey} vrf_public_key 
* @returns {PoolRegistration} 
*/
  constructor(serial: U128, owners: PublicKeys, operators: PublicKeys, management_threshold: number, start_validity: TimeOffsetSeconds, kes_public_key: KesPublicKey, vrf_public_key: VrfPublicKey);
/**
* @returns {PoolId} 
*/
  id(): PoolId;
/**
* @returns {TimeOffsetSeconds} 
*/
  start_validity(): TimeOffsetSeconds;
/**
* @returns {PublicKeys} 
*/
  owners(): PublicKeys;
/**
* @returns {TaxType} 
*/
  rewards(): TaxType;
}
/**
*/
export class PoolRegistrationAuthData {
  free(): void;
/**
* @param {IndexSignatures} signatures 
* @returns {PoolRegistrationAuthData} 
*/
  static new(signatures: IndexSignatures): PoolRegistrationAuthData;
}
/**
*/
export class PoolRetirement {
  free(): void;
}
/**
*/
export class PoolRetirementAuthData {
  free(): void;
/**
* @param {IndexSignatures} signatures 
* @returns {PoolRetirementAuthData} 
*/
  static new(signatures: IndexSignatures): PoolRetirementAuthData;
}
/**
*/
export class PoolUpdateAuthData {
  free(): void;
/**
* @param {IndexSignatures} signatures 
* @returns {PoolUpdateAuthData} 
*/
  static new(signatures: IndexSignatures): PoolUpdateAuthData;
}
/**
* ED25519 signing key, either normal or extended
*/
export class PrivateKey {
  free(): void;
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
  static from_bech32(bech32_str: string): PrivateKey;
/**
* @returns {PublicKey} 
*/
  to_public(): PublicKey;
/**
* @returns {PrivateKey} 
*/
  static generate_ed25519(): PrivateKey;
/**
* @returns {PrivateKey} 
*/
  static generate_ed25519extended(): PrivateKey;
/**
* @returns {string} 
*/
  to_bech32(): string;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* @param {Uint8Array} bytes 
* @returns {PrivateKey} 
*/
  static from_extended_bytes(bytes: Uint8Array): PrivateKey;
/**
* @param {Uint8Array} bytes 
* @returns {PrivateKey} 
*/
  static from_normal_bytes(bytes: Uint8Array): PrivateKey;
/**
* @param {Uint8Array} message 
* @returns {Ed25519Signature} 
*/
  sign(message: Uint8Array): Ed25519Signature;
}
/**
* ED25519 key used as public key
*/
export class PublicKey {
  free(): void;
/**
* Get private key from its bech32 representation
* Example:
* ```javascript
* const pkey = PublicKey.from_bech32(&#39;ed25519_pk1dgaagyh470y66p899txcl3r0jaeaxu6yd7z2dxyk55qcycdml8gszkxze2&#39;);
* ```
* @param {string} bech32_str 
* @returns {PublicKey} 
*/
  static from_bech32(bech32_str: string): PublicKey;
/**
* @returns {string} 
*/
  to_bech32(): string;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* @param {Uint8Array} bytes 
* @returns {PublicKey} 
*/
  static from_bytes(bytes: Uint8Array): PublicKey;
/**
* @param {Uint8Array} data 
* @param {Ed25519Signature} signature 
* @returns {boolean} 
*/
  verify(data: Uint8Array, signature: Ed25519Signature): boolean;
}
/**
*/
export class PublicKeys {
  free(): void;
/**
* @returns {PublicKeys} 
*/
  constructor();
/**
* @returns {number} 
*/
  size(): number;
/**
* @param {number} index 
* @returns {PublicKey} 
*/
  get(index: number): PublicKey;
/**
* @param {PublicKey} key 
*/
  add(key: PublicKey): void;
}
/**
*/
export class SingleAddress {
  free(): void;
/**
* @returns {PublicKey} 
*/
  get_spending_key(): PublicKey;
/**
* @returns {Address} 
*/
  to_base_address(): Address;
}
/**
*/
export class SpendingCounter {
  free(): void;
/**
* @returns {SpendingCounter} 
*/
  static zero(): SpendingCounter;
/**
* @param {number} counter 
* @returns {SpendingCounter} 
*/
  static from_u32(counter: number): SpendingCounter;
}
/**
*/
export class StakeDelegation {
  free(): void;
/**
* Create a stake delegation object from account (stake key) to pool_id
* @param {DelegationType} delegation_type 
* @param {PublicKey} account 
* @returns {StakeDelegation} 
*/
  static new(delegation_type: DelegationType, account: PublicKey): StakeDelegation;
/**
* @returns {DelegationType} 
*/
  delegation_type(): DelegationType;
/**
* @returns {AccountIdentifier} 
*/
  account(): AccountIdentifier;
}
/**
*/
export class StakeDelegationAuthData {
  free(): void;
/**
* @param {AccountBindingSignature} signature 
* @returns {StakeDelegationAuthData} 
*/
  static new(signature: AccountBindingSignature): StakeDelegationAuthData;
}
/**
*/
export class TaxType {
  free(): void;
}
/**
*/
export class TimeOffsetSeconds {
  free(): void;
/**
* Parse the given string into a 64 bits unsigned number
* @param {string} number 
* @returns {TimeOffsetSeconds} 
*/
  static from_string(number: string): TimeOffsetSeconds;
/**
* @returns {string} 
*/
  to_string(): string;
}
/**
* Type representing a unsigned transaction
*/
export class Transaction {
  free(): void;
/**
* Get the transaction id, needed to compute its signature
* @returns {TransactionSignDataHash} 
*/
  id(): TransactionSignDataHash;
/**
* @returns {Witnesses} 
*/
  witnesses(): Witnesses;
/**
* Get collection of the inputs in the transaction (this allocates new copies of all the values)
* @returns {Inputs} 
*/
  inputs(): Inputs;
/**
* Get collection of the outputs in the transaction (this allocates new copies of all the values)
* @returns {Outputs} 
*/
  outputs(): Outputs;
/**
* @returns {Certificate} 
*/
  certificate(): Certificate | undefined;
}
/**
*/
export class TransactionBindingAuthData {
  free(): void;
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
  free(): void;
/**
* @returns {TransactionBuilder} 
*/
  constructor();
/**
* @param {Certificate} cert 
* @returns {TransactionBuilderSetIOs} 
*/
  payload(cert: Certificate): TransactionBuilderSetIOs;
/**
* @returns {TransactionBuilderSetIOs} 
*/
  no_payload(): TransactionBuilderSetIOs;
}
/**
*/
export class TransactionBuilderSetAuthData {
  free(): void;
/**
* @returns {TransactionBindingAuthData} 
*/
  get_auth_data(): TransactionBindingAuthData;
/**
* Set the authenticated data
* @param {PayloadAuthData} auth 
* @returns {Transaction} 
*/
  set_payload_auth(auth: PayloadAuthData): Transaction;
}
/**
*/
export class TransactionBuilderSetIOs {
  free(): void;
/**
* @param {Inputs} inputs 
* @param {Outputs} outputs 
* @returns {TransactionBuilderSetWitness} 
*/
  set_ios(inputs: Inputs, outputs: Outputs): TransactionBuilderSetWitness;
}
/**
*/
export class TransactionBuilderSetWitness {
  free(): void;
/**
* @returns {TransactionSignDataHash} 
*/
  get_auth_data_for_witness(): TransactionSignDataHash;
/**
* @param {Witnesses} witnesses 
* @returns {TransactionBuilderSetAuthData} 
*/
  set_witnesses(witnesses: Witnesses): TransactionBuilderSetAuthData;
}
/**
* Type for representing the hash of a Transaction, necessary for signing it
*/
export class TransactionSignDataHash {
  free(): void;
/**
* @param {Uint8Array} bytes 
* @returns {TransactionSignDataHash} 
*/
  static from_bytes(bytes: Uint8Array): TransactionSignDataHash;
/**
* @param {string} input 
* @returns {TransactionSignDataHash} 
*/
  static from_hex(input: string): TransactionSignDataHash;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
}
/**
*/
export class U128 {
  free(): void;
/**
* @param {any} bytes 
* @returns {U128} 
*/
  static from_be_bytes(bytes: any): U128;
/**
* @param {any} bytes 
* @returns {U128} 
*/
  static from_le_bytes(bytes: any): U128;
/**
* @param {string} s 
* @returns {U128} 
*/
  static from_str(s: string): U128;
/**
* @returns {string} 
*/
  to_str(): string;
}
/**
* Unspent transaction pointer. This is composed of:
* * the transaction identifier where the unspent output is (a FragmentId)
* * the output index within the pointed transaction\'s outputs
* * the value we expect to read from this output, this setting is added in order to protect undesired withdrawal
* and to set the actual fee in the transaction.
*/
export class UtxoPointer {
  free(): void;
/**
* @param {FragmentId} fragment_id 
* @param {number} output_index 
* @param {Value} value 
* @returns {UtxoPointer} 
*/
  static new(fragment_id: FragmentId, output_index: number, value: Value): UtxoPointer;
/**
* @returns {number} 
*/
  output_index(): number;
/**
* @returns {FragmentId} 
*/
  fragment_id(): FragmentId;
}
/**
*/
export class UtxoWitness {
  free(): void;
/**
* @returns {Uint8Array} 
*/
  as_bytes(): Uint8Array;
/**
* @returns {string} 
*/
  to_bech32(): string;
/**
* @returns {string} 
*/
  to_hex(): string;
/**
* @param {Uint8Array} bytes 
* @returns {UtxoWitness} 
*/
  static from_bytes(bytes: Uint8Array): UtxoWitness;
/**
* @param {string} bech32_str 
* @returns {UtxoWitness} 
*/
  static from_bech32(bech32_str: string): UtxoWitness;
/**
* @param {string} input 
* @returns {UtxoWitness} 
*/
  static from_hex(input: string): UtxoWitness;
}
/**
* Type used for representing certain amount of lovelaces.
* It wraps an unsigned 64 bits number.
* Strings are used for passing to and from javascript,
* as the native javascript Number type can\'t hold the entire u64 range
* and BigInt is not yet implemented in all the browsers
*/
export class Value {
  free(): void;
/**
* Parse the given string into a rust u64 numeric type.
* @param {string} s 
* @returns {Value} 
*/
  static from_str(s: string): Value;
/**
* Return the wrapped u64 formatted as a string.
* @returns {string} 
*/
  to_str(): string;
/**
* @param {Value} other 
* @returns {Value} 
*/
  checked_add(other: Value): Value;
/**
* @param {Value} other 
* @returns {Value} 
*/
  checked_sub(other: Value): Value;
}
/**
*/
export class VrfPublicKey {
  free(): void;
/**
* @param {string} bech32_str 
* @returns {VrfPublicKey} 
*/
  static from_bech32(bech32_str: string): VrfPublicKey;
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
  free(): void;
/**
* Generate Witness for an utxo-based transaction Input
* @param {Hash} genesis_hash 
* @param {TransactionSignDataHash} transaction_id 
* @param {PrivateKey} secret_key 
* @returns {Witness} 
*/
  static for_utxo(genesis_hash: Hash, transaction_id: TransactionSignDataHash, secret_key: PrivateKey): Witness;
/**
* @param {UtxoWitness} witness 
* @returns {Witness} 
*/
  static from_external_utxo(witness: UtxoWitness): Witness;
/**
* Generate Witness for an account based transaction Input
* the account-spending-counter should be incremented on each transaction from this account
* @param {Hash} genesis_hash 
* @param {TransactionSignDataHash} transaction_id 
* @param {PrivateKey} secret_key 
* @param {SpendingCounter} account_spending_counter 
* @returns {Witness} 
*/
  static for_account(genesis_hash: Hash, transaction_id: TransactionSignDataHash, secret_key: PrivateKey, account_spending_counter: SpendingCounter): Witness;
/**
* @param {AccountWitness} witness 
* @returns {Witness} 
*/
  static from_external_account(witness: AccountWitness): Witness;
/**
* Generate Witness for an legacy utxo-based transaction Input
* @param {Hash} genesis_hash 
* @param {TransactionSignDataHash} transaction_id 
* @param {Bip32PrivateKey} secret_key 
* @returns {Witness} 
*/
  static for_legacy_utxo(genesis_hash: Hash, transaction_id: TransactionSignDataHash, secret_key: Bip32PrivateKey): Witness;
/**
* @param {Bip32PublicKey} key 
* @param {LegacyUtxoWitness} witness 
* @returns {Witness} 
*/
  static from_external_legacy_utxo(key: Bip32PublicKey, witness: LegacyUtxoWitness): Witness;
/**
* Get string representation
* @returns {string} 
*/
  to_bech32(): string;
}
/**
*/
export class Witnesses {
  free(): void;
/**
* @returns {Witnesses} 
*/
  static new(): Witnesses;
/**
* @returns {number} 
*/
  size(): number;
/**
* @param {number} index 
* @returns {Witness} 
*/
  get(index: number): Witness;
/**
* @param {Witness} item 
*/
  add(item: Witness): void;
}
