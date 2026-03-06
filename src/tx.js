import { sha256 } from "./noble-hashes/sha2.js";

import {
    bytesToHex,
    hexToBytes,
} from "./utils.js";

import {
    buildPubKeyObj,
} from "./key.js";

const chainId = hexToBytes("beeab0de00000000000000000000000000000000000000000000000000000000");

class HexBuffer {

    static from(value) {
        if (value instanceof HexBuffer) {
            return value;
        }
        else if (value instanceof Uint8Array) {
            return new HexBuffer(value);
        }
        else if (typeof value === "string") {
            return new HexBuffer(hexToBytes(value));
        }
        else {
            return new HexBuffer(new Uint8Array(value));
        }
    }
    constructor(buffer) {
        this.buffer = buffer;
    }
    toString() {
        return bytesToHex(this.buffer);
    }
    toJSON() {
        return this.toString();
    }
}

class Asset {
    constructor(amount, symbol) {
        this.amount = amount;
        this.symbol = symbol === "HIVE" ? "STEEM" : symbol === "HBD" ? "SBD" : symbol;
    }

    static fromString(string, expectedSymbol = null) {
        const [amountString, symbol] = string.split(" ");
        if (["STEEM", "VESTS", "SBD", "TESTS", "TBD", "HIVE", "HBD"].indexOf(symbol) === -1) {
            throw new Error(`Invalid asset symbol: ${symbol}`);
        }
        if (expectedSymbol && symbol !== expectedSymbol) {
            throw new Error(`Invalid asset, expected symbol: ${expectedSymbol} got: ${symbol}`);
        }
        const amount = Number.parseFloat(amountString);
        if (!Number.isFinite(amount)) {
            throw new Error(`Invalid asset amount: ${amountString}`);
        }
        return new Asset(amount, symbol);
    }

    static from(value, symbol) {
        if (value instanceof Asset) {
            if (symbol && value.symbol !== symbol) {
                throw new Error(`Invalid asset, expected symbol: ${symbol} got: ${value.symbol}`);
            }
            return value;
        }
        else if (typeof value === "number" && Number.isFinite(value)) {
            return new Asset(value, symbol || "STEEM");
        }
        else if (typeof value === "string") {
            return Asset.fromString(value, symbol);
        }
        else {
            throw new Error(`Invalid asset "${String(value)}"`);
        }
    }

    getPrecision() {
        switch (this.symbol) {
            case "TESTS":
            case "TBD":
            case "STEEM":
            case "SBD":
            case "HBD":
            case "HIVE":
                return 3;
            case "VESTS":
                return 6;
            default:
                return 3;
        }
    }

    toString() {
        return `${this.amount.toFixed(this.getPrecision())} ${this.symbol}`;
    }
    toJSON() {
        return this.toString();
    }
}

const OPERATION_IDS = {
    vote: 0,
    comment: 1,
    transfer: 2,
    transfer_to_vesting: 3,
    withdraw_vesting: 4,
    limit_order_create: 5,
    limit_order_cancel: 6,
    feed_publish: 7,
    convert: 8,
    account_create: 9,
    account_update: 10,
    witness_update: 11,
    account_witness_vote: 12,
    account_witness_proxy: 13,

    custom: 15,

    delete_comment: 17,
    custom_json: 18,
    comment_options: 19,
    set_withdraw_vesting_route: 20,
    limit_order_create2: 21,
    claim_account: 22,
    create_claimed_account: 23,
    request_account_recovery: 24,
    recover_account: 25,
    change_recovery_account: 26,
    escrow_transfer: 27,
    escrow_dispute: 28,
    escrow_release: 29,

    escrow_approve: 31,
    transfer_to_savings: 32,
    transfer_from_savings: 33,
    cancel_transfer_from_savings: 34,

    decline_voting_rights: 36,
    reset_account: 37,
    set_reset_account: 38,
    claim_reward_balance: 39,
    delegate_vesting_shares: 40,
    account_create_with_delegation: 41,
    witness_set_properties: 42,
    account_update2: 43,
    create_proposal: 44,
    update_proposal_votes: 45,
    remove_proposal: 46,
    update_proposal: 47,
    collateralized_convert: 48,
    recurrent_transfer: 49
};
const VoidSerializer = () => {
    throw new Error("Void can not be serialized");
};
const StringSerializer = (buffer, data) => {
    buffer.writeVString(data);
};
const Int8Serializer = (buffer, data) => {
    buffer.writeInt8(data);
};
const Int16Serializer = (buffer, data) => {
    buffer.writeInt16(data);
};
const Int32Serializer = (buffer, data) => {
    buffer.writeInt32(data);
};
const Int64Serializer = (buffer, data) => {
    buffer.writeInt64(data);
};
const UInt8Serializer = (buffer, data) => {
    buffer.writeUint8(data);
};
const UInt16Serializer = (buffer, data) => {
    buffer.writeUint16(data);
};
const UInt32Serializer = (buffer, data) => {
    buffer.writeUint32(data);
};
const UInt64Serializer = (buffer, data) => {
    buffer.writeUint64(data);
};
const BooleanSerializer = (buffer, data) => {
    buffer.writeByte(data ? 1 : 0);
};
const StaticVariantSerializer = (itemSerializers) => {

    return (buffer, data) => {
        const [id, item] = data;
        buffer.writeVarint32(id);
        itemSerializers[id](buffer, item);
    };
};

const AssetSerializer = (buffer, data) => {
    const asset = Asset.from(data);
    const precision = asset.getPrecision();
    buffer.writeInt64(Math.round(asset.amount * Math.pow(10, precision)));
    buffer.writeUint8(precision);
    for (let i = 0; i < 7; i++) {
        buffer.writeUint8(asset.symbol.charCodeAt(i) || 0);
    }
};
const DateSerializer = (buffer, data) => {
    buffer.writeUint32(Math.floor(new Date(data + "Z").getTime() / 1000));
};
const PublicKeySerializer = (buffer, data) => {
    if (data === null ||
        (typeof data === "string" && data.slice(-39) === "1111111111111111111111111111111114T1Anm")) {
        buffer.append(new Uint8Array(33).fill(0));
    }
    else {
        buffer.append(buildPubKeyObj(data).key);
    }
};
const BinarySerializer = (size = null) => {
    return (buffer, data) => {
        data = HexBuffer.from(data);
        const len = data.buffer.length;
        if (size) {
            if (len !== size) {
                throw new Error(`Unable to serialize binary. Expected ${size} bytes, got ${len}`);
            }
        }
        else {
            buffer.writeVarint32(len);
        }
        buffer.append(data.buffer);
    };
};
const VariableBinarySerializer = BinarySerializer();
const FlatMapSerializer = (keySerializer, valueSerializer) => {
    return (buffer, data) => {
        buffer.writeVarint32(data.length);
        for (const [key, value] of data) {
            keySerializer(buffer, key);
            valueSerializer(buffer, value);
        }
    };
};
const ArraySerializer = (itemSerializer) => {
    return (buffer, data) => {
        buffer.writeVarint32(data.length);
        for (const item of data) {
            itemSerializer(buffer, item);
        }
    };
};
const ObjectSerializer = (keySerializers) => {
    return (buffer, data) => {
        for (const [key, serializer] of keySerializers) {
            try {
                serializer(buffer, data[key]);
            }
            catch (error) {
                error.message = `${key}: ${error.message}`;
                throw error;
            }
        }
    };
};
const OptionalSerializer = (valueSerializer) => {
    return (buffer, data) => {
        if (data !== undefined) {
            buffer.writeByte(1);
            valueSerializer(buffer, data);
        }
        else {
            buffer.writeByte(0);
        }
    };
};
const AuthoritySerializer = ObjectSerializer([
    ["weight_threshold", UInt32Serializer],
    ["account_auths", FlatMapSerializer(StringSerializer, UInt16Serializer)],
    ["key_auths", FlatMapSerializer(PublicKeySerializer, UInt16Serializer)]
]);
const BeneficiarySerializer = ObjectSerializer([
    ["account", StringSerializer],
    ["weight", UInt16Serializer]
]);
const PriceSerializer = ObjectSerializer([
    ["base", AssetSerializer],
    ["quote", AssetSerializer]
]);

const ChainPropertiesSerializer = ObjectSerializer([
    ["account_creation_fee", AssetSerializer],
    ["maximum_block_size", UInt32Serializer],
    ["hbd_interest_rate", UInt16Serializer]
]);
const OperationDataSerializer = (operationId, definitions) => {
    const objectSerializer = ObjectSerializer(definitions);
    return (buffer, data) => {
        buffer.writeVarint32(operationId);
        objectSerializer(buffer, data);
    };
};
const OperationSerializers = {};
OperationSerializers.account_create = OperationDataSerializer(OPERATION_IDS.account_create, [
    ["fee", AssetSerializer],
    ["creator", StringSerializer],
    ["new_account_name", StringSerializer],
    ["owner", AuthoritySerializer],
    ["active", AuthoritySerializer],
    ["posting", AuthoritySerializer],
    ["memo_key", PublicKeySerializer],
    ["json_metadata", StringSerializer]
]);
OperationSerializers.account_create_with_delegation = OperationDataSerializer(OPERATION_IDS.account_create_with_delegation, [
    ["fee", AssetSerializer],
    ["delegation", AssetSerializer],
    ["creator", StringSerializer],
    ["new_account_name", StringSerializer],
    ["owner", AuthoritySerializer],
    ["active", AuthoritySerializer],
    ["posting", AuthoritySerializer],
    ["memo_key", PublicKeySerializer],
    ["json_metadata", StringSerializer],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
OperationSerializers.account_update = OperationDataSerializer(OPERATION_IDS.account_update, [
    ["account", StringSerializer],
    ["owner", OptionalSerializer(AuthoritySerializer)],
    ["active", OptionalSerializer(AuthoritySerializer)],
    ["posting", OptionalSerializer(AuthoritySerializer)],
    ["memo_key", PublicKeySerializer],
    ["json_metadata", StringSerializer]
]);
OperationSerializers.account_witness_proxy = OperationDataSerializer(OPERATION_IDS.account_witness_proxy, [
    ["account", StringSerializer],
    ["proxy", StringSerializer]
]);
OperationSerializers.account_witness_vote = OperationDataSerializer(OPERATION_IDS.account_witness_vote, [
    ["account", StringSerializer],
    ["witness", StringSerializer],
    ["approve", BooleanSerializer]
]);
OperationSerializers.cancel_transfer_from_savings = OperationDataSerializer(OPERATION_IDS.cancel_transfer_from_savings, [
    ["from", StringSerializer],
    ["request_id", UInt32Serializer]
]);
OperationSerializers.change_recovery_account = OperationDataSerializer(OPERATION_IDS.change_recovery_account, [
    ["account_to_recover", StringSerializer],
    ["new_recovery_account", StringSerializer],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
OperationSerializers.claim_account = OperationDataSerializer(OPERATION_IDS.claim_account, [
    ["creator", StringSerializer],
    ["fee", AssetSerializer],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
OperationSerializers.claim_reward_balance = OperationDataSerializer(OPERATION_IDS.claim_reward_balance, [
    ["account", StringSerializer],
    ["reward_hive", AssetSerializer],
    ["reward_hbd", AssetSerializer],
    ["reward_vests", AssetSerializer]
]);
OperationSerializers.comment = OperationDataSerializer(OPERATION_IDS.comment, [
    ["parent_author", StringSerializer],
    ["parent_permlink", StringSerializer],
    ["author", StringSerializer],
    ["permlink", StringSerializer],
    ["title", StringSerializer],
    ["body", StringSerializer],
    ["json_metadata", StringSerializer]
]);
OperationSerializers.comment_options = OperationDataSerializer(OPERATION_IDS.comment_options, [
    ["author", StringSerializer],
    ["permlink", StringSerializer],
    ["max_accepted_payout", AssetSerializer],
    ["percent_hbd", UInt16Serializer],
    ["allow_votes", BooleanSerializer],
    ["allow_curation_rewards", BooleanSerializer],
    [
        "extensions",
        ArraySerializer(StaticVariantSerializer([
            ObjectSerializer([["beneficiaries", ArraySerializer(BeneficiarySerializer)]])
        ]))
    ]
]);
OperationSerializers.convert = OperationDataSerializer(OPERATION_IDS.convert, [
    ["owner", StringSerializer],
    ["requestid", UInt32Serializer],
    ["amount", AssetSerializer]
]);
OperationSerializers.create_claimed_account = OperationDataSerializer(OPERATION_IDS.create_claimed_account, [
    ["creator", StringSerializer],
    ["new_account_name", StringSerializer],
    ["owner", AuthoritySerializer],
    ["active", AuthoritySerializer],
    ["posting", AuthoritySerializer],
    ["memo_key", PublicKeySerializer],
    ["json_metadata", StringSerializer],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
OperationSerializers.custom = OperationDataSerializer(OPERATION_IDS.custom, [
    ["required_auths", ArraySerializer(StringSerializer)],
    ["id", UInt16Serializer],
    ["data", VariableBinarySerializer]
]);

OperationSerializers.custom_json = OperationDataSerializer(OPERATION_IDS.custom_json, [
    ["required_auths", ArraySerializer(StringSerializer)],
    ["required_posting_auths", ArraySerializer(StringSerializer)],
    ["id", StringSerializer],
    ["json", StringSerializer]
]);
OperationSerializers.decline_voting_rights = OperationDataSerializer(OPERATION_IDS.decline_voting_rights, [
    ["account", StringSerializer],
    ["decline", BooleanSerializer]
]);
OperationSerializers.delegate_vesting_shares = OperationDataSerializer(OPERATION_IDS.delegate_vesting_shares, [
    ["delegator", StringSerializer],
    ["delegatee", StringSerializer],
    ["vesting_shares", AssetSerializer]
]);
OperationSerializers.delete_comment = OperationDataSerializer(OPERATION_IDS.delete_comment, [
    ["author", StringSerializer],
    ["permlink", StringSerializer]
]);
OperationSerializers.escrow_approve = OperationDataSerializer(OPERATION_IDS.escrow_approve, [
    ["from", StringSerializer],
    ["to", StringSerializer],
    ["agent", StringSerializer],
    ["who", StringSerializer],
    ["escrow_id", UInt32Serializer],
    ["approve", BooleanSerializer]
]);
OperationSerializers.escrow_dispute = OperationDataSerializer(OPERATION_IDS.escrow_dispute, [
    ["from", StringSerializer],
    ["to", StringSerializer],
    ["agent", StringSerializer],
    ["who", StringSerializer],
    ["escrow_id", UInt32Serializer]
]);
OperationSerializers.escrow_release = OperationDataSerializer(OPERATION_IDS.escrow_release, [
    ["from", StringSerializer],
    ["to", StringSerializer],
    ["agent", StringSerializer],
    ["who", StringSerializer],
    ["receiver", StringSerializer],
    ["escrow_id", UInt32Serializer],
    ["hbd_amount", AssetSerializer],
    ["hive_amount", AssetSerializer]
]);
OperationSerializers.escrow_transfer = OperationDataSerializer(OPERATION_IDS.escrow_transfer, [
    ["from", StringSerializer],
    ["to", StringSerializer],
    ["hbd_amount", AssetSerializer],
    ["hive_amount", AssetSerializer],
    ["escrow_id", UInt32Serializer],
    ["agent", StringSerializer],
    ["fee", AssetSerializer],
    ["json_meta", StringSerializer],
    ["ratification_deadline", DateSerializer],
    ["escrow_expiration", DateSerializer]
]);
OperationSerializers.feed_publish = OperationDataSerializer(OPERATION_IDS.feed_publish, [
    ["publisher", StringSerializer],
    ["exchange_rate", PriceSerializer]
]);
OperationSerializers.limit_order_cancel = OperationDataSerializer(OPERATION_IDS.limit_order_cancel, [
    ["owner", StringSerializer],
    ["orderid", UInt32Serializer]
]);
OperationSerializers.limit_order_create = OperationDataSerializer(OPERATION_IDS.limit_order_create, [
    ["owner", StringSerializer],
    ["orderid", UInt32Serializer],
    ["amount_to_sell", AssetSerializer],
    ["min_to_receive", AssetSerializer],
    ["fill_or_kill", BooleanSerializer],
    ["expiration", DateSerializer]
]);
OperationSerializers.limit_order_create2 = OperationDataSerializer(OPERATION_IDS.limit_order_create2, [
    ["owner", StringSerializer],
    ["orderid", UInt32Serializer],
    ["amount_to_sell", AssetSerializer],
    ["exchange_rate", PriceSerializer],
    ["fill_or_kill", BooleanSerializer],
    ["expiration", DateSerializer]
]);
OperationSerializers.recover_account = OperationDataSerializer(OPERATION_IDS.recover_account, [
    ["account_to_recover", StringSerializer],
    ["new_owner_authority", AuthoritySerializer],
    ["recent_owner_authority", AuthoritySerializer],
    ["extensions", ArraySerializer(VoidSerializer)]
]);

OperationSerializers.request_account_recovery = OperationDataSerializer(OPERATION_IDS.request_account_recovery, [
    ["recovery_account", StringSerializer],
    ["account_to_recover", StringSerializer],
    ["new_owner_authority", AuthoritySerializer],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
OperationSerializers.reset_account = OperationDataSerializer(OPERATION_IDS.reset_account, [
    ["reset_account", StringSerializer],
    ["account_to_reset", StringSerializer],
    ["new_owner_authority", AuthoritySerializer]
]);
OperationSerializers.set_reset_account = OperationDataSerializer(OPERATION_IDS.set_reset_account, [
    ["account", StringSerializer],
    ["current_reset_account", StringSerializer],
    ["reset_account", StringSerializer]
]);
OperationSerializers.set_withdraw_vesting_route = OperationDataSerializer(OPERATION_IDS.set_withdraw_vesting_route, [
    ["from_account", StringSerializer],
    ["to_account", StringSerializer],
    ["percent", UInt16Serializer],
    ["auto_vest", BooleanSerializer]
]);
OperationSerializers.transfer = OperationDataSerializer(OPERATION_IDS.transfer, [
    ["from", StringSerializer],
    ["to", StringSerializer],
    ["amount", AssetSerializer],
    ["memo", StringSerializer]
]);
OperationSerializers.transfer_from_savings = OperationDataSerializer(OPERATION_IDS.transfer_from_savings, [
    ["from", StringSerializer],
    ["request_id", UInt32Serializer],
    ["to", StringSerializer],
    ["amount", AssetSerializer],
    ["memo", StringSerializer]
]);
OperationSerializers.transfer_to_savings = OperationDataSerializer(OPERATION_IDS.transfer_to_savings, [
    ["from", StringSerializer],
    ["to", StringSerializer],
    ["amount", AssetSerializer],
    ["memo", StringSerializer]
]);
OperationSerializers.transfer_to_vesting = OperationDataSerializer(OPERATION_IDS.transfer_to_vesting, [
    ["from", StringSerializer],
    ["to", StringSerializer],
    ["amount", AssetSerializer]
]);
OperationSerializers.vote = OperationDataSerializer(OPERATION_IDS.vote, [
    ["voter", StringSerializer],
    ["author", StringSerializer],
    ["permlink", StringSerializer],
    ["weight", Int16Serializer]
]);
OperationSerializers.withdraw_vesting = OperationDataSerializer(OPERATION_IDS.withdraw_vesting, [
    ["account", StringSerializer],
    ["vesting_shares", AssetSerializer]
]);
OperationSerializers.witness_update = OperationDataSerializer(OPERATION_IDS.witness_update, [
    ["owner", StringSerializer],
    ["url", StringSerializer],
    ["block_signing_key", PublicKeySerializer],
    ["props", ChainPropertiesSerializer],
    ["fee", AssetSerializer]
]);
OperationSerializers.witness_set_properties = OperationDataSerializer(OPERATION_IDS.witness_set_properties, [
    ["owner", StringSerializer],
    ["props", FlatMapSerializer(StringSerializer, VariableBinarySerializer)],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
OperationSerializers.account_update2 = OperationDataSerializer(OPERATION_IDS.account_update2, [
    ["account", StringSerializer],
    ["owner", OptionalSerializer(AuthoritySerializer)],
    ["active", OptionalSerializer(AuthoritySerializer)],
    ["posting", OptionalSerializer(AuthoritySerializer)],
    ["memo_key", OptionalSerializer(PublicKeySerializer)],
    ["json_metadata", StringSerializer],
    ["posting_json_metadata", StringSerializer],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
OperationSerializers.create_proposal = OperationDataSerializer(OPERATION_IDS.create_proposal, [
    ["creator", StringSerializer],
    ["receiver", StringSerializer],
    ["start_date", DateSerializer],
    ["end_date", DateSerializer],
    ["daily_pay", AssetSerializer],
    ["subject", StringSerializer],
    ["permlink", StringSerializer],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
OperationSerializers.update_proposal_votes = OperationDataSerializer(OPERATION_IDS.update_proposal_votes, [
    ["voter", StringSerializer],
    ["proposal_ids", ArraySerializer(Int64Serializer)],
    ["approve", BooleanSerializer],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
OperationSerializers.remove_proposal = OperationDataSerializer(OPERATION_IDS.remove_proposal, [
    ["proposal_owner", StringSerializer],
    ["proposal_ids", ArraySerializer(Int64Serializer)],
    ["extensions", ArraySerializer(VoidSerializer)]
]);
const ProposalUpdateSerializer = ObjectSerializer([["end_date", DateSerializer]]);
OperationSerializers.update_proposal = OperationDataSerializer(OPERATION_IDS.update_proposal, [
    ["proposal_id", UInt64Serializer],
    ["creator", StringSerializer],
    ["daily_pay", AssetSerializer],
    ["subject", StringSerializer],
    ["permlink", StringSerializer],
    [
        "extensions",
        ArraySerializer(StaticVariantSerializer([VoidSerializer, ProposalUpdateSerializer]))
    ]
]);
OperationSerializers.collateralized_convert = OperationDataSerializer(OPERATION_IDS.collateralized_convert, [
    ["owner", StringSerializer],
    ["requestid", UInt32Serializer],
    ["amount", AssetSerializer]
]);
OperationSerializers.recurrent_transfer = OperationDataSerializer(OPERATION_IDS.recurrent_transfer, [
    ["from", StringSerializer],
    ["to", StringSerializer],
    ["amount", AssetSerializer],
    ["memo", StringSerializer],
    ["recurrence", UInt16Serializer],
    ["executions", UInt16Serializer],
    [
        "extensions",
        ArraySerializer(ObjectSerializer([
            ["type", UInt8Serializer],
            ["value", ObjectSerializer([["pair_id", UInt8Serializer]])]
        ]))
    ]
]);
const OperationSerializer = (buffer, operation) => {
    const serializer = OperationSerializers[operation[0]];
    if (!serializer) {
        throw new Error(`No serializer for operation: ${operation[0]}`);
    }
    try {
        serializer(buffer, operation[1]);
    }
    catch (error) {
        error.message = `${operation[0]}: ${error.message}`;
        throw error;
    }
};
const TransactionSerializer = ObjectSerializer([
    ["ref_block_num", UInt16Serializer],
    ["ref_block_prefix", UInt32Serializer],
    ["expiration", DateSerializer],
    ["operations", ArraySerializer(OperationSerializer)],
    ["extensions", ArraySerializer(StringSerializer)]
]);
const EncryptedMemoSerializer = ObjectSerializer([
    ["from", PublicKeySerializer],
    ["to", PublicKeySerializer],
    ["nonce", UInt64Serializer],
    ["check", UInt32Serializer],
    ["encrypted", BinarySerializer()]
]);
const Serializer = {

    Asset: AssetSerializer,

    Memo: EncryptedMemoSerializer,

    Price: PriceSerializer,
    PublicKey: PublicKeySerializer,

    String: StringSerializer,
    Transaction: TransactionSerializer,
    UInt16: UInt16Serializer,
    UInt32: UInt32Serializer

};

const EMPTY_BUFFER = new ArrayBuffer(0);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
class ByteBuffer {
    constructor(capacity = ByteBuffer.DEFAULT_CAPACITY, littleEndian = ByteBuffer.DEFAULT_ENDIAN) {
        this.readUInt32 = this.readUint32;
        this.buffer = capacity === 0 ? EMPTY_BUFFER : new ArrayBuffer(capacity);
        this.view = capacity === 0 ? new DataView(EMPTY_BUFFER) : new DataView(this.buffer);
        this.offset = 0;
        this.markedOffset = -1;
        this.limit = capacity;
        this.littleEndian = littleEndian;
    }
    static allocate(capacity, littleEndian) {
        return new ByteBuffer(capacity, littleEndian);
    }
    static concat(buffers, littleEndian) {
        let capacity = 0;
        for (let i = 0; i < buffers.length; ++i) {
            const buf = buffers[i];
            if (buf instanceof ByteBuffer) {
                capacity += buf.limit - buf.offset;
            }
            else if (buf instanceof Uint8Array) {
                capacity += buf.length;
            }
            else if (buf instanceof ArrayBuffer) {
                capacity += buf.byteLength;
            }
            else if (Array.isArray(buf)) {
                capacity += buf.length;
            }
            else {
                throw TypeError("Illegal buffer");
            }
        }
        if (capacity === 0) {
            return new ByteBuffer(0, littleEndian);
        }
        const bb = new ByteBuffer(capacity, littleEndian);
        const view = new Uint8Array(bb.buffer);
        let offset = 0;
        for (let i = 0; i < buffers.length; ++i) {
            let buf = buffers[i];
            if (buf instanceof ByteBuffer) {
                view.set(new Uint8Array(buf.buffer, buf.offset, buf.limit - buf.offset), offset);
                offset += buf.limit - buf.offset;
            }
            else if (buf instanceof Uint8Array) {
                view.set(buf, offset);
                offset += buf.length;
            }
            else if (buf instanceof ArrayBuffer) {
                view.set(new Uint8Array(buf), offset);
                offset += buf.byteLength;
            }
            else {

                view.set(buf, offset);
                offset += buf.length;
            }
        }
        bb.limit = bb.offset = offset;
        bb.offset = 0;
        return bb;
    }
    static wrap(buffer, littleEndian) {
        if (buffer instanceof ByteBuffer) {
            const bb = buffer.clone();
            bb.markedOffset = -1;
            return bb;
        }
        let bb;
        if (buffer instanceof Uint8Array) {
            bb = new ByteBuffer(0, littleEndian);
            if (buffer.length > 0) {
                bb.buffer = buffer.buffer;
                bb.offset = buffer.byteOffset;
                bb.limit = buffer.byteOffset + buffer.byteLength;
                bb.view = new DataView(buffer.buffer);
            }
        }
        else if (buffer instanceof ArrayBuffer) {
            bb = new ByteBuffer(0, littleEndian);
            if (buffer.byteLength > 0) {
                bb.buffer = buffer;
                bb.offset = 0;
                bb.limit = buffer.byteLength;
                bb.view = buffer.byteLength > 0 ? new DataView(buffer) : new DataView(EMPTY_BUFFER);
            }
        }
        else if (Array.isArray(buffer)) {
            bb = new ByteBuffer(buffer.length, littleEndian);
            bb.limit = buffer.length;
            new Uint8Array(bb.buffer).set(buffer);
        }
        else {
            throw TypeError("Illegal buffer");
        }
        return bb;
    }
    writeBytes(source, offset) {
        return this.append(source, offset);
    }
    writeInt8(value, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        if (offset + 1 > this.buffer.byteLength) {
            this.resize(offset + 1);
        }
        this.view.setInt8(offset, value);
        if (relative)
            this.offset += 1;
        return this;
    }
    writeByte(value, offset) {
        return this.writeInt8(value, offset);
    }
    writeUint8(value, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        if (offset + 1 > this.buffer.byteLength) {
            this.resize(offset + 1);
        }
        this.view.setUint8(offset, value);
        if (relative)
            this.offset += 1;
        return this;
    }
    writeUInt8(value, offset) {
        return this.writeUint8(value, offset);
    }
    readUint8(offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        const value = this.view.getUint8(offset);
        if (relative)
            this.offset += 1;
        return value;
    }
    readUInt8(offset) {
        return this.readUint8(offset);
    }
    writeInt16(value, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        if (offset + 2 > this.buffer.byteLength) {
            this.resize(offset + 2);
        }
        this.view.setInt16(offset, value, this.littleEndian);
        if (relative)
            this.offset += 2;
        return this;
    }
    writeShort(value, offset) {
        return this.writeInt16(value, offset);
    }
    writeUint16(value, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        if (offset + 2 > this.buffer.byteLength) {
            this.resize(offset + 2);
        }
        this.view.setUint16(offset, value, this.littleEndian);
        if (relative)
            this.offset += 2;
        return this;
    }
    writeUInt16(value, offset) {
        return this.writeUint16(value, offset);
    }
    writeInt32(value, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        if (offset + 4 > this.buffer.byteLength) {
            this.resize(offset + 4);
        }
        this.view.setInt32(offset, value, this.littleEndian);
        if (relative)
            this.offset += 4;
        return this;
    }
    writeInt(value, offset) {
        return this.writeInt32(value, offset);
    }
    writeUint32(value, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        if (offset + 4 > this.buffer.byteLength) {
            this.resize(offset + 4);
        }
        this.view.setUint32(offset, value, this.littleEndian);
        if (relative)
            this.offset += 4;
        return this;
    }
    writeUInt32(value, offset) {
        return this.writeUint32(value, offset);
    }
    readUint32(offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        const value = this.view.getUint32(offset, this.littleEndian);
        if (relative) {
            this.offset += 4;
        }
        return value;
    }
    append(source, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        let src;
        if (source instanceof ByteBuffer) {
            src = new Uint8Array(source.buffer, source.offset, source.limit - source.offset);
            source.offset += src.length;
        }
        else if (source instanceof Uint8Array) {
            src = source;
        }
        else if (source instanceof ArrayBuffer) {
            src = new Uint8Array(source);
        }
        else {
            src = new Uint8Array(source);
        }
        if (src.length <= 0)
            return this;
        if (offset + src.length > this.buffer.byteLength) {
            this.resize(offset + src.length);
        }
        new Uint8Array(this.buffer).set(src, offset);
        if (relative)
            this.offset += src.length;
        return this;
    }
    clone(copy) {
        const bb = new ByteBuffer(0, this.littleEndian);
        if (copy) {
            bb.buffer = new ArrayBuffer(this.buffer.byteLength);
            new Uint8Array(bb.buffer).set(new Uint8Array(this.buffer));
            bb.view = new DataView(bb.buffer);
        }
        else {
            bb.buffer = this.buffer;
            bb.view = this.view;
        }
        bb.offset = this.offset;
        bb.markedOffset = this.markedOffset;
        bb.limit = this.limit;
        return bb;
    }
    copy(begin, end) {
        if (begin === undefined)
            begin = this.offset;
        if (end === undefined)
            end = this.limit;
        if (begin === end) {
            return new ByteBuffer(0, this.littleEndian);
        }
        const capacity = end - begin;
        const bb = new ByteBuffer(capacity, this.littleEndian);
        bb.offset = 0;
        bb.limit = capacity;
        new Uint8Array(bb.buffer).set(new Uint8Array(this.buffer).subarray(begin, end), 0);
        return bb;
    }
    copyTo(target, targetOffset, sourceOffset, sourceLimit) {
        const targetRelative = typeof targetOffset === "undefined";
        const relative = typeof sourceOffset === "undefined";
        targetOffset = targetRelative ? target.offset : targetOffset;
        sourceOffset = relative ? this.offset : sourceOffset;
        sourceLimit = sourceLimit === undefined ? this.limit : sourceLimit;
        const len = sourceLimit - sourceOffset;
        if (len === 0)
            return target;
        target.ensureCapacity(targetOffset + len);
        new Uint8Array(target.buffer).set(new Uint8Array(this.buffer).subarray(sourceOffset, sourceLimit), targetOffset);
        if (relative)
            this.offset += len;
        if (targetRelative)
            target.offset += len;
        return this;
    }
    ensureCapacity(capacity) {
        let current = this.buffer.byteLength;
        if (current < capacity) {
            return this.resize((current *= 2) > capacity ? current : capacity);
        }
        return this;
    }
    flip() {
        this.limit = this.offset;
        this.offset = 0;
        return this;
    }
    resize(capacity) {
        if (this.buffer.byteLength < capacity) {
            const buffer = new ArrayBuffer(capacity);
            new Uint8Array(buffer).set(new Uint8Array(this.buffer));
            this.buffer = buffer;
            this.view = new DataView(buffer);
        }
        return this;
    }
    skip(length) {
        this.offset += length;
        return this;
    }
    writeInt64(value, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        if (typeof value === "number")
            value = BigInt(value);
        if (offset + 8 > this.buffer.byteLength) {
            this.resize(offset + 8);
        }
        this.view.setBigInt64(offset, value, this.littleEndian);
        if (relative)
            this.offset += 8;
        return this;
    }
    writeLong(value, offset) {
        return this.writeInt64(value, offset);
    }
    readInt64(offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        const value = this.view.getBigInt64(offset, this.littleEndian);
        if (relative)
            this.offset += 8;
        return value;
    }
    readLong(offset) {
        return this.readInt64(offset);
    }
    writeUint64(value, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        if (typeof value === "number")
            value = BigInt(value);
        if (offset + 8 > this.buffer.byteLength) {
            this.resize(offset + 8);
        }
        this.view.setBigUint64(offset, value, this.littleEndian);
        if (relative)
            this.offset += 8;
        return this;
    }
    writeUInt64(value, offset) {
        return this.writeUint64(value, offset);
    }
    readUint64(offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        const value = this.view.getBigUint64(offset, this.littleEndian);
        if (relative)
            this.offset += 8;
        return value;
    }
    readUInt64(offset) {
        return this.readUint64(offset);
    }
    toBuffer(forceCopy) {
        const offset = this.offset;
        const limit = this.limit;
        if (!forceCopy && offset === 0 && limit === this.buffer.byteLength) {
            return this.buffer;
        }
        if (offset === limit)
            return EMPTY_BUFFER;
        return this.buffer.slice(offset, limit);
    }
    toArrayBuffer(forceCopy) {
        return this.toBuffer(forceCopy);
    }
    writeVarint32(value, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        const size = this.calculateVarint32(value);
        if (offset + size > this.buffer.byteLength) {
            this.resize(offset + size);
        }
        value >>>= 0;
        while (value >= 0x80) {
            this.view.setUint8(offset++, (value & 0x7f) | 0x80);
            value >>>= 7;
        }
        this.view.setUint8(offset++, value);
        if (relative) {
            this.offset = offset;
            return this;
        }
        return size;
    }
    readVarint32(offset) {
        const relative = typeof offset === "undefined";
        if (typeof offset === "undefined") {
            offset = this.offset;
        }
        let c = 0;
        let value = 0 >>> 0;
        let b;
        do {
            b = this.view.getUint8(offset++);
            if (c < 5) {
                value |= (b & 0x7f) << (7 * c);
            }
            ++c;
        } while ((b & 0x80) !== 0);
        value |= 0;
        if (relative) {
            this.offset = offset;
            return value;
        }
        return { value, length: c };
    }
    calculateVarint32(value) {
        value = value >>> 0;
        if (value < 1 << 7)
            return 1;
        else if (value < 1 << 14)
            return 2;
        else if (value < 1 << 21)
            return 3;
        else if (value < 1 << 28)
            return 4;
        else
            return 5;
    }
    writeVString(str, offset) {
        const relative = typeof offset === "undefined";
        let currentOffset = relative ? this.offset : offset;
        const encoded = textEncoder.encode(str);
        const len = encoded.length;
        const lenVarintSize = this.calculateVarint32(len);
        if (currentOffset + lenVarintSize + len > this.buffer.byteLength) {
            this.resize(currentOffset + lenVarintSize + len);
        }
        this.writeVarint32(len, currentOffset);
        currentOffset += lenVarintSize;
        new Uint8Array(this.buffer).set(encoded, currentOffset);
        currentOffset += len;
        if (relative) {
            this.offset = currentOffset;
            return this;
        }
        return currentOffset - (offset || 0);
    }
    readVString(offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;
        const start = offset;
        const lenResult = this.readVarint32(offset);
        const lenValue = lenResult.value;
        const lenLength = lenResult.length;
        offset += lenLength;

        const str = textDecoder.decode(new Uint8Array(this.buffer, offset, lenValue));
        offset += lenValue;
        if (relative) {
            this.offset = offset;
            return str;
        }
        else {
            return {
                string: str,
                length: offset - start
            };
        }
    }
    readUTF8String(length, offset) {
        const relative = typeof offset === "undefined";
        if (relative)
            offset = this.offset;
        else
            offset = offset;

        const str = textDecoder.decode(new Uint8Array(this.buffer, offset, length));
        if (relative) {
            this.offset += length;
            return str;
        }
        else {
            return {
                string: str,
                length
            };
        }
    }
}
ByteBuffer.LITTLE_ENDIAN = true;
ByteBuffer.BIG_ENDIAN = false;
ByteBuffer.DEFAULT_CAPACITY = 16;
ByteBuffer.DEFAULT_ENDIAN = ByteBuffer.BIG_ENDIAN;

export class Transaction {
    constructor(props, expiration = 60000) {

        if (!props) {
            throw new Error(`"props" is required for transaction construction`);
        }
        this.expiration = expiration;
        const bytes = hexToBytes(props.head_block_id);
        const refBlockPrefix = Number(new Uint32Array(bytes.buffer, bytes.byteOffset + 4, 1)[0]);
        const expirationIso = new Date(Date.now() + this.expiration).toISOString().slice(0, -5);
        this.transaction = {
            expiration: expirationIso,
            extensions: [],
            operations: [],
            ref_block_num: props.head_block_number & 0xffff,
            ref_block_prefix: refBlockPrefix,
            signatures: [],
        };
    }

    addOperation(operation) {
        this.transaction.operations.push(operation);
    }

    digest() {
        if (!this.transaction?.operations) {
            throw new Error(`First add an operation with .addOperation()`);
        }
        const buffer = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
        const temp = { ...this.transaction };
        try {
            Serializer.Transaction(buffer, temp);
        }
        catch (cause) {
            throw new Error("Unable to serialize transaction: " + cause);
        }
        buffer.flip();
        const transactionData = new Uint8Array(buffer.toBuffer());
        const txId = bytesToHex(sha256(transactionData)).slice(0, 40);
        const digest = sha256(new Uint8Array([...chainId, ...transactionData]));
        return { digest, txId };
    }

    sign(keys) {
        if (!this.transaction?.operations) {
            throw new Error(`First add an operation with .addOperation()`);
        }
        const { digest, txId } = this.digest();
        if (!Array.isArray(keys)) {
            keys = [keys];
        }
        for (const key of keys) {
            const signature = key.sign(digest);
            this.transaction.signatures.push(signature.customToString());
        }
        this.txId = txId;
        return this.transaction;
    }

    addSignature(signature) {
        if (!this.transaction?.operations) {
            throw new Error(`First add an operation with .addOperation()`);
        }
        if (typeof signature !== "string") {
            throw new Error("Signature must be string");
        }
        if (signature.length !== 130) {
            throw new Error("Signature must be 130 characters long");
        }
        this.transaction.signatures.push(signature);
        return this.transaction;
    }
}
