from construct import (
    Byte,
    Bytes,
    Enum,
    GreedyBytes,
    GreedyRange,
    Int16ub,
    Int24ub,
    Int64ub,
    Struct,
    Terminated,
    this,
)

MerkleTreeHeader = Struct(
    "Version" / Byte,
    "MerkleLeafType" / Byte,
    "Timestamp" / Int64ub,
    "LogEntryType" / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry" / GreedyBytes,
)

Certificate = Struct("Length" / Int24ub, "CertData" / Bytes(this.Length))

CertificateChain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(Certificate),
)

PreCertEntry = Struct("LeafCert" / Certificate, "ChainData" / CertificateChain, Terminated)
