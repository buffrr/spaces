use std::collections::BTreeMap;
use bincode::{Decode, Encode};
use spacedb::db::Database;
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spacedb::tx::{ReadTransaction, WriteTransaction};
use spaces_protocol::bitcoin::OutPoint;

pub mod spaces;
pub mod ptrs;
pub mod chain;

type SpaceDb = Database<Sha256Hasher>;
type ReadTx = ReadTransaction<Sha256Hasher>;
pub type WriteTx<'db> = WriteTransaction<'db, Sha256Hasher>;
type WriteMemory = BTreeMap<Hash, Option<Vec<u8>>>;

pub struct Sha256;


#[derive(Encode, Decode)]
pub struct EncodableOutpoint(#[bincode(with_serde)] pub OutPoint);

impl From<OutPoint> for EncodableOutpoint {
    fn from(value: OutPoint) -> Self {
        Self(value)
    }
}

impl From<EncodableOutpoint> for OutPoint {
    fn from(value: EncodableOutpoint) -> Self {
        value.0
    }
}

impl spaces_protocol::hasher::KeyHasher for Sha256 {
    fn hash(data: &[u8]) -> spaces_protocol::hasher::Hash {
        Sha256Hasher::hash(data)
    }
}
