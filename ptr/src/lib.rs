#[cfg(feature = "std")]
pub mod sptr;
pub mod constants;

use std::collections::BTreeMap;
#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::{OP_PUSHBYTES_33, OP_RETURN};
use spaces_protocol::hasher::{KeyHasher, KeyHash, Hash};
use spaces_protocol::slabel::SLabel;
use spaces_protocol::{SpaceOut};
use crate::sptr::{Sptr};


pub trait PtrSource {
    fn get_ptr_outpoint(&mut self, sptr: &Sptr) -> spaces_protocol::errors::Result<Option<OutPoint>>;

    fn get_commitment(&mut self, key: &CommitmentKey) -> spaces_protocol::errors::Result<Option<Commitment>>;

    fn get_commitments_tip(&mut self, key: &RegistryKey) -> spaces_protocol::errors::Result<Option<Hash>>;

    fn get_delegator(&mut self, sptr: &RegistrySptrKey) -> spaces_protocol::errors::Result<Option<SLabel>>;

    fn get_ptrout(&mut self, outpoint: &OutPoint) -> spaces_protocol::errors::Result<Option<PtrOut>>;
}

#[derive(Debug, Clone)]
pub struct Validator {}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
/// A `TxChangeSet` captures all resulting state changes.
pub struct TxChangeSet {
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub txid: Txid,
    /// List of transaction input indexes spending a ptrout.
    pub spends: Vec<usize>,
    /// List of transaction outputs creating a ptrout.
    pub creates: Vec<PtrOut>,
    /// Any updates to existing ptrs mainly to remove a delegation
    pub updates: Vec<FullPtrOut>,
    /// New commitments made
    pub commitments: BTreeMap<SLabel, Commitment>,
    pub revoked_delegations: Vec<RegistrySptrKey>,
    pub new_delegations: Vec<Delegation>,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct Delegation {
    pub space: SLabel,
    pub sptr_key: RegistrySptrKey,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct FullPtrOut {
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub txid: Txid,

    #[cfg_attr(feature = "serde", serde(flatten))]
    pub ptrout: PtrOut,
}

/// PTR TxOut
/// This structure is a superset of [bitcoin::TxOut]
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct PtrOut {
    pub n: usize,
    /// Any handle associated with this output
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub sptr: Option<Ptr>,
    /// The value of the output, in satoshis.
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub value: Amount,
    /// The script which must be satisfied for the output to be spent.
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub script_pubkey: ScriptBuf,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct Ptr {
    pub genesis_spk: Vec<u8>,
    pub data: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct Commitment {
    /// Merkle/Trie commitment to the current state.
    pub state_root: [u8; 32],

    /// Previous state root (None for genesis).
    pub prev_root: Option<[u8; 32]>,

    /// Running history hash
    pub history_hash: [u8; 32],

    /// Block height at which the commitment was made
    pub block_height: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Commitment = 0x01,
    Sptr = 0x02,
    Registry = 0x03,
    RegistrySptr = 0x04,
}

impl KeyKind {
    #[inline]
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

pub fn ns_hash<H: KeyHasher>(kind: KeyKind, data: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32];
    buf[0] = kind.as_byte();
    buf[1..].copy_from_slice(&data);
    H::hash(&buf)
}


#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct RegistryKey([u8; 32]);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct RegistrySptrKey([u8; 32]);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct CommitmentKey([u8; 32]);

impl KeyHash for RegistryKey {}
impl KeyHash for RegistrySptrKey {}
impl KeyHash for CommitmentKey {}

impl From<RegistryKey> for Hash {
    fn from(value: RegistryKey) -> Self {
        value.0
    }
}

impl From<RegistrySptrKey> for Hash {
    fn from(value: RegistrySptrKey) -> Self {
        value.0
    }
}

impl From<CommitmentKey> for Hash {
    fn from(value: CommitmentKey) -> Self {
        value.0
    }
}

impl CommitmentKey {
    pub fn new<H: KeyHasher>(space: &SLabel, root: [u8;32]) -> Self {
        let mut data = [0u8;64];
        data[0..32].copy_from_slice(&H::hash(space.as_ref()));
        data[32..64].copy_from_slice(&root);
        Self(ns_hash::<H>(KeyKind::Registry, H::hash(&data)))
    }
}


impl RegistryKey {
    pub fn from_slabel<H: KeyHasher>(space: &SLabel) -> Self {
        Self(ns_hash::<H>(KeyKind::Registry, H::hash(space.as_ref())))
    }
}

impl RegistrySptrKey {
    pub fn from_sptr<H: KeyHasher>(sptr: Sptr) -> Self {
        RegistrySptrKey(ns_hash::<H>(KeyKind::RegistrySptr, sptr.to_bytes()))
    }
}

impl Commitment {
    pub fn key<H: KeyHasher>(&self) -> [u8; 32] {
        ns_hash::<H>(KeyKind::Commitment, self.state_root)
    }
}

#[derive(Clone)]
pub struct Stxo {
    pub n: usize,
    pub ptrout: PtrOut,
    pub delegate: Option<DelegateContext>,
}

#[derive(Clone)]
pub struct DelegateContext {
    space: SLabel,
    previous_commitment: Option<Commitment>,
}

pub struct TxContext {
    pub inputs: Vec<Stxo>,
    pub relevant_sptr_spks: Vec<ScriptBuf>
}

impl TxContext {
    pub fn spending_ptrs<T: PtrSource>(src: &mut T, tx: &Transaction) -> spaces_protocol::errors::Result<bool> {
        for input in tx.input.iter() {
            if src.get_ptrout(&input.previous_output)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Creates a [TxContext] from a Bitcoin [Transaction], loading all necessary data
    /// for validation from the provided data source `src`.
    ///
    /// Returns `Some(TxContext)` if the transaction is ptrs tx.
    /// Returns `None` if the transaction is not relevant.
    pub fn from_tx<T: PtrSource, H: KeyHasher>(
        src: &mut T,
        tx: &Transaction,
        has_spaces: bool,
    ) -> spaces_protocol::errors::Result<Option<TxContext>> {
        let has_ptr_outputs = is_ptr_minting_locktime(&tx.lock_time) &&
            tx.output.iter().any(|out| out.is_ptr_output());
        let relevant = has_spaces || has_ptr_outputs ||
            Self::spending_ptrs(src, &tx)?;

        if !relevant {
            return Ok(None);
        }

        let mut inputs = Vec::with_capacity(tx.input.len());
        for (n, input) in tx.input.iter().enumerate() {
            let ptrout = src.get_ptrout(&input.previous_output)?;
            if let Some(ptrout) = ptrout {
                let delegate = match &ptrout.sptr {
                    Some(sptr) => {
                        // TODO: how about just storing the sptr itself in sptr.spk?
                        let rsk = RegistrySptrKey::from_sptr::<H>(
                            Sptr::from_spk::<H>(ScriptBuf::from(sptr.genesis_spk.clone()))
                        );
                        let slabel = src.get_delegator(&rsk)?;
                        if let Some(slabel) = slabel {
                            let registry_key = RegistryKey::from_slabel::<H>(&slabel);
                            let state_root = src.get_commitments_tip(&registry_key)?;
                            let ck = match state_root {
                                Some(state_root) => {
                                    let ck = CommitmentKey::new::<H>(&slabel, state_root);
                                    src.get_commitment(&ck)?
                                },
                                None => None,
                            };

                            Some(DelegateContext {
                                space: slabel,
                                previous_commitment: ck,
                            })
                        } else {
                            None
                        }
                    }
                    None => None,
                };
                let ptrin = Stxo {
                    n,
                    ptrout,
                    delegate,
                };
                inputs.push(ptrin);
            }
        }

        // for existence checks we need to find any previous sptrs from outputs
        // TODO: technically we could fetch less by checking transfers
        let mut ctx = TxContext {
            inputs,
            relevant_sptr_spks: Vec::with_capacity(tx.output.len()),
        };
        for out in tx.output.iter() {
            if !out.is_ptr_output() {
                continue;
            }
            let sptr = Sptr::from_spk::<H>(out.script_pubkey.clone());
            if src.get_ptr_outpoint(&sptr)?.is_some() {
                ctx.relevant_sptr_spks.push(out.script_pubkey.clone());
            }
        }

        Ok(Some(ctx))
    }
}

pub fn transcript_hash<H: KeyHasher>(old: [u8; 32], new_root: [u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[0..32].copy_from_slice(&old);
    data[32..64].copy_from_slice(&new_root);
    H::hash(&data)
}

impl Validator {
    pub fn new() -> Self {
        Self {}
    }

    pub fn process<H: KeyHasher>(
        &self, height: u32,
        tx: &Transaction,
        ctx: TxContext,
        spent_space_utxos: Vec<SpaceOut>,
        new_space_utxos: Vec<SpaceOut>,
    ) -> TxChangeSet {
        let mut changeset = TxChangeSet {
            txid: tx.compute_txid(),
            spends: vec![],
            creates: vec![],
            updates: vec![],
            commitments: BTreeMap::new(),
            revoked_delegations: vec![],
            new_delegations: vec![],
        };

        let mut commitment_root = get_commitment_root(&tx);

        // Maintain space -> sptr registry mappings
        for spent in spent_space_utxos {
            let sptr = Sptr::from_spk::<H>(spent.script_pubkey);
            changeset.revoked_delegations.push(RegistrySptrKey::from_sptr::<H>(sptr));
        }
        for created in &new_space_utxos {
            let space = match &created.space {
                None => continue,
                Some(space) => space
            };
            let sptr = Sptr::from_spk::<H>(created.script_pubkey.clone());
            changeset.new_delegations.push(Delegation {
                space: space.name.clone(),
                sptr_key: RegistrySptrKey::from_sptr::<H>(sptr),
            })
        }

        for input_ctx in ctx.inputs.into_iter() {
            if let Some(delegate) = input_ctx.delegate {
                if let Some(commitment_root) = commitment_root.take() {
                    let commitment = match delegate.previous_commitment {
                        None => Commitment {
                            state_root: commitment_root,
                            history_hash: commitment_root,
                            prev_root: None,
                            block_height: height,
                        },
                        Some(prev) => {
                            Commitment {
                                state_root: commitment_root,
                                history_hash: transcript_hash::<H>(prev.history_hash, commitment_root),
                                prev_root: Some(prev.state_root),
                                block_height: height,
                            }
                        }
                    };
                    changeset.commitments.insert(delegate.space, commitment);
                }
            }

            changeset.spends.push(input_ctx.n);
            self.process_spend(
                tx,
                input_ctx.n,
                input_ctx.ptrout,
                &mut changeset,
            );
        }

        if !is_ptr_minting_locktime(&tx.lock_time) {
            return changeset;
        }

        for (n, output) in tx.output.iter().enumerate() {
            let already_added = changeset.creates.iter().find(|x| x.n == n).is_some();
            let is_space = new_space_utxos.iter().find(|x| x.n == n).is_some();
            let is_ptr_out = output.is_ptr_output();
            if already_added || is_space || !is_ptr_out {
                continue;
            }

            let already_exists = ctx.relevant_sptr_spks.iter()
                .find(|spk| output.script_pubkey.as_bytes() == spk.as_bytes()).is_some();
            if already_exists {
                continue;
            }

            changeset.creates.push(PtrOut {
                n,
                sptr: Some(Ptr {
                    genesis_spk: output.script_pubkey.to_bytes(),
                    data: None,
                }),
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
            });
        }

        changeset
    }

    fn process_spend(
        &self,
        tx: &Transaction,
        input_index: usize,
        mut ptrout: PtrOut,
        changeset: &mut TxChangeSet,
    ) {
        let ptr = match ptrout.sptr {
            None => return,
            Some(ptr) => ptr,
        };
        let output_index = input_index + 1;
        let output = tx.output.get(output_index);

        match output {
            None => {
                // TODO: No corresponding output found - could it be rebound?
                return
            }
            Some(output) => {
                ptrout.n = output_index;
                ptrout.value = output.value;
                ptrout.script_pubkey = output.script_pubkey.clone();
                ptrout.sptr = Some(ptr);
                changeset.creates.push(ptrout);
            }
        }
    }
}

pub fn get_commitment_root(tx: &Transaction) -> Option<[u8; 32]> {
    let txout = tx.output.first()?;
    let script = txout.script_pubkey.to_bytes();

    // Fixed length: 1 (OP_RETURN) + 1 (OP_PUSHBYTES_33) + 1 (marker) + 32 (data)
    if script.len() != 35 {
        return None;
    }

    if script[0] != OP_RETURN.to_u8() ||
        script[1] != OP_PUSHBYTES_33.to_u8() ||
        script[2] != 0x77 /* Marker */ {
        return None;
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&script[3..]);
    Some(out)
}



pub fn is_ptr_minting_locktime(lock_time: &LockTime) -> bool {
    if let LockTime::Seconds(s) = lock_time {
        return s.to_consensus_u32() % 1000 == 777;
    }
    false
}

pub trait PtrTrackableOutput {
    fn is_ptr_output(&self) -> bool;
}

impl PtrTrackableOutput for TxOut {
    fn is_ptr_output(&self) -> bool {
        self.value.to_sat() % 10 == 7
    }
}

