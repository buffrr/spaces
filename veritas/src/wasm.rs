#[cfg(feature = "wasm")]
mod wasm_api {
    use alloc::{
        format,
        string::{String, ToString},
        vec::Vec,
    };
    use core::str::FromStr;

    use spaces_protocol::{
        bitcoin::hashes::{sha256, Hash, HashEngine},
        slabel::SLabel as NativeSLabel,
        Covenant as NativeCovenant, Space as NativeSpace, SpaceOut as NativeSpaceOut,
    };
    use spaces_ptr::{
        Commitment as NativeCommitment, Ptr as NativePtr, PtrOut as NativePtrOut,
        sptr::Sptr as NativeSptr,
    };
    use wasm_bindgen::prelude::*;

    use crate::{Error, Proof as ProofNative, ProofType as ProofTypeNative, Value as ValueNative, Veritas as VeritasNative};

    #[wasm_bindgen]
    pub struct Veritas {
        inner: VeritasNative,
    }

    #[wasm_bindgen]
    pub struct Proof {
        inner: ProofNative,
    }

    #[wasm_bindgen]
    pub struct SpaceOut {
        inner: NativeSpaceOut,
    }

    #[wasm_bindgen]
    pub struct Space {
        inner: NativeSpace,
    }

    #[wasm_bindgen]
    pub struct SLabel {
        inner: NativeSLabel,
    }

    #[wasm_bindgen]
    pub struct Covenant {
        inner: NativeCovenant,
    }

    #[wasm_bindgen]
    pub struct TransferCovenant {
        expire_height: u32,
        data: Option<Vec<u8>>,
    }

    #[wasm_bindgen]
    pub struct BidCovenant {
        burn_increment: u64,
        signature: Vec<u8>,
        total_burned: u64,
        claim_height: Option<u32>,
    }

    #[wasm_bindgen]
    pub struct PtrOut {
        inner: NativePtrOut,
    }

    #[wasm_bindgen]
    pub struct Ptr {
        inner: NativePtr,
    }

    #[wasm_bindgen]
    pub struct Sptr {
        inner: NativeSptr,
    }

    #[wasm_bindgen]
    pub struct Commitment {
        inner: NativeCommitment,
    }

    #[wasm_bindgen]
    impl SLabel {
        #[wasm_bindgen(constructor)]
        pub fn new(space: &str) -> Result<Self, JsValue> {
            Ok(Self {
                inner: NativeSLabel::from_str(space)
                    .map_err(|err| JsValue::from_str(&format!("{:?}", err)))?,
            })
        }

        #[wasm_bindgen(js_name = "toString")]
        pub fn to_string(&self) -> String {
            self.inner.to_string()
        }

        #[wasm_bindgen(js_name = "toBytes")]
        pub fn to_bytes(&self) -> Vec<u8> {
            self.inner.as_ref().to_vec()
        }
    }

    #[wasm_bindgen]
    impl SpaceOut {
        /// Constructs a SpaceOut from raw bytes.
        #[wasm_bindgen(js_name = "fromBytes")]
        pub fn from_bytes(data: &[u8]) -> Result<SpaceOut, JsValue> {
            let (native, _): (NativeSpaceOut, _) =
                bincode::decode_from_slice(data, bincode::config::standard())
                    .map_err(|e| JsValue::from_str(&format!("Deserialization error: {:?}", e)))?;
            Ok(SpaceOut { inner: native })
        }

        #[wasm_bindgen(js_name = "getScriptPubkey")]
        pub fn get_script_pubkey(&self) -> Vec<u8> {
            self.inner.script_pubkey.to_bytes()
        }

        #[wasm_bindgen(js_name = "getPublicKey")]
        pub fn get_public_key(&self) -> Option<Vec<u8>> {
            match self.inner.script_pubkey.is_p2tr() {
                true => Some(self.inner.script_pubkey.as_bytes()[2..].to_vec()),
                false => None,
            }
        }

        #[wasm_bindgen(js_name = "getValue")]
        pub fn get_value(&self) -> u64 {
            self.inner.value.to_sat()
        }

        #[wasm_bindgen(js_name = "getSpace")]
        pub fn get_space(&self) -> Option<Space> {
            self.inner.space.clone().map(|s| Space { inner: s })
        }
    }

    #[wasm_bindgen]
    impl Space {
        #[wasm_bindgen(js_name = "getName")]
        pub fn get_name(&self) -> SLabel {
            SLabel {
                inner: self.inner.name.clone(),
            }
        }

        #[wasm_bindgen(js_name = "getCovenant")]
        pub fn get_covenant(&self) -> Covenant {
            Covenant {
                inner: self.inner.covenant.clone(),
            }
        }
    }

    #[wasm_bindgen]
    impl Covenant {
        /// Returns "bid", "transfer", or "reserved" to indicate the variant.
        #[wasm_bindgen(js_name = "getKind")]
        pub fn get_kind(&self) -> String {
            match self.inner {
                NativeCovenant::Bid { .. } => "bid".into(),
                NativeCovenant::Transfer { .. } => "transfer".into(),
                NativeCovenant::Reserved => "reserved".into(),
            }
        }

        /// If this covenant is a Bid, returns the bid details.
        #[wasm_bindgen(js_name = "asBid")]
        pub fn as_bid(&self) -> Option<BidCovenant> {
            if let NativeCovenant::Bid {
                ref burn_increment,
                ref signature,
                ref total_burned,
                claim_height,
            } = self.inner
            {
                Some(BidCovenant {
                    burn_increment: burn_increment.to_sat(),
                    signature: signature.as_ref().to_vec(),
                    total_burned: total_burned.to_sat(),
                    claim_height,
                })
            } else {
                None
            }
        }

        /// If this covenant is a Transfer, returns the transfer details.
        #[wasm_bindgen(js_name = "asTransfer")]
        pub fn as_transfer(&self) -> Option<TransferCovenant> {
            if let NativeCovenant::Transfer {
                expire_height,
                ref data,
            } = self.inner
            {
                Some(TransferCovenant {
                    expire_height,
                    data: data.clone().map(|d| d.to_vec()),
                })
            } else {
                None
            }
        }
    }

    #[wasm_bindgen]
    impl BidCovenant {
        #[wasm_bindgen(js_name = "getBurnIncrement")]
        pub fn get_burn_increment(&self) -> u64 {
            self.burn_increment
        }

        #[wasm_bindgen(js_name = "getSignature")]
        pub fn get_signature(&self) -> Vec<u8> {
            self.signature.clone()
        }

        #[wasm_bindgen(js_name = "getTotalBurned")]
        pub fn total_burned(&self) -> u64 {
            self.total_burned
        }

        #[wasm_bindgen(js_name = "getClaimHeight")]
        pub fn claim_height(&self) -> Option<u32> {
            self.claim_height
        }
    }

    #[wasm_bindgen]
    impl TransferCovenant {
        #[wasm_bindgen(js_name = "getExpireHeight")]
        pub fn get_expire_height(&self) -> u32 {
            self.expire_height
        }

        #[wasm_bindgen(js_name = "getData")]
        pub fn get_data(&self) -> Option<Vec<u8>> {
            self.data.clone()
        }
    }

    #[wasm_bindgen]
    impl Sptr {
        #[wasm_bindgen(constructor)]
        pub fn new(sptr: &str) -> Result<Self, JsValue> {
            Ok(Self {
                inner: NativeSptr::from_str(sptr)
                    .map_err(|err| JsValue::from_str(&format!("{:?}", err)))?,
            })
        }

        #[wasm_bindgen(js_name = "toString")]
        pub fn to_string(&self) -> String {
            self.inner.to_string()
        }

        #[wasm_bindgen(js_name = "toBytes")]
        pub fn to_bytes(&self) -> Vec<u8> {
            self.inner.to_bytes().to_vec()
        }
    }

    #[wasm_bindgen]
    impl PtrOut {
        #[wasm_bindgen(js_name = "fromBytes")]
        pub fn from_bytes(data: &[u8]) -> Result<PtrOut, JsValue> {
            let (native, _): (NativePtrOut, _) =
                bincode::decode_from_slice(data, bincode::config::standard())
                    .map_err(|e| JsValue::from_str(&format!("Deserialization error: {:?}", e)))?;
            Ok(PtrOut { inner: native })
        }

        #[wasm_bindgen(js_name = "getScriptPubkey")]
        pub fn get_script_pubkey(&self) -> Vec<u8> {
            self.inner.script_pubkey.to_bytes()
        }

        #[wasm_bindgen(js_name = "getPublicKey")]
        pub fn get_public_key(&self) -> Option<Vec<u8>> {
            match self.inner.script_pubkey.is_p2tr() {
                true => Some(self.inner.script_pubkey.as_bytes()[2..].to_vec()),
                false => None,
            }
        }

        #[wasm_bindgen(js_name = "getValue")]
        pub fn get_value(&self) -> u64 {
            self.inner.value.to_sat()
        }

        #[wasm_bindgen(js_name = "getPtr")]
        pub fn get_ptr(&self) -> Option<Ptr> {
            self.inner.sptr.clone().map(|p| Ptr { inner: p })
        }
    }

    #[wasm_bindgen]
    impl Ptr {
        #[wasm_bindgen(js_name = "getId")]
        pub fn get_id(&self) -> Sptr {
            Sptr {
                inner: self.inner.id.clone(),
            }
        }

        #[wasm_bindgen(js_name = "getLastUpdate")]
        pub fn get_last_update(&self) -> u32 {
            self.inner.last_update
        }

        #[wasm_bindgen(js_name = "getData")]
        pub fn get_data(&self) -> Option<Vec<u8>> {
            self.inner.data.clone()
        }
    }

    #[wasm_bindgen]
    impl Commitment {
        #[wasm_bindgen(js_name = "fromBytes")]
        pub fn from_bytes(data: &[u8]) -> Result<Commitment, JsValue> {
            let (native, _): (NativeCommitment, _) =
                bincode::decode_from_slice(data, bincode::config::standard())
                    .map_err(|e| JsValue::from_str(&format!("Deserialization error: {:?}", e)))?;
            Ok(Commitment { inner: native })
        }

        #[wasm_bindgen(js_name = "getRoot")]
        pub fn get_root(&self) -> Vec<u8> {
            self.inner.state_root.to_vec()
        }

        #[wasm_bindgen(js_name = "getBlockHeight")]
        pub fn get_block_height(&self) -> u32 {
            self.inner.block_height
        }
    }

    #[wasm_bindgen]
    impl Veritas {
        /// Creates a new Veritas instance.
        /// proof_type: "spaces" or "ptrs"
        #[wasm_bindgen(constructor)]
        pub fn new(proof_type: &str) -> Result<Veritas, JsValue> {
            let pt = match proof_type {
                "spaces" => ProofTypeNative::Spaces,
                "ptrs" => ProofTypeNative::Ptrs,
                _ => return Err(JsValue::from_str("proof_type must be 'spaces' or 'ptrs'")),
            };
            Ok(Veritas {
                inner: VeritasNative::new(pt),
            })
        }

        /// Adds an anchor.
        ///
        /// The provided `anchor` must be a 32‑byte array (passed as a Uint8Array).
        #[wasm_bindgen(js_name = "addAnchor")]
        pub fn add_anchor(&mut self, anchor: &[u8]) -> Result<(), JsValue> {
            let hash = read_hash(anchor)?;
            self.inner.add_anchor(hash);
            Ok(())
        }

        /// Verifies a proof.
        #[wasm_bindgen(js_name = "verifyProof")]
        pub fn verify_proof(&self, proof: &[u8]) -> Result<Proof, JsValue> {
            self.inner
                .verify_proof(proof)
                .map(|p| Proof { inner: p })
                .map_err(|e| error_to_jsvalue(e))
        }

        #[wasm_bindgen(js_name = "verifySchnorr")]
        pub fn verify_schnorr(&self, pubkey: &[u8], digest: &[u8], signature: &[u8]) -> bool {
            self.inner.verify_schnorr(pubkey, digest, signature)
        }

        #[wasm_bindgen(js_name = "sha256")]
        pub fn sha256(data: &[u8]) -> Result<Vec<u8>, JsValue> {
            let mut engine = sha256::Hash::engine();
            engine.input(data);
            let h = sha256::Hash::from_engine(engine);
            Ok(h.to_byte_array().to_vec())
        }
    }

    #[wasm_bindgen]
    impl Proof {
        /// Returns the proof’s root hash.
        #[wasm_bindgen(js_name = "getRoot")]
        pub fn get_root(&self) -> Vec<u8> {
            self.inner.root.to_vec()
        }

        /// Checks whether a given key (a 32‑byte array) provably exists or not exists
        #[wasm_bindgen]
        pub fn contains(&self, key: &[u8]) -> Result<bool, JsValue> {
            let hash = read_hash(key)?;
            self.inner.contains(&hash).map_err(|e| error_to_jsvalue(e))
        }

        #[wasm_bindgen(js_name = "findSpace")]
        pub fn find_space(&self, space: &SLabel) -> Result<Option<SpaceOut>, JsValue> {
            Ok(self
                .inner
                .find_space(&space.inner)
                .map_err(|e| error_to_jsvalue(e))?
                .map(|out| SpaceOut { inner: out }))
        }

        #[wasm_bindgen(js_name = "findPtr")]
        pub fn find_ptr(&self, sptr: &Sptr) -> Result<Option<PtrOut>, JsValue> {
            Ok(self
                .inner
                .find_ptr(&sptr.inner)
                .map_err(|e| error_to_jsvalue(e))?
                .map(|out| PtrOut { inner: out }))
        }

        #[wasm_bindgen(js_name = "getPtrout")]
        pub fn get_ptrout(&self, utxo_key: &[u8]) -> Result<Option<PtrOut>, JsValue> {
            let hash = read_hash(utxo_key)?;
            Ok(self
                .inner
                .get_ptrout(&hash)
                .map_err(|e| error_to_jsvalue(e))?
                .map(|out| PtrOut { inner: out }))
        }

        #[wasm_bindgen(js_name = "getCommitment")]
        pub fn get_commitment(&self, commitment_key: &[u8]) -> Result<Option<Commitment>, JsValue> {
            let hash = read_hash(commitment_key)?;
            Ok(self
                .inner
                .get_commitment(&hash)
                .map_err(|e| error_to_jsvalue(e))?
                .map(|c| Commitment { inner: c }))
        }

        #[wasm_bindgen(js_name = "getDelegation")]
        pub fn get_delegation(&self, sptr_key: &[u8]) -> Result<Option<SLabel>, JsValue> {
            let hash = read_hash(sptr_key)?;
            Ok(self
                .inner
                .get_delegation(&hash)
                .map_err(|e| error_to_jsvalue(e))?
                .map(|s| SLabel { inner: s }))
        }

        #[wasm_bindgen(js_name = "getRegistryTip")]
        pub fn get_registry_tip(&self, registry_key: &[u8]) -> Result<Option<Vec<u8>>, JsValue> {
            let hash = read_hash(registry_key)?;
            Ok(self
                .inner
                .get_registry_tip(&hash)
                .map_err(|e| error_to_jsvalue(e))?
                .map(|h| h.to_vec()))
        }

        /// Returns all proof entries as an array of objects.
        #[wasm_bindgen]
        pub fn entries(&self) -> Result<JsValue, JsValue> {
            let entries = js_sys::Array::new();
            for (k, v) in self.inner.iter() {
                let entry = js_sys::Object::new();

                let key_array = js_sys::Uint8Array::from(k.as_ref());
                js_sys::Reflect::set(&entry, &JsValue::from_str("key"), &key_array.into())?;

                // Convert the value.
                let value_js = match v {
                    ValueNative::Outpoint(ref op) => JsValue::from_str(&op.to_string()),
                    ValueNative::UTXO(ref utxo) => JsValue::from(SpaceOut {
                        inner: utxo.clone(),
                    }),
                    ValueNative::PtrUTXO(ref ptrout) => JsValue::from(PtrOut {
                        inner: ptrout.clone(),
                    }),
                    ValueNative::Commitment(ref commitment) => JsValue::from(Commitment {
                        inner: commitment.clone(),
                    }),
                    ValueNative::Space(ref space) => JsValue::from(SLabel {
                        inner: space.clone(),
                    }),
                    ValueNative::Root(ref root) => {
                        JsValue::from(js_sys::Uint8Array::from(&root[..]))
                    },
                    ValueNative::Unknown(ref bytes) => {
                        JsValue::from(js_sys::Uint8Array::from(&bytes[..]))
                    }
                };
                js_sys::Reflect::set(&entry, &JsValue::from_str("value"), &value_js)?;
                entries.push(&entry);
            }
            Ok(entries.into())
        }
    }

    fn read_hash(hash: &[u8]) -> Result<[u8; 32], JsValue> {
        if hash.len() != 32 {
            return Err(JsValue::from_str("hash must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        Ok(arr)
    }

    fn error_to_jsvalue(e: Error) -> JsValue {
        JsValue::from_str(&format!("{:?}", e))
    }
}
