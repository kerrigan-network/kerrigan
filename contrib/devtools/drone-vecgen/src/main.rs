// vecgen v2 -- golden-vector generator for the Kerrigan CDroneRegTx special-tx
// payload (src/evo/inference_wire.h), regenerated 2026-07-28 to add the
// 1-byte nModelTier field after nHardwareClass (still payload v1 -- the format
// is unpublished, v1's shape is redefined in place).
//
// Modes:
//   vecgen verify-old <old.json>   -- validate this generator's serializer,
//                                     msg-hash and blst min_sig handling against
//                                     the PREVIOUS vectors (pre-tier layout)
//   vecgen probe <old.json>        -- try trivial candidate secrets against the
//                                     old vectors' pubkeys
//   vecgen generate <out.json>     -- emit the new (tier-carrying) vectors
//
// Keys are deterministic: blst min_sig SecretKey::key_gen with
// IKM = b"KRGN-DRONE-WIRE-VECGEN-V2-KEY-<n>-2026-07-28!!" and empty key_info.
// BLS scheme: blst 0.3.16 min_sig (G2 pubkeys 96B, G1 sigs 48B), DST
// BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_KRGN_REG_V1_, message = the 32-byte
// sha256d of the payload serialized without vchSig.

use blst::min_sig::{PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_KRGN_REG_V1_";
const MAX_MODEL_TIER: u8 = 3;

fn sha256d(b: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(b);
    let h2 = Sha256::digest(h1);
    h2.into()
}

fn hash160(b: &[u8]) -> [u8; 20] {
    let h1 = Sha256::digest(b);
    Ripemd160::digest(h1).into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn compact_size(n: usize) -> Vec<u8> {
    assert!(n < 253, "vector sizes stay tiny");
    vec![n as u8]
}

#[derive(Clone)]
struct Payload {
    version: u16,
    pkh: [u8; 20],
    pubkey: Vec<u8>,
    iroh: [u8; 32],
    hw_class: u8,
    model_tier: Option<u8>, // None = OLD (pre-tier) layout, for verify-old
    collateral_index: u32,
    script_payout: Vec<u8>,
    inputs_hash: [u8; 32],
}

impl Payload {
    /// Serialization WITHOUT vchSig -- exactly the C++ SER_GETHASH portion.
    fn ser_nosig(&self) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&self.version.to_le_bytes());
        r.extend_from_slice(&self.pkh);
        r.extend_from_slice(&compact_size(self.pubkey.len()));
        r.extend_from_slice(&self.pubkey);
        r.extend_from_slice(&self.iroh);
        r.push(self.hw_class);
        if let Some(t) = self.model_tier {
            r.push(t);
        }
        r.extend_from_slice(&self.collateral_index.to_le_bytes());
        r.extend_from_slice(&compact_size(self.script_payout.len()));
        r.extend_from_slice(&self.script_payout);
        r.extend_from_slice(&self.inputs_hash);
        r
    }

    fn ser_with_sig(&self, sig: &[u8]) -> Vec<u8> {
        let mut r = self.ser_nosig();
        r.extend_from_slice(&compact_size(sig.len()));
        r.extend_from_slice(sig);
        r
    }

    fn msg_hash(&self) -> [u8; 32] {
        sha256d(&self.ser_nosig())
    }
}

fn sign(sk: &SecretKey, msg_hash: &[u8; 32]) -> [u8; 48] {
    sk.sign(msg_hash, DST, &[]).compress()
}

fn verify(pubkey: &[u8], msg_hash: &[u8; 32], sig: &[u8]) -> bool {
    if pubkey.len() != 96 || sig.len() != 48 {
        return false;
    }
    // Reject infinity encodings outright (matches the C++ verifier).
    if pubkey[0] & 0x40 != 0 || sig[0] & 0x40 != 0 {
        return false;
    }
    let pk = match PublicKey::uncompress(pubkey) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let s = match Signature::uncompress(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    s.verify(true, msg_hash, DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
}

fn key(n: u8) -> (SecretKey, Vec<u8>) {
    let ikm = format!("KRGN-DRONE-WIRE-VECGEN-V2-KEY-{}-2026-07-28!!", n);
    let sk = SecretKey::key_gen(ikm.as_bytes(), &[]).expect("key_gen");
    let pk = sk.sk_to_pk().compress().to_vec();
    (sk, pk)
}

// ---------------------------------------------------------------------------
// verify-old: prove this generator reproduces the OLD (pre-tier) consensus
// serializer, message definition and blst acceptance bit-for-bit.
// ---------------------------------------------------------------------------

fn json_field<'a>(entry: &'a str, key: &str) -> Option<&'a str> {
    // Vectors are flat one-line JSON objects with string/num/bool scalars:
    // a tiny targeted extractor is fine (no nested objects, no escapes).
    let pat = format!("\"{}\": ", key);
    let start = entry.find(&pat)? + pat.len();
    let rest = &entry[start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        Some(&stripped[..stripped.find('"')?])
    } else {
        let end = rest.find([',', '}']).unwrap();
        Some(rest[..end].trim())
    }
}

fn verify_old(path: &str) {
    let text = std::fs::read_to_string(path).expect("read old json");
    let mut checked = 0;
    for line in text.lines() {
        let line = line.trim().trim_end_matches(',');
        if !line.starts_with('{') || line.contains("\"comment\"") {
            continue;
        }
        let name = json_field(line, "name").unwrap();
        let payload = unhex(json_field(line, "payload").unwrap());
        if json_field(line, "valid_payload").unwrap() != "true" {
            continue;
        }
        let version = u16::from_le_bytes([payload[0], payload[1]]);
        if json_field(line, "version_ok").map(|v| v == "true") != Some(true) {
            // unknown-version entries stop after the version field
            assert_eq!(payload.len(), 2, "{}: unexpected unknown-version shape", name);
            continue;
        }
        // Parse with the OLD layout (no tier byte).
        let mut o = 2usize;
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&payload[o..o + 20]);
        o += 20;
        let pklen = payload[o] as usize;
        o += 1;
        let pubkey = payload[o..o + pklen].to_vec();
        o += pklen;
        let mut iroh = [0u8; 32];
        iroh.copy_from_slice(&payload[o..o + 32]);
        o += 32;
        let hw = payload[o];
        o += 1;
        let ci = u32::from_le_bytes(payload[o..o + 4].try_into().unwrap());
        o += 4;
        let slen = payload[o] as usize;
        o += 1;
        let script = payload[o..o + slen].to_vec();
        o += slen;
        let mut ih = [0u8; 32];
        ih.copy_from_slice(&payload[o..o + 32]);
        o += 32;
        let siglen = payload[o] as usize;
        o += 1;
        let sig = payload[o..o + siglen].to_vec();
        o += siglen;
        assert_eq!(o, payload.len(), "{}: trailing bytes", name);

        let p = Payload {
            version,
            pkh,
            pubkey: pubkey.clone(),
            iroh,
            hw_class: hw,
            model_tier: None,
            collateral_index: ci,
            script_payout: script,
            inputs_hash: ih,
        };
        // 1. serializer round-trip is byte-identical
        assert_eq!(p.ser_with_sig(&sig), payload, "{}: reserialization mismatch", name);
        // 2. signed-message definition matches
        assert_eq!(hex(&p.msg_hash()), json_field(line, "msg_hash").unwrap(), "{}: msg_hash mismatch", name);
        // 3. HASH160 commitment logic matches
        let pkh_matches = hash160(&pubkey)[..] == pkh[..];
        assert_eq!(
            pkh_matches.to_string(),
            json_field(line, "pkh_matches").unwrap(),
            "{}: pkh_matches mismatch",
            name
        );
        // 4. blst min_sig acceptance matches the pinned verdicts
        let sig_valid = verify(&pubkey, &p.msg_hash(), &sig);
        assert_eq!(
            sig_valid.to_string(),
            json_field(line, "sig_valid").unwrap(),
            "{}: sig_valid mismatch",
            name
        );
        checked += 1;
    }
    println!("verify-old: OK -- {} pre-tier vectors reproduced (serializer + msg_hash + HASH160 + blst min_sig verdicts)", checked);
}

fn probe(path: &str) {
    let text = std::fs::read_to_string(path).expect("read old json");
    let target = json_field(
        text.lines().find(|l| l.contains("valid_registration")).unwrap(),
        "bls_pubkey",
    )
    .unwrap()
    .to_string();
    let mut cands: Vec<Vec<u8>> = Vec::new();
    for i in 1u8..=64 {
        let mut s = vec![0u8; 32];
        s[31] = i;
        cands.push(s);
    }
    for b in [0x01u8, 0x2a, 0x42, 0xff] {
        cands.push(vec![b; 32]);
    }
    for c in &cands {
        if let Ok(sk) = SecretKey::from_bytes(c) {
            if hex(&sk.sk_to_pk().compress()) == target {
                println!("probe: FOUND secret {}", hex(c));
                return;
            }
        }
    }
    for n in 0u8..64 {
        for pat in ["KRGN-DRONE-VEC-KEY-{}", "krgn-drone-vec-{}", "drone-vec-key-{}"] {
            let ikm32 = format!("{:0>48}", pat.replace("{}", &n.to_string()));
            if let Ok(sk) = SecretKey::key_gen(ikm32.as_bytes(), &[]) {
                if hex(&sk.sk_to_pk().compress()) == target {
                    println!("probe: FOUND ikm {}", ikm32);
                    return;
                }
            }
        }
    }
    println!("probe: no trivial candidate secret matches the old pubkey -- fresh deterministic keys will be used");
}

// ---------------------------------------------------------------------------
// generate: the new tier-carrying vector set.
// ---------------------------------------------------------------------------

struct Entry {
    json: String,
}

fn full_entry(
    name: &str,
    payload_bytes: &[u8],
    p: &Payload,
    sig: &[u8],
    sig_valid_expected: bool,
) -> Entry {
    let tier = p.model_tier.expect("full entries carry a tier");
    let pubkey_size_ok = p.pubkey.len() == 96;
    let pkh_matches = hash160(&p.pubkey)[..] == p.pkh[..];
    // Cross-check the blst verdict against what the vector will claim.
    let actual = verify(&p.pubkey, &p.msg_hash(), sig);
    assert_eq!(actual, sig_valid_expected, "{}: sig_valid expectation wrong", name);
    let json = format!(
        concat!(
            "{{\"name\": \"{}\", \"payload\": \"{}\", \"valid_payload\": true, ",
            "\"version\": {}, \"version_ok\": true, \"pubkey_size_ok\": {}, ",
            "\"pkh_matches\": {}, \"sig_valid\": {}, \"model_tier\": {}, \"tier_ok\": {}, ",
            "\"bls_pubkey_hash\": \"{}\", \"bls_pubkey\": \"{}\", \"iroh_node_id\": \"{}\", ",
            "\"hardware_class\": {}, \"collateral_index\": {}, \"script_payout\": \"{}\", ",
            "\"inputs_hash\": \"{}\", \"msg_hash\": \"{}\", \"signature\": \"{}\"}}"
        ),
        name,
        hex(payload_bytes),
        p.version,
        pubkey_size_ok,
        pkh_matches,
        sig_valid_expected,
        tier,
        tier <= MAX_MODEL_TIER,
        hex(&p.pkh),
        hex(&p.pubkey),
        hex(&p.iroh),
        p.hw_class,
        p.collateral_index,
        hex(&p.script_payout),
        hex(&p.inputs_hash),
        hex(&p.msg_hash()),
        hex(sig),
    );
    Entry { json }
}

fn bad_entry(name: &str, payload_bytes: &[u8]) -> Entry {
    Entry {
        json: format!(
            "{{\"name\": \"{}\", \"payload\": \"{}\", \"valid_payload\": false}}",
            name,
            hex(payload_bytes)
        ),
    }
}

fn p2pkh(byte: u8) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&[byte; 20]);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn generate(out_path: &str) {
    let (sk1, pk1) = key(1);
    let (sk2, pk2) = key(2);

    // Arbitrary constants carried over unchanged from the previous vector set.
    let iroh_reg: [u8; 32] = unhex("5d661fecf3c4b8957e54b3a6a16a203aded622a56e6fc4e6f6d878228d7f8602")
        .try_into()
        .unwrap();
    let iroh_hb: [u8; 32] = unhex("9a7d0b4edef17c97fe77bee1e480a99a54b776bd1aef3ec63e4e09e66c526ccf")
        .try_into()
        .unwrap();
    let inputs_reg: [u8; 32] = unhex("c896145d941137bcff58e0a424eb129e82a42be94045831ab310927b4ae1a6f0")
        .try_into()
        .unwrap();
    let inputs_hb: [u8; 32] = unhex("9cd06f59ef2102b36e7900ec7180fb456eba6f79ec955b6a4869a7529f477e61")
        .try_into()
        .unwrap();

    let base = Payload {
        version: 1,
        pkh: hash160(&pk1),
        pubkey: pk1.clone(),
        iroh: iroh_reg,
        hw_class: 3,
        model_tier: Some(2),
        collateral_index: 1,
        script_payout: p2pkh(0x11),
        inputs_hash: inputs_reg,
    };
    let base_sig = sign(&sk1, &base.msg_hash());
    let base_bytes = base.ser_with_sig(&base_sig);

    let mut entries: Vec<Entry> = Vec::new();
    entries.push(Entry {
        json: concat!(
            "{\"comment\": \"GENERATED golden vectors for the CDroneRegTx special-tx payload (src/evo/inference_wire.h). ",
            "Payload bytes follow the C++ consensus serializer (v1 layout INCLUDING the 1-byte nModelTier field after nHardwareClass; ",
            "consensus accepts tiers 0..3 only, bad-drone-reg-tier); the C++ test round-trips them byte-for-byte. ",
            "BLS signatures were produced with Rust blst 0.3.16 min_sig (the swarm's library/scheme) over msg_hash with DST ",
            "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_KRGN_REG_V1_, pinning dashbls-verify <-> blst-sign compatibility. ",
            "NOTE (cross-repo follow-up): kerrigan-sdk register_tx.rs still builds the old OP_RETURN 0x01 registration and the ",
            "krgn-coordinator scanner still scans for it -- both MUST be updated to this special-tx format (nVersion=3, nType=11, ",
            "extraPayload as pinned here) before drones can register under the v1.3.0 fork rules. ",
            "Generator: contrib/devtools/drone-vecgen (vecgen v2) (blst+sha2+ripemd; deterministic keys: blst min_sig key_gen with ",
            "IKM 'KRGN-DRONE-WIRE-VECGEN-V2-KEY-<n>-2026-07-28!!'), 2026-07-28.\"}"
        )
        .to_string(),
    });

    // 1. valid_registration
    entries.push(full_entry("valid_registration", &base_bytes, &base, &base_sig, true));

    // 2. valid_heartbeat_shape -- same key/script, bond index 0, different
    //    iroh id + inputs hash.
    let hb = Payload {
        iroh: iroh_hb,
        collateral_index: 0,
        inputs_hash: inputs_hb,
        ..base.clone()
    };
    let hb_sig = sign(&sk1, &hb.msg_hash());
    entries.push(full_entry("valid_heartbeat_shape", &hb.ser_with_sig(&hb_sig), &hb, &hb_sig, true));

    // 3. wrong_key_signature -- base payload, signed by key2.
    let wrong_sig = sign(&sk2, &base.msg_hash());
    entries.push(full_entry("wrong_key_signature", &base.ser_with_sig(&wrong_sig), &base, &wrong_sig, false));

    // 4. bit_flipped_signature -- base signature with one bit flipped.
    let mut flipped = base_sig;
    flipped[10] ^= 0x01;
    entries.push(full_entry("bit_flipped_signature", &base.ser_with_sig(&flipped), &base, &flipped, false));

    // 5. pkh_mismatch_squat -- key2's HASH160 committed, key1's pubkey +
    //    valid key1 signature: the squatting shape CheckDroneRegTx rejects
    //    on the pkh-commitment check.
    let squat = Payload { pkh: hash160(&pk2), ..base.clone() };
    let squat_sig = sign(&sk1, &squat.msg_hash());
    entries.push(full_entry("pkh_mismatch_squat", &squat.ser_with_sig(&squat_sig), &squat, &squat_sig, true));

    // 6. rebound_payout_script -- base signature replayed onto a payload
    //    paying a different script: must NOT verify (replay protection).
    let rebound = Payload { script_payout: p2pkh(0x99), ..base.clone() };
    entries.push(full_entry("rebound_payout_script", &rebound.ser_with_sig(&base_sig), &rebound, &base_sig, false));

    // 7. infinity_pubkey_and_sig -- identity-point encodings must be rejected.
    let mut inf_pk = vec![0u8; 96];
    inf_pk[0] = 0xc0;
    let mut inf_sig = vec![0u8; 48];
    inf_sig[0] = 0xc0;
    let inf = Payload { pkh: hash160(&inf_pk), pubkey: inf_pk, ..base.clone() };
    entries.push(full_entry("infinity_pubkey_and_sig", &inf.ser_with_sig(&inf_sig), &inf, &inf_sig, false));

    // 8. unknown_hardware_class -- hardware byte stays consensus-unvalidated.
    let hw = Payload { hw_class: 42, model_tier: Some(1), ..base.clone() };
    let hw_sig = sign(&sk1, &hw.msg_hash());
    entries.push(full_entry("unknown_hardware_class", &hw.ser_with_sig(&hw_sig), &hw, &hw_sig, true));

    // 9. frontier_tier_boundary -- tier 3 is the highest valid tier.
    let t3 = Payload { model_tier: Some(3), ..base.clone() };
    let t3_sig = sign(&sk1, &t3.msg_hash());
    entries.push(full_entry("frontier_tier_boundary", &t3.ser_with_sig(&t3_sig), &t3, &t3_sig, true));

    // 10. tier_out_of_range_wire -- tier 4 decodes fine on the wire and even
    //     carries a VALID signature; rejection is purely CheckDroneRegTx's
    //     bad-drone-reg-tier range rule (tier_ok == false).
    let t4 = Payload { model_tier: Some(4), ..base.clone() };
    let t4_sig = sign(&sk1, &t4.msg_hash());
    entries.push(full_entry("tier_out_of_range_wire", &t4.ser_with_sig(&t4_sig), &t4, &t4_sig, true));

    // 11. unknown_version -- serializer bails right after the version field.
    entries.push(Entry {
        json: concat!(
            "{\"name\": \"unknown_version\", \"payload\": \"0200\", \"valid_payload\": true, ",
            "\"version\": 2, \"version_ok\": false, \"pubkey_size_ok\": false, ",
            "\"pkh_matches\": false, \"sig_valid\": false}"
        )
        .to_string(),
    });

    // 12./13. truncated / trailing byte -- strict-size payload decode.
    entries.push(bad_entry("truncated_payload", &base_bytes[..base_bytes.len() - 1]));
    let mut trailing = base_bytes.clone();
    trailing.push(0x00);
    entries.push(bad_entry("trailing_byte", &trailing));

    // 14. short_pubkey -- 95-byte pubkey decodes (LIMITED_VECTOR allows <=96)
    //     but fails the size + signature checks; pkh commits to the short blob.
    let short_pk = pk1[..95].to_vec();
    let short = Payload { pkh: hash160(&short_pk), pubkey: short_pk, ..base.clone() };
    let short_sig = sign(&sk1, &short.msg_hash());
    entries.push(full_entry("short_pubkey", &short.ser_with_sig(&short_sig), &short, &short_sig, false));

    // 15. oversized_pubkey -- 97 bytes exceeds LIMITED_VECTOR: decode fails.
    let mut over_pk = pk1.clone();
    over_pk.push(0x00);
    let over = Payload { pubkey: over_pk, ..base.clone() };
    entries.push(bad_entry("oversized_pubkey", &over.ser_with_sig(&base_sig)));

    let mut out = String::from("[\n");
    out.push_str(&entries.iter().map(|e| e.json.clone()).collect::<Vec<_>>().join(",\n"));
    out.push_str("\n]\n");
    std::fs::write(out_path, out).expect("write output");
    println!("generate: wrote {} entries (+1 comment) to {}", entries.len() - 1, out_path);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("verify-old") => verify_old(&args[2]),
        Some("probe") => probe(&args[2]),
        Some("generate") => generate(&args[2]),
        _ => eprintln!("usage: vecgen verify-old|probe|generate <path>"),
    }
}
