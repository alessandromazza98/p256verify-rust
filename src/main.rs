use hex;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
fn main() {
    let hex_string = "4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e";
    let input_vec = hex::decode(hex_string).unwrap();

    let mut input = [0u8; 160];
    input.copy_from_slice(&input_vec);

    let mut msg = [0u8; 32];
    let mut sig = [0u8; 64];
    let mut pk = [0u8; 64];
    let mut uncompressed_pk = [0u8; 65];

    // msg signed
    msg[0..32].copy_from_slice(&input[0..32]);
    // r: signature
    sig[0..32].copy_from_slice(&input[32..64]);
    // s: signature
    sig[32..64].copy_from_slice(&input[64..96]);
    // x: public key
    pk[0..32].copy_from_slice(&input[96..128]);
    // y: public key
    pk[32..64].copy_from_slice(&input[128..160]);
    // append 0x04 to the public key: uncompressed form
    uncompressed_pk[0] = 0x04;
    uncompressed_pk[1..].copy_from_slice(&pk);

    // create signature instance
    let signature: Signature = Signature::from_slice(&sig).unwrap();
    // create public_key instance
    let public_key: VerifyingKey = VerifyingKey::from_sec1_bytes(&uncompressed_pk).unwrap();

    // verify the signature: it returns not valid...
    if public_key.verify(&msg, &signature).is_ok() {
        println!("signature is valid")
    } else {
        println!("signature is not valid")
    }
}
