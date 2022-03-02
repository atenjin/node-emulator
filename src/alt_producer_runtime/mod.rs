use sp_runtime::traits::Header as HeaderT;
use sp_std::vec::Vec;

use codec::{Decode, Encode};
use sp_trie::CompactProof;

use crate::verifier::NodeBlockData;
use crate::ValidationParams;
pub use target_runtime::*;

pub fn dev_genesis_header() -> Header {
    let extrinsics_root = Hash::from_slice(
        hex::decode("03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314")
            .expect("")
            .as_slice(),
    );
    let parent_hash = Hash::from_slice(
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .expect("")
            .as_slice(),
    );
    let state_root = Hash::from_slice(
        hex::decode("cf3e735acf18f9830337c6be604a4bd6c25f5dd91f1907a1da2081587a5ca5e8")
            .expect("")
            .as_slice(),
    );
    let genesis = Header::new(
        0,
        extrinsics_root,
        state_root,
        parent_hash,
        Default::default(),
    );
    genesis
}

fn generate_data(
    parent_head: Vec<u8>,
    block_str: &str,
    proof_str: &str,
) -> (ValidationParams, Header) {
    // current block
    let block = hex::decode(block_str).expect("");
    let tmp_block = Block::decode(&mut &block[..]).expect("");
    // proof
    let proof = CompactProof::decode(&mut &hex::decode(proof_str).expect("")[..]).expect("");
    let data = NodeBlockData {
        header: tmp_block.header.clone(),
        extrinsics: tmp_block.extrinsics,
        storage_proof: proof,
    };
    (
        ValidationParams {
            parent_head: parent_head.into(),
            block_data: data.encode().into(),
        },
        tmp_block.header,
    )
}

pub fn test_data_1() -> Vec<ValidationParams> {
    let mut v = Vec::new();
    let genesis = dev_genesis_header();
    // block1
    let (params, parent_head) = generate_data(
        genesis.encode(),
        "224346e47be9aa90f6a4565289d411d0aabf4d21dc25d15acb5d19d7057fa6a504d23773ba572b4b65d8656b80b85de6d9a288d20fd2ed91bbccf054482954ac1b44dbab60f1050ea92d216a824d3ba39d28b1e2897c5962e8bd0b769424854b2d0406617572612053505a100000000004280402000b5399ba447f01",
        "44a4802c980000000080ed02fa8bdf827f5fe07d59a52c99d5ac87e90c4234a222315b4d118ce84e7db40001019f06aa394eea5630e07c48ae0c9558cef7308d505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f0684a022a34dd8bfa2baaf44f172b710040100000000c85f0a42f33323cb5ced3b44dd825fda9fcc8045454545454545454545454545454545454545454545454545454545454545455c80900000485efd6c28836b9a28522dc924110cf4390401f4764704b568d21667356a5a050c118746b4def25cfda6ef3a000000008045454545454545454545454545454545454545454545454545454545454545455d029f099d880ec681799c0cf30e8886371da95820808a18f972a616d5291bd46faa98bb85cb351f7867c223d42deb9ccefec3709313807171a7e1d9d657f86efa829359c835234020fb8c81aa28ef6ecf8b60322b6823807e909ae467833aadcfc4d77a6c5562ab6e097ca192c8ca5a6e1e010adf2ffff0808aa6ab1a6496581c61930ae16e22912a0527812399f1e5ace77bda5147b9e9f8845f09cce9c888469bb1a0dceaa129672ef83c910130616c742d70726f64756365721480008400006d018106a800807932e9d883f3c297d9248d27a168bc065a84c0cc54a556a391dbf69a38ca9087505c787472696e7369635f696e6465781000000000809fef36dd98627f4650186448e79cc23a856507fed301a57b6c16900baa2454e2ec9e1467a096bcd71a5b6a0c8155e2081018004c5f008ce9615de0775a82f8a94dc3d285a10401505f0e7b9012096b41c4eb3aaf947f6ea429080000988080900080140b4b9148bc2e03a7f8a4c223a70dc7e7984871cfea135d844e15126336a11e00a09ef8dc2f5ab09467896f47300f0424383000505f0e7b9012096b41c4eb3aaf947f6ea42908000000cc013f000e0621c4869aa60c02be9adcc98a0d1d5742fa11496d039103c536e226eea53fefca7b43bb6bc76724352e476ab0bef68404d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d8d019e9cc45b7a00c5899361e1c6099678dc1021505f0e7b9012096b41c4eb3aaf947f6ea429080400685f0a2d09463effcc78a22d75b9cb87dffc200000000000000000808f6ca5b339ead3e5b67ac674cd9f7625bde95ca367c422d044836b9e729c8b4c947f000d2a529379475088d3e29a918cd478724e7b9012096b41c4eb3aaf947f6ea429080000947f0000c365c3cf59d671eb72da0e7a4113c44e7b9012096b41c4eb3aaf947f6ea429080000");
    v.push(params);

    // // block2
    // let (params, parent_head)  = generate_data(
    //     parent_head.encode(),
    //     "696195b68baa6c16073197b6e23f6a6075040b97df9f5aed6ab1d789af35ac4a04474157a0784bc72f995dd2bab8b84ae1ba14fb0bde427bafe48ce7d0fb273dad70ff40e1e31d9a8256f820868dc206b2f8fe6b3ce094ab72c9980961dcf0bce7080661757261206d410c31000000000466726f6e8801e1f0e6db411f396af07a6d6884961e0a6227cfcdea9223dc2032f8f82a2a992f0004280402000b9123bf2f7f01",
    //     "5cb101802e9e80c237cdf2804a419e029b68b2e1021f7c08dcff32cdef502c46b64f9f25c8a85500000080b1329fc5bf35dab76f24b91355fe03928f631ef36238419ca39d008a230580c980d7711901cc2764bc5f404e60ad967acb79ca97c5b0bf685341e10332866fca6700000014804100000045019e13754dd003840aea66b349f8241e25101d505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f02fbce236236c63b34351052f96f67510400004c5f01ef0b108928f2a3c149728bbd19fb480400006d017f30044704b568d21667356a5a050c118746f52c63705dbee9f6000000000000000000000000000000000000000000000000000000000000000080fa4aa93e2c3e7ebbde0de33c820decbbfbb731ca9359333821af2cd09a302f16c83f0008c156f8164e0465c74b8972ea68b4b3ea09ff85c3f0eba8b1766279888d12ca00c8a169e363f1b7a690d2a00ef58c5471019eaa394eea5630e07c48ae0c9558cef7308d505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f0684a022a34dd8bfa2baaf44f172b7100401000000745f09cce9c888469bb1a0dceaa129672ef82c9101206d6f6f6e62617365c85f0a42f33323cb5ced3b44dd825fda9fcc8045454545454545454545454545454545454545454545454545454545454545455c80900000485efd6c28836b9a28522dc924110cf4390401f4764704b568d21667356a5a050c118746b4def25cfda6ef3a00000000804545454545454545454545454545454545454545454545454545454545454545e1029f099d880ec681799c0cf30e8886371da9422a8099f082c476f9ce2b5b59a6aa01dfc86814d5daa820d7b2c1fe9b19c2386c10da80f9a295fd3613448ed14154e84deca4e8784f4609d5d9369a34086ace16f62b8e80ec162f21e1f484f385c1f226cc60ebf4d5bd280d8c7c7c985b387549a9db3c3080b86d29a506c12509a2cb1f11d02c51359b677db8b8d16688f2433f3854926f92807a5fd942736576ce3513dbad6cd56ea003276d17d306e0d147785e7ee9feac1d1480008400001d018106a80080d05337740779f3e79683e9b602b1fe218ae6cb555e8404e4b26d66fedfb98ce500809fef36dd98627f4650186448e79cc23a856507fed301a57b6c16900baa2454e2a481071001405a68657265756d5f736368656d6104034c5a7472696e7369635f696e6465781000000000ec9e1467a096bcd71a5b6a0c8155e2081018004c5f008ce9615de0775a82f8a94dc3d285a10401505f0e7b9012096b41c4eb3aaf947f6ea429080000988080900080c24beedd84f70b85acea217c413de1e814b3fa206b351ec191676d667f66d8a600a09ef8dc2f5ab09467896f47300f0424383000505f0e7b9012096b41c4eb3aaf947f6ea42908000000cc013f000e0621c4869aa60c02be9adcc98a0d1d5742fa11496d039103c536e226eea53fefca7b43bb6bc76724352e476ab0bef68404d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d8d019e9cc45b7a00c5899361e1c6099678dc1021505f0e7b9012096b41c4eb3aaf947f6ea429080400685f0a2d09463effcc78a22d75b9cb87dffc200000000000000000808f6ca5b339ead3e5b67ac674cd9f7625bde95ca367c422d044836b9e729c8b4c947f000d2a529379475088d3e29a918cd478724e7b9012096b41c4eb3aaf947f6ea42908000094800600008044d5254145892b225f106932a3d8a09896e6a376ad584e3323b9e43284824c8f71019efef3b7207c11a52df13c12884e7726180280527c8b5a22f13c5a93039efa5f2927850537d22f7c3f4bc138475ee4896351d9505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f07d99b40aea431100eb0e0bbac4678150400947f0000c365c3cf59d671eb72da0e7a4113c44e7b9012096b41c4eb3aaf947f6ea429080000");
    // v.push(params);
    //
    // // block3
    // let (params, _parent_head)  = generate_data(
    //     parent_head.encode(),
    //     "0d9a6fe059dd4a288520b650afadf42bea0c8f4a18aecff244a9a2577788fa520c2212f6f2e6aea8ce52f7096ff39a67aca8915f64854ae288a488aebd6dfa4f12eda66b01deb868c0c6162099243ac52d35e4c5401665fd48170ed9a98099be70080661757261206f410c31000000000466726f6e8801838226f753b554648ed01bc04d9785fe086c6d15efa530ee03c0d7aa4018eb970004280402000b3033bf2f7f01",
    //     "7cb101802e9e80c237cdf2804a419e029b68b2e1021f7c08dcff32cdef502c46b64f9f25c8a85500000080b1329fc5bf35dab76f24b91355fe03928f631ef36238419ca39d008a230580c980d7711901cc2764bc5f404e60ad967acb79ca97c5b0bf685341e10332866fca6700000014804100000045019e13754dd003840aea66b349f8241e25101d505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f02fbce236236c63b34351052f96f67510400004c5f01ef0b108928f2a3c149728bbd19fb4804000059019f044704b568d21667356a5a050c1187468280008017145c9a1a98e707b77b186fa21d511c8a38e9fb8b1d76e1e992e0799b95ea2780f1beb07da2009333b943c14bd8e2695bb022734e6ecb0fa863955cb1680869af2d017f10023c6b93355876da02000000000000000000000000000000000000000000000000000000000000008061952fac15fe3eea7af6fcbcb670c9d8413793e5a7d30d285bbae195d49aade7e9095f08c156f8164e0465c74b8972ea68b4b39d09e1f0e6db411f396af07a6d6884961e0a6227cfcdea9223dc2032f8f82a2a992f1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934715fdd31c61141abd04a99fd6822c8558854ccde3e9a01cd95744b12e3ddac9bfde33c3737d379d105e32b8bda63ecec07963b8fa56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42156e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000ffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000602bbf2f7f010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007d019eaa394eea5630e07c48ae0c9558cef7398f0000505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f0684a022a34dd8bfa2baaf44f172b710040100000000745f09cce9c888469bb1a0dceaa129672ef82c9101206d6f6f6e62617365bc800404545ea5c1b19ab7a04f536c519aca4983ac1002000000545e98fdbe9ce6c55837576c60c7af38501001000000a85f04abf5cb34d6244378cddbf18e849d966000000000000000000000000000000000d08ca75401000000148001040000905ed41e5e16056765bc8461851072c9d74c0400000000000000585f8f0900000000020000c45e42f33323cb5ced3b44dd825fda9fcc8062b5ad4b51be25b192a8866862b3254c4526a7dbd25c07343643ab672d53165125015f09e7f93fc6a98f0874fd057f111c4d2ddc080661757261206e410c31000000000466726f6e880161952fac15fe3eea7af6fcbcb670c9d8413793e5a7d30d285bbae195d49aade7005c80900000485efd6c28836b9a28522dc924110cf439040151019e4704b568d21667356a5a050c11874620088039ef816c85fc64482d6fa666cf7dffaea6b098b909762da8de23b92af5748d4d8017699a18ce9ada3b6b56741cbd5ec6d81c9ce0e765425fd2b63f377aa9d2c4a4e1029f099d880ec681799c0cf30e8886371da9422a8099f082c476f9ce2b5b59a6aa01dfc86814d5daa820d7b2c1fe9b19c2386c10da80f9a295fd3613448ed14154e84deca4e8784f4609d5d9369a34086ace16f62b8e80ec162f21e1f484f385c1f226cc60ebf4d5bd280d8c7c7c985b387549a9db3c3080b86d29a506c12509a2cb1f11d02c51359b677db8b8d16688f2433f3854926f92807a5fd942736576ce3513dbad6cd56ea003276d17d306e0d147785e7ee9feac1d14800084000061018106a80080d05337740779f3e79683e9b602b1fe218ae6cb555e8404e4b26d66fedfb98ce5445c7468657265756d5f736368656d610403809fef36dd98627f4650186448e79cc23a856507fed301a57b6c16900baa2454e2a09e1467a096bcd71a5b6a0c8155e20810180000505f0e7b9012096b41c4eb3aaf947f6ea4290800005c800180485e8ce9615de0775a82f8a94dc3d285a1040100845e2edf3bdf381debe331ab7446addfdc4000000000000000000000000000000000988080900080c24beedd84f70b85acea217c413de1e814b3fa206b351ec191676d667f66d8a6000d019ef8dc2f5ab09467896f47300f0424383100685f06155b3cd9a8c9e5e9a23fd5dc13a5ed206e410c3100000000505f0e7b9012096b41c4eb3aaf947f6ea42908000000cc013f000e0621c4869aa60c02be9adcc98a0d1d5742fa11496d039103c536e226eea53fefca7b43bb6bc76724352e476ab0bef68404d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d8d019e9cc45b7a00c5899361e1c6099678dc1021505f0e7b9012096b41c4eb3aaf947f6ea429080400685f0a2d09463effcc78a22d75b9cb87dffc200000000000000000808f6ca5b339ead3e5b67ac674cd9f7625bde95ca367c422d044836b9e729c8b4ca49f0d2a529379475088d3e29a918cd47872120000505f0e7b9012096b41c4eb3aaf947f6ea42908000051015f0a39ec767bd5269111e6492a1675702a050108696195b68baa6c16073197b6e23f6a6075040b97df9f5aed6ab1d789af35ac4a62b5ad4b51be25b192a8866862b3254c4526a7dbd25c07343643ab672d53165194800600008044d5254145892b225f106932a3d8a09896e6a376ad584e3323b9e43284824c8f71019efef3b7207c11a52df13c12884e7726180280527c8b5a22f13c5a93039efa5f2927850537d22f7c3f4bc138475ee4896351d9505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f07d99b40aea431100eb0e0bbac46781504000d019f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb20602bbf2f7f010000");
    // v.push(params);

    v
}
