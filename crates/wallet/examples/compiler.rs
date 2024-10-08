// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

extern crate miniscript;
extern crate serde_json;
extern crate tapyrus;
extern crate tdk_wallet;

use std::error::Error;
use std::str::FromStr;

use miniscript::policy::Concrete;
use miniscript::Descriptor;
use tapyrus::Network;

use tdk_wallet::{KeychainKind, Wallet};

/// Miniscript policy is a high level abstraction of spending conditions. Defined in the
/// rust-miniscript library here  https://docs.rs/miniscript/7.0.0/miniscript/policy/index.html
/// rust-miniscript provides a `compile()` function that can be used to compile any miniscript policy
/// into a descriptor. This descriptor then in turn can be used in bdk a fully functioning wallet
/// can be derived from the policy.
///
/// This example demonstrates the interaction between a bdk wallet and miniscript policy.

fn main() -> Result<(), Box<dyn Error>> {
    // We start with a miniscript policy string
    let policy_str = "or(
        10@thresh(4,
            pk(029ffbe722b147f3035c87cb1c60b9a5947dd49c774cc31e94773478711a929ac0),pk(025f05815e3a1a8a83bfbb03ce016c9a2ee31066b98f567f6227df1d76ec4bd143),pk(025625f41e4a065efc06d5019cbbd56fe8c07595af1231e7cbc03fafb87ebb71ec),pk(02a27c8b850a00f67da3499b60562673dcf5fdfb82b7e17652a7ac54416812aefd),pk(03e618ec5f384d6e19ca9ebdb8e2119e5bef978285076828ce054e55c4daf473e2)
        ),1@and(
            older(4209713),
            thresh(2,
                pk(03deae92101c790b12653231439f27b8897264125ecb2f46f48278603102573165),pk(033841045a531e1adf9910a6ec279589a90b3b8a904ee64ffd692bd08a8996c1aa),pk(02aebf2d10b040eb936a6f02f44ee82f8b34f5c1ccb20ff3949c2b28206b7c1068)
            )
        )
    )"
    .replace(&[' ', '\n', '\t'][..], "");

    println!("Compiling policy: \n{}", policy_str);

    // Parse the string as a [`Concrete`] type miniscript policy.
    let policy = Concrete::<String>::from_str(&policy_str)?;

    // Create a `sh` type descriptor from the policy.
    // `policy.compile()` returns the resulting miniscript from the policy.
    let descriptor = Descriptor::new_sh(policy.compile()?)?.to_string();

    println!("Compiled into Descriptor: \n{}", descriptor);

    // Do the same for another (internal) keychain
    let policy_str = "or(
        10@thresh(2,
            pk(029ffbe722b147f3035c87cb1c60b9a5947dd49c774cc31e94773478711a929ac0),pk(025f05815e3a1a8a83bfbb03ce016c9a2ee31066b98f567f6227df1d76ec4bd143),pk(025625f41e4a065efc06d5019cbbd56fe8c07595af1231e7cbc03fafb87ebb71ec)
        ),1@and(
            pk(03deae92101c790b12653231439f27b8897264125ecb2f46f48278603102573165),
            older(12960)
        )
    )"
    .replace(&[' ', '\n', '\t'][..], "");

    println!("Compiling internal policy: \n{}", policy_str);

    let policy = Concrete::<String>::from_str(&policy_str)?;
    let internal_descriptor = Descriptor::new_sh(policy.compile()?)?.to_string();
    println!(
        "Compiled into internal Descriptor: \n{}",
        internal_descriptor
    );

    // Create a new wallet from descriptors
    let mut wallet = Wallet::new_no_persist(&descriptor, &internal_descriptor, Network::Dev)?;

    println!(
        "First derived address from the descriptor: \n{}",
        wallet.next_unused_address(KeychainKind::External)?,
    );

    // BDK also has it's own `Policy` structure to represent the spending condition in a more
    // human readable json format.
    let spending_policy = wallet.policies(KeychainKind::External)?;
    println!(
        "The BDK spending policy: \n{}",
        serde_json::to_string_pretty(&spending_policy)?
    );

    Ok(())
}
