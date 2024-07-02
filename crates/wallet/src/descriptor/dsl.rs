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

//! Descriptors DSL

#[doc(hidden)]
#[macro_export]
macro_rules! impl_top_level_sh {
    // disallow `sortedmulti` in `bare()`
    ( Bare, new, new, Legacy, sortedmulti $( $inner:tt )* ) => {
        compile_error!("`bare()` descriptors can't contain any `sortedmulti()` operands");
    };
    ( Bare, new, new, Legacy, sortedmulti_vec $( $inner:tt )* ) => {
        compile_error!("`bare()` descriptors can't contain any `sortedmulti_vec()` operands");
    };

    ( $inner_struct:ident, $constructor:ident, $sortedmulti_constructor:ident, $ctx:ident, sortedmulti $( $inner:tt )* ) => {{
        use core::marker::PhantomData;

        use $crate::miniscript::descriptor::{$inner_struct, Descriptor, DescriptorPublicKey};
        use $crate::miniscript::$ctx;

        let build_desc = |k, pks| {
            Ok((Descriptor::<DescriptorPublicKey>::$inner_struct($inner_struct::$sortedmulti_constructor(k, pks)?), PhantomData::<$ctx>))
        };

        $crate::impl_sortedmulti!(build_desc, sortedmulti $( $inner )*)
    }};
    ( $inner_struct:ident, $constructor:ident, $sortedmulti_constructor:ident, $ctx:ident, sortedmulti_vec $( $inner:tt )* ) => {{
        use core::marker::PhantomData;

        use $crate::miniscript::descriptor::{$inner_struct, Descriptor, DescriptorPublicKey};
        use $crate::miniscript::$ctx;

        let build_desc = |k, pks| {
            Ok((Descriptor::<DescriptorPublicKey>::$inner_struct($inner_struct::$sortedmulti_constructor(k, pks)?), PhantomData::<$ctx>))
        };

        $crate::impl_sortedmulti!(build_desc, sortedmulti_vec $( $inner )*)
    }};

    ( $inner_struct:ident, $constructor:ident, $sortedmulti_constructor:ident, $ctx:ident, $( $minisc:tt )* ) => {{
        use $crate::miniscript::descriptor::{$inner_struct, Descriptor, DescriptorPublicKey};

        $crate::fragment!($( $minisc )*)
            .and_then(|(minisc, keymap, networks)| Ok(($inner_struct::$constructor(minisc)?, keymap, networks)))
            .and_then(|(inner, key_map, valid_networks)| Ok((Descriptor::<DescriptorPublicKey>::$inner_struct(inner), key_map, valid_networks)))
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_top_level_pk {
    ( $inner_type:ident, $ctx:ty, $key:expr ) => {{
        use $crate::miniscript::descriptor::$inner_type;

        #[allow(unused_imports)]
        use $crate::keys::{DescriptorKey, IntoDescriptorKey};
        let secp = $crate::tapyrus::secp256k1::Secp256k1::new();

        $key.into_descriptor_key()
            .and_then(|key: DescriptorKey<$ctx>| key.extract(&secp))
            .map_err($crate::descriptor::DescriptorError::Key)
            .map(|(pk, key_map, valid_networks)| ($inner_type::new(pk), key_map, valid_networks))
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_top_level_tr {
    ( $internal_key:expr, $tap_tree:expr ) => {{
        use $crate::miniscript::descriptor::{
            Descriptor, DescriptorPublicKey, KeyMap, TapTree, Tr,
        };
        use $crate::miniscript::Tap;

        #[allow(unused_imports)]
        use $crate::keys::{DescriptorKey, IntoDescriptorKey, ValidNetworks};

        let secp = $crate::tapyrus::secp256k1::Secp256k1::new();

        $internal_key
            .into_descriptor_key()
            .and_then(|key: DescriptorKey<Tap>| key.extract(&secp))
            .map_err($crate::descriptor::DescriptorError::Key)
            .and_then(|(pk, mut key_map, mut valid_networks)| {
                let tap_tree = $tap_tree.map(
                    |(tap_tree, tree_keymap, tree_networks): (
                        TapTree<DescriptorPublicKey>,
                        KeyMap,
                        ValidNetworks,
                    )| {
                        key_map.extend(tree_keymap.into_iter());
                        valid_networks =
                            $crate::keys::merge_networks(&valid_networks, &tree_networks);

                        tap_tree
                    },
                );

                Ok((
                    Descriptor::<DescriptorPublicKey>::Tr(Tr::new(pk, tap_tree)?),
                    key_map,
                    valid_networks,
                ))
            })
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_leaf_opcode {
    ( $terminal_variant:ident ) => {{
        use $crate::descriptor::CheckMiniscript;

        $crate::miniscript::Miniscript::from_ast(
            $crate::miniscript::miniscript::decode::Terminal::$terminal_variant,
        )
        .map_err($crate::descriptor::DescriptorError::Miniscript)
        .and_then(|minisc| {
            minisc.check_miniscript()?;
            Ok(minisc)
        })
        .map(|minisc| {
            (
                minisc,
                $crate::miniscript::descriptor::KeyMap::default(),
                $crate::keys::any_network(),
            )
        })
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_leaf_opcode_value {
    ( $terminal_variant:ident, $value:expr ) => {{
        use $crate::descriptor::CheckMiniscript;

        $crate::miniscript::Miniscript::from_ast(
            $crate::miniscript::miniscript::decode::Terminal::$terminal_variant($value),
        )
        .map_err($crate::descriptor::DescriptorError::Miniscript)
        .and_then(|minisc| {
            minisc.check_miniscript()?;
            Ok(minisc)
        })
        .map(|minisc| {
            (
                minisc,
                $crate::miniscript::descriptor::KeyMap::default(),
                $crate::keys::any_network(),
            )
        })
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_leaf_opcode_value_two {
    ( $terminal_variant:ident, $one:expr, $two:expr ) => {{
        use $crate::descriptor::CheckMiniscript;

        $crate::miniscript::Miniscript::from_ast(
            $crate::miniscript::miniscript::decode::Terminal::$terminal_variant($one, $two),
        )
        .map_err($crate::descriptor::DescriptorError::Miniscript)
        .and_then(|minisc| {
            minisc.check_miniscript()?;
            Ok(minisc)
        })
        .map(|minisc| {
            (
                minisc,
                $crate::miniscript::descriptor::KeyMap::default(),
                $crate::keys::any_network(),
            )
        })
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_node_opcode_two {
    ( $terminal_variant:ident, $( $inner:tt )* ) => ({
        use $crate::descriptor::CheckMiniscript;

        let inner = $crate::fragment_internal!( @t $( $inner )* );
        let (a, b) = $crate::descriptor::dsl::TupleTwo::from(inner).flattened();

        a
            .and_then(|a| Ok((a, b?)))
            .and_then(|((a_minisc, mut a_keymap, a_networks), (b_minisc, b_keymap, b_networks))| {
                // join key_maps
                a_keymap.extend(b_keymap.into_iter());

                let minisc = $crate::miniscript::Miniscript::from_ast($crate::miniscript::miniscript::decode::Terminal::$terminal_variant(
                    $crate::alloc::sync::Arc::new(a_minisc),
                    $crate::alloc::sync::Arc::new(b_minisc),
                ))?;

                minisc.check_miniscript()?;

                Ok((minisc, a_keymap, $crate::keys::merge_networks(&a_networks, &b_networks)))
            })
    });
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_node_opcode_three {
    ( $terminal_variant:ident, $( $inner:tt )* ) => ({
        use $crate::descriptor::CheckMiniscript;

        let inner = $crate::fragment_internal!( @t $( $inner )* );
        let (a, b, c) = $crate::descriptor::dsl::TupleThree::from(inner).flattened();

        a
            .and_then(|a| Ok((a, b?, c?)))
            .and_then(|((a_minisc, mut a_keymap, a_networks), (b_minisc, b_keymap, b_networks), (c_minisc, c_keymap, c_networks))| {
                // join key_maps
                a_keymap.extend(b_keymap.into_iter());
                a_keymap.extend(c_keymap.into_iter());

                let networks = $crate::keys::merge_networks(&a_networks, &b_networks);
                let networks = $crate::keys::merge_networks(&networks, &c_networks);

                let minisc = $crate::miniscript::Miniscript::from_ast($crate::miniscript::miniscript::decode::Terminal::$terminal_variant(
                    $crate::alloc::sync::Arc::new(a_minisc),
                    $crate::alloc::sync::Arc::new(b_minisc),
                    $crate::alloc::sync::Arc::new(c_minisc),
                ))?;

                minisc.check_miniscript()?;

                Ok((minisc, a_keymap, networks))
            })
    });
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_sortedmulti {
    ( $build_desc:expr, sortedmulti_vec ( $thresh:expr, $keys:expr ) ) => ({
        let secp = $crate::tapyrus::secp256k1::Secp256k1::new();
        $crate::keys::make_sortedmulti($thresh, $keys, $build_desc, &secp)
    });
    ( $build_desc:expr, sortedmulti ( $thresh:expr $(, $key:expr )+ ) ) => ({
        use $crate::keys::IntoDescriptorKey;
        let secp = $crate::tapyrus::secp256k1::Secp256k1::new();

        let keys = vec![
            $(
                $key.into_descriptor_key(),
            )*
        ];

        keys.into_iter().collect::<Result<$crate::alloc::vec::Vec<_>, _>>()
            .map_err($crate::descriptor::DescriptorError::Key)
            .and_then(|keys| $crate::keys::make_sortedmulti($thresh, keys, $build_desc, &secp))
    });

}

#[doc(hidden)]
#[macro_export]
macro_rules! parse_tap_tree {
    ( @merge $tree_a:expr, $tree_b:expr) => {{
        use $crate::miniscript::descriptor::TapTree;

        $tree_a
            .and_then(|tree_a| Ok((tree_a, $tree_b?)))
            .and_then(|((a_tree, mut a_keymap, a_networks), (b_tree, b_keymap, b_networks))| {
                a_keymap.extend(b_keymap.into_iter());
                Ok((TapTree::combine(a_tree, b_tree), a_keymap, $crate::keys::merge_networks(&a_networks, &b_networks)))
            })

    }};

    // Two sub-trees
    ( { { $( $tree_a:tt )* }, { $( $tree_b:tt )* } } ) => {{
        let tree_a = $crate::parse_tap_tree!( { $( $tree_a )* } );
        let tree_b = $crate::parse_tap_tree!( { $( $tree_b )* } );

        $crate::parse_tap_tree!(@merge tree_a, tree_b)
    }};

    // One leaf and a sub-tree
    ( { $op_a:ident ( $( $minisc_a:tt )* ), { $( $tree_b:tt )* } } ) => {{
        let tree_a = $crate::parse_tap_tree!( $op_a ( $( $minisc_a )* ) );
        let tree_b = $crate::parse_tap_tree!( { $( $tree_b )* } );

        $crate::parse_tap_tree!(@merge tree_a, tree_b)
    }};
    ( { { $( $tree_a:tt )* }, $op_b:ident ( $( $minisc_b:tt )* ) } ) => {{
        let tree_a = $crate::parse_tap_tree!( { $( $tree_a )* } );
        let tree_b = $crate::parse_tap_tree!( $op_b ( $( $minisc_b )* ) );

        $crate::parse_tap_tree!(@merge tree_a, tree_b)
    }};

    // Two leaves
    ( { $op_a:ident ( $( $minisc_a:tt )* ), $op_b:ident ( $( $minisc_b:tt )* ) } ) => {{
        let tree_a = $crate::parse_tap_tree!( $op_a ( $( $minisc_a )* ) );
        let tree_b = $crate::parse_tap_tree!( $op_b ( $( $minisc_b )* ) );

        $crate::parse_tap_tree!(@merge tree_a, tree_b)
    }};

    // Single leaf
    ( $op:ident ( $( $minisc:tt )* ) ) => {{
        use $crate::alloc::sync::Arc;
        use $crate::miniscript::descriptor::TapTree;

        $crate::fragment!( $op ( $( $minisc )* ) )
            .map(|(a_minisc, a_keymap, a_networks)| (TapTree::Leaf(Arc::new(a_minisc)), a_keymap, a_networks))
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! apply_modifier {
    ( $terminal_variant:ident, $inner:expr ) => {{
        use $crate::descriptor::CheckMiniscript;

        $inner
            .map_err(|e| -> $crate::descriptor::DescriptorError { e.into() })
            .and_then(|(minisc, keymap, networks)| {
                let minisc = $crate::miniscript::Miniscript::from_ast(
                    $crate::miniscript::miniscript::decode::Terminal::$terminal_variant(
                        $crate::alloc::sync::Arc::new(minisc),
                    ),
                )?;

                minisc.check_miniscript()?;

                Ok((minisc, keymap, networks))
            })
    }};

    ( a: $inner:expr ) => {{
        $crate::apply_modifier!(Alt, $inner)
    }};
    ( s: $inner:expr ) => {{
        $crate::apply_modifier!(Swap, $inner)
    }};
    ( c: $inner:expr ) => {{
        $crate::apply_modifier!(Check, $inner)
    }};
    ( d: $inner:expr ) => {{
        $crate::apply_modifier!(DupIf, $inner)
    }};
    ( v: $inner:expr ) => {{
        $crate::apply_modifier!(Verify, $inner)
    }};
    ( j: $inner:expr ) => {{
        $crate::apply_modifier!(NonZero, $inner)
    }};
    ( n: $inner:expr ) => {{
        $crate::apply_modifier!(ZeroNotEqual, $inner)
    }};

    // Modifiers expanded to other operators
    ( t: $inner:expr ) => {{
        $inner.and_then(|(a_minisc, a_keymap, a_networks)| {
            $crate::impl_leaf_opcode_value_two!(
                AndV,
                $crate::alloc::sync::Arc::new(a_minisc),
                $crate::alloc::sync::Arc::new($crate::fragment!(true).unwrap().0)
            )
            .map(|(minisc, _, _)| (minisc, a_keymap, a_networks))
        })
    }};
    ( l: $inner:expr ) => {{
        $inner.and_then(|(a_minisc, a_keymap, a_networks)| {
            $crate::impl_leaf_opcode_value_two!(
                OrI,
                $crate::alloc::sync::Arc::new($crate::fragment!(false).unwrap().0),
                $crate::alloc::sync::Arc::new(a_minisc)
            )
            .map(|(minisc, _, _)| (minisc, a_keymap, a_networks))
        })
    }};
    ( u: $inner:expr ) => {{
        $inner.and_then(|(a_minisc, a_keymap, a_networks)| {
            $crate::impl_leaf_opcode_value_two!(
                OrI,
                $crate::alloc::sync::Arc::new(a_minisc),
                $crate::alloc::sync::Arc::new($crate::fragment!(false).unwrap().0)
            )
            .map(|(minisc, _, _)| (minisc, a_keymap, a_networks))
        })
    }};
}

/// Macro to write full descriptors with code
///
/// This macro expands to a `Result` of
/// [`DescriptorTemplateOut`](super::template::DescriptorTemplateOut) and [`DescriptorError`](crate::descriptor::DescriptorError)
///
/// The syntax is very similar to the normal descriptor syntax, with the exception that modifiers
/// cannot be grouped together. For instance, a descriptor fragment like `sdv:older(144)` has to be
/// broken up to `s:d:v:older(144)`.
///
/// The `pk()`, `pk_k()` and `pk_h()` operands can take as argument any type that implements
/// [`IntoDescriptorKey`]. This means that keys can also be written inline as strings, but in that
/// case they must be wrapped in quotes, which is another difference compared to the standard
/// descriptor syntax.
///
/// [`IntoDescriptorKey`]: crate::keys::IntoDescriptorKey
///
/// ## Example
///
/// Signature plus timelock descriptor:
///
/// ```
/// # use std::str::FromStr;
/// let (my_descriptor, my_keys_map, networks) = tdk_wallet::descriptor!(sh(and_v(v:pk("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy"),older(50))))?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// -------
///
/// 2-of-3 that becomes a 1-of-3 after a timelock has expired. Both `descriptor_a` and `descriptor_b` are equivalent: the first
/// syntax is more suitable for a fixed number of items known at compile time, while the other accepts a
/// [`Vec`] of items, which makes it more suitable for writing dynamic descriptors.
///
/// They both produce the descriptor: `sh(thresh(2,pk(...),s:pk(...),sndv:older(...)))`
///
/// ```
/// # use std::str::FromStr;
/// let my_key_1 = tapyrus::PublicKey::from_str(
///     "02e96fe52ef0e22d2f131dd425ce1893073a3c6ad20e8cac36726393dfb4856a4c",
/// )?;
/// let my_key_2 =
///     tapyrus::PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy")?;
/// let my_timelock = 50;
///
/// let (descriptor_a, key_map_a, networks) = tdk_wallet::descriptor! {
///     sh (
///         thresh(2, pk(my_key_1), s:pk(my_key_2), s:n:d:v:older(my_timelock))
///     )
/// }?;
///
/// #[rustfmt::skip]
/// let b_items = vec![
///     tdk_wallet::fragment!(pk(my_key_1))?,
///     tdk_wallet::fragment!(s:pk(my_key_2))?,
///     tdk_wallet::fragment!(s:n:d:v:older(my_timelock))?,
/// ];
/// let (descriptor_b, mut key_map_b, networks) =
///     tdk_wallet::descriptor!(sh(thresh_vec(2, b_items)))?;
///
/// assert_eq!(descriptor_a, descriptor_b);
/// assert_eq!(key_map_a.len(), key_map_b.len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ------
///
/// Simple 2-of-2 multi-signature, equivalent to: `sh(multi(2, ...))`
///
/// ```
/// # use std::str::FromStr;
/// let my_key_1 = tapyrus::PublicKey::from_str(
///     "02e96fe52ef0e22d2f131dd425ce1893073a3c6ad20e8cac36726393dfb4856a4c",
/// )?;
/// let my_key_2 =
///     tapyrus::PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy")?;
///
/// let (descriptor, key_map, networks) = tdk_wallet::descriptor! {
///     sh (
///         multi(2, my_key_1, my_key_2)
///     )
/// }?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ------
///
/// Native-Segwit single-sig, equivalent to: `wpkh(...)`
///
/// ```
/// let my_key =
///     tapyrus::PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy")?;
///
/// let (descriptor, key_map, networks) = tdk_wallet::descriptor!(pkh(my_key))?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [`Vec`]: alloc::vec::Vec
#[macro_export]
macro_rules! descriptor {
    ( bare ( $( $minisc:tt )* ) ) => ({
        $crate::impl_top_level_sh!(Bare, new, new, Legacy, $( $minisc )*)
    });
    ( pk ( $key:expr ) ) => ({
        // `pk()` is actually implemented as `bare(pk())`
        $crate::descriptor!( bare ( pk ( $key ) ) )
    });
    ( pkh ( $key:expr ) ) => ({
        use $crate::miniscript::descriptor::{Descriptor, DescriptorPublicKey};

        $crate::impl_top_level_pk!(Pkh, $crate::miniscript::Legacy, $key)
            .and_then(|(a, b, c)| Ok((a.map_err(|e| miniscript::Error::from(e))?, b, c)))
            .map(|(a, b, c)| (Descriptor::<DescriptorPublicKey>::Pkh(a), b, c))
    });
    ( sh ( $( $minisc:tt )* ) ) => ({
        $crate::impl_top_level_sh!(Sh, new, new_sortedmulti, Legacy, $( $minisc )*)
    });
}

#[doc(hidden)]
pub struct TupleTwo<A, B> {
    pub a: A,
    pub b: B,
}

impl<A, B> TupleTwo<A, B> {
    pub fn flattened(self) -> (A, B) {
        (self.a, self.b)
    }
}

impl<A, B> From<(A, (B, ()))> for TupleTwo<A, B> {
    fn from((a, (b, _)): (A, (B, ()))) -> Self {
        TupleTwo { a, b }
    }
}

#[doc(hidden)]
pub struct TupleThree<A, B, C> {
    pub a: A,
    pub b: B,
    pub c: C,
}

impl<A, B, C> TupleThree<A, B, C> {
    pub fn flattened(self) -> (A, B, C) {
        (self.a, self.b, self.c)
    }
}

impl<A, B, C> From<(A, (B, (C, ())))> for TupleThree<A, B, C> {
    fn from((a, (b, (c, _))): (A, (B, (C, ())))) -> Self {
        TupleThree { a, b, c }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! group_multi_keys {
    ( $( $key:expr ),+ ) => {{
        use $crate::keys::IntoDescriptorKey;

        let keys = vec![
            $(
                $key.into_descriptor_key(),
            )*
        ];

        keys.into_iter().collect::<Result<$crate::alloc::vec::Vec<_>, _>>()
            .map_err($crate::descriptor::DescriptorError::Key)
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! fragment_internal {
    // The @v prefix is used to parse a sequence of operands and return them in a vector. This is
    // used by operands that take a variable number of arguments, like `thresh()` and `multi()`.
    ( @v $op:ident ( $( $args:tt )* ) $( $tail:tt )* ) => ({
        let mut v = vec![$crate::fragment!( $op ( $( $args )* ) )];
        v.append(&mut $crate::fragment_internal!( @v $( $tail )* ));

        v
    });
    // Match modifiers
    ( @v $modif:tt : $( $tail:tt )* ) => ({
        let mut v = $crate::fragment_internal!( @v $( $tail )* );
        let first = v.drain(..1).next().unwrap();

        let first = $crate::apply_modifier!($modif:first);

        let mut v_final = vec![first];
        v_final.append(&mut v);

        v_final
    });
    // Remove commas between operands
    ( @v , $( $tail:tt )* ) => ({
        $crate::fragment_internal!( @v $( $tail )* )
    });
    ( @v ) => ({
        vec![]
    });

    // The @t prefix is used to parse a sequence of operands and return them in a tuple. This
    // allows checking at compile-time the number of arguments passed to an operand. For this
    // reason it's used by `and_*()`, `or_*()`, etc.
    //
    // Unfortunately, due to the fact that concatenating tuples is pretty hard, the final result
    // adds in the first spot the parsed operand and in the second spot the result of parsing
    // all the following ones. For two operands the type then corresponds to: (X, (X, ())). For
    // three operands it's (X, (X, (X, ()))), etc.
    //
    // To check that the right number of arguments has been passed we can "cast" those tuples to
    // more convenient structures like `TupleTwo`. If the conversion succeeds, the right number of
    // args was passed. Otherwise the compilation fails entirely.
    ( @t $op:ident ( $( $args:tt )* ) $( $tail:tt )* ) => ({
        ($crate::fragment!( $op ( $( $args )* ) ), $crate::fragment_internal!( @t $( $tail )* ))
    });
    // Match modifiers
    ( @t $modif:tt : $( $tail:tt )* ) => ({
        let (first, tail) = $crate::fragment_internal!( @t $( $tail )* );
        ($crate::apply_modifier!($modif:first), tail)
    });
    // Remove commas between operands
    ( @t , $( $tail:tt )* ) => ({
        $crate::fragment_internal!( @t $( $tail )* )
    });
    ( @t ) => ({});

    // Fallback to calling `fragment!()`
    ( $( $tokens:tt )* ) => ({
        $crate::fragment!($( $tokens )*)
    });
}

/// Macro to write descriptor fragments with code
///
/// This macro will be expanded to an object of type `Result<(Miniscript<DescriptorPublicKey, _>, KeyMap, ValidNetworks), DescriptorError>`. It allows writing
/// fragments of larger descriptors that can be pieced together using `fragment!(thresh_vec(m, ...))`.
///
/// The syntax to write macro fragment is the same as documented for the [`descriptor`] macro.
#[macro_export]
macro_rules! fragment {
    // Modifiers
    ( $modif:tt : $( $tail:tt )* ) => ({
        let op = $crate::fragment!( $( $tail )* );
        $crate::apply_modifier!($modif:op)
    });

    // Miniscript
    ( true ) => ({
        $crate::impl_leaf_opcode!(True)
    });
    ( false ) => ({
        $crate::impl_leaf_opcode!(False)
    });
    ( pk_k ( $key:expr ) ) => ({
        let secp = $crate::tapyrus::secp256k1::Secp256k1::new();
        $crate::keys::make_pk($key, &secp)
    });
    ( pk ( $key:expr ) ) => ({
        $crate::fragment!(c:pk_k ( $key ))
    });
    ( pk_h ( $key:expr ) ) => ({
        let secp = $crate::tapyrus::secp256k1::Secp256k1::new();
        $crate::keys::make_pkh($key, &secp)
    });
    ( after ( $value:expr ) ) => ({
        $crate::impl_leaf_opcode_value!(After, $crate::miniscript::AbsLockTime::from_consensus($value))
    });
    ( older ( $value:expr ) ) => ({
        $crate::impl_leaf_opcode_value!(Older, $crate::tapyrus::Sequence($value)) // TODO!!
    });
    ( sha256 ( $hash:expr ) ) => ({
        $crate::impl_leaf_opcode_value!(Sha256, $hash)
    });
    ( hash256 ( $hash:expr ) ) => ({
        $crate::impl_leaf_opcode_value!(Hash256, $hash)
    });
    ( ripemd160 ( $hash:expr ) ) => ({
        $crate::impl_leaf_opcode_value!(Ripemd160, $hash)
    });
    ( hash160 ( $hash:expr ) ) => ({
        $crate::impl_leaf_opcode_value!(Hash160, $hash)
    });
    ( and_v ( $( $inner:tt )* ) ) => ({
        $crate::impl_node_opcode_two!(AndV, $( $inner )*)
    });
    ( and_b ( $( $inner:tt )* ) ) => ({
        $crate::impl_node_opcode_two!(AndB, $( $inner )*)
    });
    ( and_or ( $( $inner:tt )* ) ) => ({
        $crate::impl_node_opcode_three!(AndOr, $( $inner )*)
    });
    ( andor ( $( $inner:tt )* ) ) => ({
        $crate::impl_node_opcode_three!(AndOr, $( $inner )*)
    });
    ( or_b ( $( $inner:tt )* ) ) => ({
        $crate::impl_node_opcode_two!(OrB, $( $inner )*)
    });
    ( or_d ( $( $inner:tt )* ) ) => ({
        $crate::impl_node_opcode_two!(OrD, $( $inner )*)
    });
    ( or_c ( $( $inner:tt )* ) ) => ({
        $crate::impl_node_opcode_two!(OrC, $( $inner )*)
    });
    ( or_i ( $( $inner:tt )* ) ) => ({
        $crate::impl_node_opcode_two!(OrI, $( $inner )*)
    });
    ( thresh_vec ( $thresh:expr, $items:expr ) ) => ({
        use $crate::miniscript::descriptor::KeyMap;

        let (items, key_maps_networks): ($crate::alloc::vec::Vec<_>, $crate::alloc::vec::Vec<_>) = $items.into_iter().map(|(a, b, c)| (a, (b, c))).unzip();
        let items = items.into_iter().map($crate::alloc::sync::Arc::new).collect();

        let (key_maps, valid_networks) = key_maps_networks.into_iter().fold((KeyMap::default(), $crate::keys::any_network()), |(mut keys_acc, net_acc), (key, net)| {
            keys_acc.extend(key.into_iter());
            let net_acc = $crate::keys::merge_networks(&net_acc, &net);

            (keys_acc, net_acc)
        });

        $crate::impl_leaf_opcode_value_two!(Thresh, $thresh, items)
            .map(|(minisc, _, _)| (minisc, key_maps, valid_networks))
    });
    ( thresh ( $thresh:expr, $( $inner:tt )* ) ) => ({
        let items = $crate::fragment_internal!( @v $( $inner )* );

        items.into_iter().collect::<Result<$crate::alloc::vec::Vec<_>, _>>()
            .and_then(|items| $crate::fragment!(thresh_vec($thresh, items)))
    });
    ( multi_vec ( $thresh:expr, $keys:expr ) ) => ({
        let secp = $crate::tapyrus::secp256k1::Secp256k1::new();

        $crate::keys::make_multi($thresh, $crate::miniscript::Terminal::Multi, $keys, &secp)
    });
    ( multi ( $thresh:expr $(, $key:expr )+ ) ) => ({
        $crate::group_multi_keys!( $( $key ),* )
            .and_then(|keys| $crate::fragment!( multi_vec ( $thresh, keys ) ))
    });
    ( multi_a_vec ( $thresh:expr, $keys:expr ) ) => ({
        let secp = $crate::tapyrus::secp256k1::Secp256k1::new();

        $crate::keys::make_multi($thresh, $crate::miniscript::Terminal::MultiA, $keys, &secp)
    });
    ( multi_a ( $thresh:expr $(, $key:expr )+ ) ) => ({
        $crate::group_multi_keys!( $( $key ),* )
            .and_then(|keys| $crate::fragment!( multi_a_vec ( $thresh, keys ) ))
    });

    // `sortedmulti()` is handled separately
    ( sortedmulti ( $( $inner:tt )* ) ) => ({
        compile_error!("`sortedmulti` can only be used as the root operand of a descriptor");
    });
    ( sortedmulti_vec ( $( $inner:tt )* ) ) => ({
        compile_error!("`sortedmulti_vec` can only be used as the root operand of a descriptor");
    });
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;
    use miniscript::descriptor::{DescriptorPublicKey, KeyMap};
    use miniscript::{Descriptor, Legacy, Segwitv0};
    use tapyrus::secp256k1::Secp256k1;

    use core::str::FromStr;

    use crate::descriptor::DescriptorError;
    use crate::keys::{DescriptorKey, IntoDescriptorKey, ValidNetworks};
    use tapyrus::bip32;
    use tapyrus::Network::{Dev, Prod};
    use tapyrus::PrivateKey;

    // test the descriptor!() macro

    // verify descriptor generates expected script(s) (if bare or pk) or address(es)
    fn check(
        desc: Result<(Descriptor<DescriptorPublicKey>, KeyMap, ValidNetworks), DescriptorError>,
        _is_witness: bool,
        is_fixed: bool,
        expected: &[&str],
    ) {
        let (desc, _key_map, _networks) = desc.unwrap();
        assert_eq!(!desc.has_wildcard(), is_fixed);
        for i in 0..expected.len() {
            let child_desc = desc
                .at_derivation_index(i as u32)
                .expect("i is not hardened");
            let address = child_desc.address(Dev);
            if let Ok(address) = address {
                assert_eq!(address.to_string(), *expected.get(i).unwrap());
            } else {
                let script = child_desc.script_pubkey();
                assert_eq!(script.to_hex_string(), *expected.get(i).unwrap());
            }
        }
    }

    // - at least one of each "type" of operator; i.e. one modifier, one leaf_opcode, one leaf_opcode_value, etc.
    // - mixing up key types that implement IntoDescriptorKey in multi() or thresh()

    // expected script for pk and bare manually created
    // expected addresses created with `bitcoin-cli getdescriptorinfo` (for hash) and `bitcoin-cli deriveaddresses`

    #[test]
    fn test_fixed_legacy_descriptors() {
        let pubkey1 = tapyrus::PublicKey::from_str(
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
        )
        .unwrap();
        let pubkey2 = tapyrus::PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();

        check(
            descriptor!(bare(multi(1,pubkey1,pubkey2))),
            false,
            true,
            &["512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd21032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af52ae"],
        );
        check(
            descriptor!(pk(pubkey1)),
            false,
            true,
            &["2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac"],
        );
        check(
            descriptor!(pkh(pubkey1)),
            false,
            true,
            &["muZpTpBYhxmRFuCjLc7C6BBDF32C8XVJUi"],
        );
        check(
            descriptor!(sh(multi(1, pubkey1, pubkey2))),
            false,
            true,
            &["2MymURoV1bzuMnWMGiXzyomDkeuxXY7Suey"],
        );
    }

    #[test]
    fn test_fixed_threeop_descriptors() {
        let redeem_key = tapyrus::PublicKey::from_str(
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
        )
        .unwrap();
        let move_key = tapyrus::PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();

        check(
            descriptor!(sh(and_or(pk(redeem_key), older(1000), pk(move_key)))),
            false,
            true,
            &["2MxyMCxGYgkYDS3kDDqVjM1EqvF8Wfx6yDn"],
        );
    }

    #[test]
    fn test_bip32_legacy_descriptors() {
        let xprv = bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();

        let path = bip32::DerivationPath::from_str("m/0").unwrap();
        let desc_key = (xprv, path.clone()).into_descriptor_key().unwrap();
        check(
            descriptor!(pk(desc_key)),
            false,
            false,
            &[
                "2102363ad03c10024e1b597a5b01b9982807fb638e00b06f3b2d4a89707de3b93c37ac",
                "2102063a21fd780df370ed2fc8c4b86aa5ea642630609c203009df631feb7b480dd2ac",
                "2102ba2685ad1fa5891cb100f1656b2ce3801822ccb9bac0336734a6f8c1b93ebbc0ac",
            ],
        );

        let desc_key = (xprv, path.clone()).into_descriptor_key().unwrap();
        check(
            descriptor!(pkh(desc_key)),
            false,
            false,
            &[
                "muvBdsVpJxpFuTHMKA47htJPdCvdt4F9DP",
                "mxQSHK7DL2t1DN3xFxov1janCoXSSkrSPj",
                "mfz43r15GiWo4nizmyzMNubsnkDpByFFAn",
            ],
        );

        let path2 = bip32::DerivationPath::from_str("m/2147483647'/0").unwrap();
        let desc_key1 = (xprv, path).into_descriptor_key().unwrap();
        let desc_key2 = (xprv, path2).into_descriptor_key().unwrap();

        check(
            descriptor!(sh(multi(1, desc_key1, desc_key2))),
            false,
            false,
            &[
                "2MtMDXsfwefZkEEhVViEPidvcKRUtJamJJ8",
                "2MwAUZ1NYyWjhVvGTethFL6n7nZhS8WE6At",
                "2MuT6Bj66HLwZd7s4SoD8XbK4GwriKEA6Gr",
            ],
        );
    }

    #[test]
    fn test_dsl_sortedmulti() {
        let key_1 = bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        let path_1 = bip32::DerivationPath::from_str("m/0").unwrap();

        let key_2 = bip32::Xpriv::from_str("tprv8ZgxMBicQKsPegBHHnq7YEgM815dG24M2Jk5RVqipgDxF1HJ1tsnT815X5Fd5FRfMVUs8NZs9XCb6y9an8hRPThnhfwfXJ36intaekySHGF").unwrap();
        let path_2 = bip32::DerivationPath::from_str("m/1").unwrap();

        let desc_key1 = (key_1, path_1);
        let desc_key2 = (key_2, path_2);

        check(
            descriptor!(sh(sortedmulti(1, desc_key1.clone(), desc_key2.clone()))),
            false,
            false,
            &[
                "2MsxzPEJDBzpGffJXPaDpfXZAUNnZhaMh2N",
                "2My3x3DLPK3UbGWGpxrXr1RnbD8MNC4FpgS",
                "2NByEuiQT7YLqHCTNxL5KwYjvtuCYcXNBSC",
                "2N1TGbP81kj2VUKTSWgrwxoMfuWjvfUdyu7",
                "2N3Bomq2fpAcLRNfZnD3bCWK9quan28CxCR",
                "2N9nrZaEzEFDqEAU9RPvDnXGT6AVwBDKAQb",
            ],
        );

        check(
            descriptor!(sh(sortedmulti_vec(1, vec![desc_key1, desc_key2]))),
            false,
            false,
            &[
                "2MsxzPEJDBzpGffJXPaDpfXZAUNnZhaMh2N",
                "2My3x3DLPK3UbGWGpxrXr1RnbD8MNC4FpgS",
                "2NByEuiQT7YLqHCTNxL5KwYjvtuCYcXNBSC",
                "2N1TGbP81kj2VUKTSWgrwxoMfuWjvfUdyu7",
                "2N3Bomq2fpAcLRNfZnD3bCWK9quan28CxCR",
                "2N9nrZaEzEFDqEAU9RPvDnXGT6AVwBDKAQb",
            ],
        );
    }

    // - verify the valid_networks returned is correctly computed based on the keys present in the descriptor
    #[test]
    fn test_valid_networks() {
        let xprv = bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        let path = bip32::DerivationPath::from_str("m/0").unwrap();
        let desc_key = (xprv, path).into_descriptor_key().unwrap();

        let (_desc, _key_map, valid_networks) = descriptor!(pkh(desc_key)).unwrap();
        assert_eq!(valid_networks, [Dev].iter().cloned().collect());

        let xprv = bip32::Xpriv::from_str("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi").unwrap();
        let path = bip32::DerivationPath::from_str("m/10/20/30/40").unwrap();
        let desc_key = (xprv, path).into_descriptor_key().unwrap();

        let (_desc, _key_map, valid_networks) = descriptor!(pkh(desc_key)).unwrap();
        assert_eq!(valid_networks, [Prod].iter().cloned().collect());
    }

    // - verify the key_maps are correctly merged together
    #[test]
    fn test_key_maps_merged() {
        let secp = Secp256k1::new();

        let xprv1 = bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        let path1 = bip32::DerivationPath::from_str("m/0").unwrap();
        let desc_key1 = (xprv1, path1.clone()).into_descriptor_key().unwrap();

        let xprv2 = bip32::Xpriv::from_str("tprv8ZgxMBicQKsPegBHHnq7YEgM815dG24M2Jk5RVqipgDxF1HJ1tsnT815X5Fd5FRfMVUs8NZs9XCb6y9an8hRPThnhfwfXJ36intaekySHGF").unwrap();
        let path2 = bip32::DerivationPath::from_str("m/2147483647'/0").unwrap();
        let desc_key2 = (xprv2, path2.clone()).into_descriptor_key().unwrap();

        let xprv3 = bip32::Xpriv::from_str("tprv8ZgxMBicQKsPdZXrcHNLf5JAJWFAoJ2TrstMRdSKtEggz6PddbuSkvHKM9oKJyFgZV1B7rw8oChspxyYbtmEXYyg1AjfWbL3ho3XHDpHRZf").unwrap();
        let path3 = bip32::DerivationPath::from_str("m/10/20/30/40").unwrap();
        let desc_key3 = (xprv3, path3.clone()).into_descriptor_key().unwrap();

        let (_desc, key_map, _valid_networks) =
            descriptor!(sh(multi(2, desc_key1, desc_key2, desc_key3))).unwrap();
        assert_eq!(key_map.len(), 3);

        let desc_key1: DescriptorKey<Segwitv0> = (xprv1, path1).into_descriptor_key().unwrap();
        let desc_key2: DescriptorKey<Segwitv0> = (xprv2, path2).into_descriptor_key().unwrap();
        let desc_key3: DescriptorKey<Segwitv0> = (xprv3, path3).into_descriptor_key().unwrap();

        let (key1, _key_map, _valid_networks) = desc_key1.extract(&secp).unwrap();
        let (key2, _key_map, _valid_networks) = desc_key2.extract(&secp).unwrap();
        let (key3, _key_map, _valid_networks) = desc_key3.extract(&secp).unwrap();
        assert_eq!(key_map.get(&key1).unwrap().to_string(), "tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy/0/*");
        assert_eq!(key_map.get(&key2).unwrap().to_string(), "tprv8ZgxMBicQKsPegBHHnq7YEgM815dG24M2Jk5RVqipgDxF1HJ1tsnT815X5Fd5FRfMVUs8NZs9XCb6y9an8hRPThnhfwfXJ36intaekySHGF/2147483647'/0/*");
        assert_eq!(key_map.get(&key3).unwrap().to_string(), "tprv8ZgxMBicQKsPdZXrcHNLf5JAJWFAoJ2TrstMRdSKtEggz6PddbuSkvHKM9oKJyFgZV1B7rw8oChspxyYbtmEXYyg1AjfWbL3ho3XHDpHRZf/10/20/30/40/*");
    }

    // - verify the ScriptContext is correctly validated (i.e. passing a type that only impl IntoDescriptorKey<Segwitv0> to a pkh() descriptor should throw a compilation error
    #[test]
    fn test_script_context_validation() {
        // this compiles
        let xprv = bip32::Xpriv::from_str("tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy").unwrap();
        let path = bip32::DerivationPath::from_str("m/0").unwrap();
        let desc_key: DescriptorKey<Legacy> = (xprv, path).into_descriptor_key().unwrap();

        let (desc, _key_map, _valid_networks) = descriptor!(pkh(desc_key)).unwrap();
        assert_eq!(desc.to_string(), "pkh(tpubD6NzVbkrYhZ4WR7a4vY1VT3khMJMeAxVsfq9TBJyJWrNk247zCJtV7AWf6UJP7rAVsn8NNKdJi3gFyKPTmWZS9iukb91xbn2HbFSMQm2igY/0/*)#yrnz9pp2");

        // as expected this does not compile due to invalid context
        //let desc_key:DescriptorKey<Segwitv0> = (xprv, path.clone()).into_descriptor_key().unwrap();
        //let (desc, _key_map, _valid_networks) = descriptor!(pkh(desc_key)).unwrap();
    }

    #[test]
    fn test_dsl_modifiers() {
        let private_key =
            PrivateKey::from_wif("cSQPHDBwXGjVzWRqAHm6zfvQhaTuj1f2bFH58h55ghbjtFwvmeXR").unwrap();
        let (descriptor, _, _) =
            descriptor!(sh(thresh(2,n:d:v:older(1),s:pk(private_key),s:pk(private_key)))).unwrap();

        assert_eq!(descriptor.to_string(), "sh(thresh(2,ndv:older(1),s:pk(02e96fe52ef0e22d2f131dd425ce1893073a3c6ad20e8cac36726393dfb4856a4c),s:pk(02e96fe52ef0e22d2f131dd425ce1893073a3c6ad20e8cac36726393dfb4856a4c)))#qjzsvw99")
    }

    // Uncompressed key is allowed in Legacy Context.
    #[test]
    fn test_dsl_miniscript_checks() {
        let mut uncompressed_pk =
            PrivateKey::from_wif("L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6").unwrap();
        uncompressed_pk.compressed = false;
        descriptor!(pkh(uncompressed_pk)).unwrap();
    }
}
