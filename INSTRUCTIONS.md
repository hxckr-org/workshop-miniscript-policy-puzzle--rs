# Miniscript Policy Puzzle

This workshop is designed to help you understand the concepts of Miniscript and how to use them to create Bitcoin scripts.

## Exercise Spending Conditions

For this workshop, we present a list of spending conditions for which we
expect the following for each:

- Write a policy.
- Compile to miniscript.
- Generate the mapped bitcoin script.
- Generate an address for the script and we'll lock funds to this address.
- Check that we provide enough information to generate a valid witness to satisfy the spending condition.

The spending conditions presented are below. We provide test files with batteries included so that you can generate policies, compile them, and test their satisfaction by providing an adequate witness.

1. [Single key can spend](./tests/stage2.rs).
2. [One-of-two keys, equally likely to spend](./tests/stage3.rs).
3. [One-of-two keys, one more likely to spend](./tests/stage4.rs).
4. [User key, and service key or timelock](./tests/stage5.rs)

## Resources

- [Rust Miniscript Documentation](https://docs.rs/miniscript/latest/miniscript/)
- [Miniscript Documentation](https://bitcoin.sipa.be/miniscript/)
- [Rust miniscript code example](https://github.com/apoelstra/rust-miniscript/tree/master/examples)
- [Streamlined Bitcoin Scripting With Miniscript](https://medium.com/blockstream/miniscript-bitcoin-scripting-3aeff3853620)
- [Custom Spending Conditions](https://bitcoin.design/guide/how-it-works/custom-spending-conditions/#:~:text=Spending%20conditions%20encode%20the%20rules,key%20that%20can%20sign%20transactions.)
- [BIP 379: Miniscript](https://github.com/bitcoin/bips/blob/master/bip-0379.md)
- [Miniscript Puzzle Overview](https://enigbe.gitbook.io/btrust_sg/miniscript)
