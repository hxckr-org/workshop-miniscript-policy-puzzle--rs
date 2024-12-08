# Miniscript Policy Puzzle

## Overview

This puzzle is designed to test your understanding of Miniscript, and your ability to construct Miniscript policies that match given spending conditions. Miniscript is a powerful tool for expressing Bitcoin scripts in a more human-readable and manageable way.

## Prerequisites

- Basic knowledge of [Bitcoin scripting](https://learnmeabitcoin.com/technical/script/) and [Miniscript](https://bitcoin.sipa.be/miniscript/).
- Familiarity with the [Bitcoin network](https://developer.bitcoin.org/devguide/p2p_network.html), [transaction structure](https://learnmeabitcoin.com/technical/transaction/), and the concept of [spending conditions](https://bitcoin.design/guide/how-it-works/custom-spending-conditions/#:~:text=Spending%20conditions%20encode%20the%20rules,key%20that%20can%20sign%20transactions).

## Setup

### Quick Start

1. Clone the repository:

```bash
git clone <repository-url>
cd <repository-name>
```

2. Install dependencies:

```bash
cargo build
```

## Passing the First Stage

The entry point to the workshop is each of the files in the [tests](tests) directory. To pass the first stage, you need to create an empty commit and push it to the remote repository.

```bash
git commit --allow-empty -m "Pass the first stage"
git push
```

## Passing Other Stages

Study the code in each of the files in the [tests](tests) directory and fix the bugs. The [stage1_bitcoind.rs](tests/stage1_bitcoind.rs) file contains the test for the first stage. You do not need to run this test, it is run automatically by the CI pipeline. There are comments in the code that will guide you to the solution. When you are done, create a new commit and push it to the remote repository.

```bash
git commit -am "Pass the stage"
git push
```

You should see the logs for your changes in your terminal. Your code will be tested automatically by the CI pipeline. Your changes will be tested against the latest commit in your branch.

You can also run the program manually to test your changes.

```bash
cargo test --test <file_name>
```

For example:

```bash
cargo test --test stage2
```

## Supporting Code

We have provided you with a minimal bitcoind instance that you can use to test your code. The bitcoind instance is configured to use regtest mode, and it has been pre-configured for you. The [src/lib.rs](src/lib.rs) file contains the supporting code for this challenge. DO NOT MODIFY THIS FILE.

## Problem

- **Problem**: Given a description of a Bitcoin transaction's spending conditions, participants are required to construct a corresponding [Miniscript](https://bitcoin.sipa.be/miniscript/) representation.
The goal is to express the provided spending paths in Miniscript, which, when compiled, results in a Bitcoin script that accurately represents these conditions.

- **Expected Outcome**: You should produce a valid Miniscript that, when compiled, generates the correct Bitcoin script. This script must satisfy the provided spending conditions.

- **Validation**: The final Miniscript submitted by you will be compiled into a bitcoin script, funds will be locked to an output with that script, And we will test spending the funds using all the spending conditions in the script.
