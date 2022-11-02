# README

[TOC]

## 1. 描述

本仓库基于零知识证明开源库 [arkworks](https://github.com/arkworks-rs) 实现了[PLONK](https://eprint.iacr.org/2019/953.pdf)和[PLOOKUP](https://eprint.iacr.org/2020/315.pdf)协议，并在此基础上实现了子串匹配，哈希算法sha256，哈希算法mimc，range等 自定义电路门（Custome Gate）。其中哈希算法 sha256 由于哈希原文长度上限的不同电路大小也会有所不同，所以分别设计了长度上限为1024字节和2048字节的电路。子串匹配算法分为两种，一种是子串为公开信息，一种是子串为隐藏的秘密信息。

基于以上零知识证明算法及电路的实现，本项目实现了对 Mailheader 中的特定信息（包括发件 from email、subject、selector、domain 等字段，其中发件邮箱为隐藏秘密信息）的内容检查和索引位置检查，以及 Mailheader 及 from email 的哈希值校验。其中from email为秘密信息，subject、selector、domain 为公开信息。协助完成基于 DKIM 协议的邮件身份验证的功能。

代码共分为三个部分：

1. Plonk with Plookup 算法实现（Rust）
2. Email-Header 字符串匹配等相关计算的电路
3. 由 Solidity 语言实现的合约上验证代码

## 2.  用法

### 2.1 环境配置

#### 2.1.1 Rust

安装最新版 Rust，安装说明参考[官方指引](https://www.rust-lang.org/tools/install)。

检查 Rust 安装

```shell
rustc --version
rustc 1.62.1 (e092d0b6b 2022-07-16)
```

#### 2.1.2 Hardhat

安装最新版 Hardhat，安装说明参考[官方指引](https://hardhat.org/hardhat-runner/docs/getting-started#installation)。

检查 Hardhat 安装

```shell
npx hardhat --version
2.11.2
```



### 2.2 运行

#### 2.2.1 运行 Rust 测试用例

1. 进入文件夹`unipass-examples`

   ```shell
   cd unipass-examples
   ```

2. 编译Rust代码及测试用例

   ```shell
   cargo build
   ```

3. 运行测试用例

   ```shell
   cargo run
   ```

   编译运行的是 `src/main.rs` 中的代码，共五组测试用例，运行成功后导出一组文件，包括 pk 和承诺数据和证明数据等。

#### 2.2.2 运行合约代码

1. 进入子文件夹 `unipass-verifier-contract `

   ```shell
   cd unipass-verifier-contract 
   ```

2. 拷贝五个测试用例产生的 proof 文件

   ```shell
   cp ../unipass1024example01.txt ../unipassexample01.txt ../unipassexample02.txt ../unipassexample03.txt ../unipassexample04.txt .
   ```

3. 编译合约及测试代码

   ```shell
   npx hardhat compile
   ```

4. 运行测试用例

   ```shell
   npx hardhat test --verbose     
   ```

   输出打印日志

   ```shell
   > [INIT] deployer.address = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 ...... 
   > [DPLY] Contract deployed, addr=0x5FbDB2315678afecb367f032d93F642f64180aa3  
   test start
   test verify
   ...
       ✔ part verify test (4125ms)
   
   
     1 passing (5s)
   ```

## 3. 代码说明

### 3.1 代码结构

`unipass-examples` 中代码分为三部分，Rust 语言实现的算法代码，Solidity 合约代码及 Rust 测试代码。

```shell
├── Cargo.lock 
├── Cargo.toml
├── plookup-sha256
├── src
└── unipass-verifier-contract
```

#### 3.1.1 Rust 语言算法代码

```rust
plookup-sha256
├── Cargo.lock
├── Cargo.toml
└── src
    ├── composer      // 电路部分的主要代码
    ├── kzg10.rs      // KZG10协议代码的实现
    ├── lib.rs        // plookup-sha256的入口
    ├── proof.rs      // Proof 结构体
    ├── prover        // 产生证明部分的主要代码
    ├── serialize.rs  // 数据的序列化处理
    ├── sha256.rs		  // sha256电路代码
    ├── substring.rs  // 字符串匹配相关的
    ├── transcript.rs // 做substring单独验证的代码
    ├── utils.rs	    // 工具类函数
    └── verifier.rs   // 验证部分的代码
```

本文件基于 [arkworks](https://github.com/arkworks-rs) 仓库实现了包含substring，sha256电路的 [PLONK](https://eprint.iacr.org/2019/953.pdf)和 [PLOOKUP](https://eprint.iacr.org/2020/315.pdf)。其中`composer` ，`substring.rs`和 `sha256.rs`为电路部分内容；`proof.rs` 和 `prover` 为产生证明部分；`verifier.rs`为验证证明部分；`kzg10.rs` 为KZG10协议的实现，是Plonk协议不可或缺的一部分；`transcript.rs` 是用来做Fiat-Shamir 变换的相关代码。

prover文件夹下为构造证明的相关代码实现。

```rust
├── mod.rs        // Prover 结构体的相关函数代码
├── prover_key.rs // 对电路的一些预处理（将向量插值为多项式，以及计算coset fft）的相关函数代码
└── widget // 各个电路模块的相关代码
    ├── arithmetic.rs    // 算术电路相关的代码实现
    ├── lookup.rs				 // lookup 的相关的代码实现
    ├── mimc.rs					 // mimc 哈希相关的代码实现
    ├── mod.rs           // 将 custom gates 抽象为 “widget”
    ├── permutation.rs	 // copy constraint 相关部分的代码实现
    ├── pubmatch.rs			 // 公开子串的 substring 算法相关代码实现
    ├── range.rs				 // range proof 的相关代码实现
    └── substring.rs		 // 秘密子串的 substring 算法相关代码实现
```

`mod.rs` 为主文件，用来生产 proof；`prover_key.rs` 对电路的一些预处理（将向量插值为多项式，以及计算 coset fft）; `widget` 下为各个电路模块的相关代码：`mod.rs` 下将 custom gates 抽象为“widget”，`arithmetic.rs` 下为算术电路相关的实现；`permutation.rs`下为 copy constraint 相关部分的代码实现，`lookup.rs`下为 lookup 的相关代码实现，`substring.rs` 下为秘密子串的 substring 代码实现，`pubmatch.rs` 下为公开子串的 substring 算法相关的代码实现，`range.rs`为 range proof 的相关代码实现，`mimc.rs`为 mimc 哈希相关的代码实现。

composer 文件夹下为电路部分的相关代码实现。

```rust
├── arithmetic.rs	 // 算术电路相关的实现代码
├── lookup.rs      // lookup的相关的电路代码实现
├── mimc.rs				 // mimc哈希相关的电路代码实现
├── mod.rs				 // 定义了PLONK电路相关的结构体和一些基础的方法
├── permutation.rs // plonk电路的copy constraint部分相关的电路代码实现
├── range.rs			 // range proof相关的电路代码实现
└── substring.rs	 // substring算法相关的电路代码实现，包括公开字串匹配和秘密子串匹配
```

`mod.rs` 文件定义了 PLONK 电路相关的结构体和一些基础的方法，比如分配变量 Variable，按行添加 witness 等；`arithmetic.rs` plonk 电路的算术门部分；`lookup.rs` 是 lookup 电路的部分，在电路中支持的table的格式，以及在电路中查表的操作，并预置了一个可生成“n比特异或表”的方法；`permutation.rs`实现了 plonk 电路的 copy constraint 部分，`substring.rs` 实现了电路的substring相关的 custom gates 部分，包括公开字串匹配和秘密子串匹配；`range.rs`实现了 range proof 的电路部分；`mimc.rs` 实现了 mimc 哈希的电路部分。

#### 3.1.2 Solidity 合约代码

```rust
unipass-verifier-contract
├── contracts
│   ├── PlonkCoreLib.sol			// 包含两个 library，分别处理 Bn254 曲线下的相关运算和 Fiat-Shamir 变换
│   └── PlookupSingleCore.sol	// 包含两个合约，分别是协议验证部分的代码及对验证代码的封装接口
├── hardhat.config.js				  // Hardhat 工具的配置文件
└── test
    └── PlookupSingleCore.js  // 合约测试代码
```

本文件为合约代码及合约代码的测试代码文件。其中 `contracts` 中为合约代码，实现了协议的 verifier 部分，其中 PlonkCoreLib.sol中包含两个 library，PlookupSingleCore.sol 中包含两个合约结构；`hardhat.config.js ` 为 Hardhat 工具的配置文件；test 下为 js 实现的合约测试代码。

#### 3.1.3 Rust测试代码

```shell
src
└── main.rs
```

本文件下为 Rust 代码的测试代码。`main.rs` 中共包含五个测试用例。

```rust
fn main() -> Result<(), SerializationError> {
    example01()?;
    example02()?;
    example03()?;
    example04()?;
    example01_1024()?;

    Ok(())
}
```

默认情况下，sha256 支持的哈希原文长度为 2048 字节，为了减小电路，代码中也同时实现了最大原文长度为 1024 字节的哈希的电路。测试用例的前4组不同 emailheader 下产生证明和验证证明的测试，使用默认的最大原文长度为 2048 字节的哈希算法产生电路， `example01_1024()` 是使用第一组测试用例，在 sha256 的最大原文长度为 1024 字节的的电路下做的测试。

四组测试均用例来源于 `email_example4.zip`。

### 3.2 接口说明

#### 3.2.1 Rust 语言算法代码主要接口

##### 3.2.1.1 PCKey

```rust
pub struct PCKey<E: PairingEngine> {
    /// The key used to commit to polynomials.
    pub powers: Vec<E::G1Affine>,
    /// The maximum degree supported by the `UniversalParams` `self` was derived from.
    pub max_degree: usize,

    pub vk: VKey<E>,
}

#[derive(Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct VKey<E: PairingEngine> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,

    pub max_degree: usize,
}
```

PCKey结构体为 KZG10 的算法产生的一组 key。主要API接口：

1. setup函数

   `pub fn setup<R>(max_degree: usize, rng: &mut R) -> PCKey<E>`

   本函数为 KZG10 协议的 setup 步骤，用于产生多项式承诺的相关pk和vk。

   a. 输入值

   | 参数       | 数据类型     | 描述信息      |
   | ---------- | ------------ | ------------- |
   | max_degree | usize        | key的最高阶数 |
   | rng        | &mut RngCore | 随机生成源    |

   b. 输出值

   | 输出类型             | 描述信息                    |
   | -------------------- | --------------------------- |
   | PCKey<PairingEngine> | 结构体 PCKey，保存产生的key |

2. commit_one 函数

   `pub fn commit_one<F: PrimeField>(&self, polynomial: &DensePolynomial<F>) -> Commitment<E> `

   本函数对一组多项式参数做多项式承诺。

   a. 输入值

   | 参数       | 数据类型                     | 描述信息            |
   | ---------- | ---------------------------- | ------------------- |
   | self       | PCKey<PairingEngine>         | 产生承诺所使用的key |
   | polynomial | &DensePolynomial<PrimeField> | 要承诺的多项式      |

   b. 输出值

   | 输出类型                  | 描述信息     |
   | ------------------------- | ------------ |
   | Commitment<PairingEngine> | 多项式的承诺 |

3. commit_vec函数

   `pub fn commit_vec<F: PrimeField>(&self, polynomials: &[DensePolynomial<F>],) -> Vec<Commitment<E>> `

   本函数批量对多组多项式参数分别做多项式承诺。

   a. 输入值

   | 参数        | 数据类型                       | 描述信息            |
   | ----------- | ------------------------------ | ------------------- |
   | self        | PCKey<PairingEngine>           | 产生承诺所使用的key |
   | polynomials | &[DensePolynomial<PrimeField>] | 多个要承诺的多项式  |

   b. 输出值

   | 输出类型                       | 描述信息         |
   | ------------------------------ | ---------------- |
   | Vec<Commitment<PairingEngine>> | 多个多项式的承诺 |

4. open_one函数

   `pub fn open_one<F: PrimeField>(&self, polynomial: &DensePolynomial<F>, point: F) -> Commitment<E>`	

   本函数用于产生一个多项式承诺的证明。

   a. 输入值

   | 参数       | 数据类型                     | 描述信息            |
   | ---------- | ---------------------------- | ------------------- |
   | self       | PCKey<PairingEngine>         | 产生证明所使用的key |
   | polynomial | &DensePolynomial<PrimeField> | 承诺的多项式        |
   | point      | PrimeField                   | 挑战点              |

   b. 输出值

   | 输出类型                  | 描述信息         |
   | ------------------------- | ---------------- |
   | Commitment<PairingEngine> | 多项式承诺的证明 |

5. verify_pc 函数

   `pub fn verify_pc<F: PrimeField>(&self, comm: &Commitment<E>, point: F,  point_eval: F, pi: &Commitment<E>) -> bool`

   多项式承诺的验证。

   a. 输入值

   | 参数       | 数据类型                   | 描述信息                  |
   | ---------- | -------------------------- | ------------------------- |
   | self       | VKey<PairingEngine>        | 验证证明的vk              |
   | comm       | &Commitment<PairingEngine> | 多项式承诺                |
   | point      | PrimeField                 | 挑战点                    |
   | point_eval | PrimeField                 | 多项式在point处的计算结果 |
   | pi         | &Commitment<PairingEngine> | 多项式承诺的证明          |

   b. 输出值

   | 输出类型 | 描述信息 |
   | -------- | -------- |
   | bool     | 验证结果 |

6. batch_verify_multi_point_open_pc 函数

   `pub fn batch_verify_multi_point_open_pc<F: PrimeField>(&self, comms: &[Commitment<E>], points: &[F], point_evals: &[F], pis: &[Commitment<E>], v: F,) -> bool`

   对多个多项式在不同open点处产生的证明的验证。

   a. 输入值

   | 参数        | 数据类型                     | 描述信息                            |
   | ----------- | ---------------------------- | ----------------------------------- |
   | self        | VKey<PairingEngine>          | 验证证明的vk                        |
   | comm        | &[Commitment<PairingEngine>] | 多个多项式承诺                      |
   | points      | &[PrimeField]                | 多个挑战点                          |
   | point_evals | &[PrimeField]                | 各个多项式在对应的point处的计算结果 |
   | Pis         | &[Commitment<PairingEngine>] | 多个多项式承诺的证明                |

   b. 输出值

   | 输出类型 | 描述信息 |
   | -------- | -------- |
   | bool     | 验证结果 |

   

##### 3.2.1.2 Composer

```rust
pub struct Composer<F: Field> {
    pub program_width: usize, // 电路的宽度

    size: usize, // 电路的数量
    is_finalized: bool, // 电路构造是否结束的标记

    wires: Map<String, Vec<Variable>>, // 每一列witness上的所有变量
    selectors: Map<String, Vec<F>>,
    public_input: Vec<Variable>, // 公开输入值的变量

    assignments: Vec<F>,	// 每个变量的取值
    epicycles: Vec<Vec<Wire>>, // 每个变量所在位置的统计
    tables: Vec<Table<F>>, // lookup 表

    pub contain_range: bool, // 是否包含range电路的标记
    pub contain_lookup: bool, // 是否包含lookup电路的标记
    pub contain_mimc: bool, // 是否包含mimc电路的标记
    pub contain_mask_poly: bool, // 是否包含子串匹配（子串为秘密值）电路的标记
    pub contain_pubmatch: bool, // 是否包含子串匹配（子串为公开值）电路的标记
}
```

Composer结构体下保存电路部分信息。主要API接口：

1. new函数

   `pub fn new(program_width: usize) -> Composer<F> `

   初始化 Composer 结构体。

   a. 输入值

   | 参数          | 数据类型 | 描述信息 |
   | ------------- | -------- | -------- |
   | program_width | usize    | 电路宽度 |

   b. 输出值

   | 输出类型        | 描述信息                                |
   | --------------- | --------------------------------------- |
   | Composer<Field> | 结构体 Composer，包含电路相关的所有数据 |

2. alloc函数

   `pub fn alloc(&mut self, value: F) -> Variable`

   分配私有变量。

   a. 输入值

   | 参数  | 数据类型        | 描述信息                                |
   | ----- | --------------- | --------------------------------------- |
   | self  | Composer<Field> | Composer 结构体，包含电路相关的所有数据 |
   | value | Field           | 变量值                                  |

   b. 输出值

   | 输出类型 | 描述信息   |
   | -------- | ---------- |
   | Variable | 分配的变量 |

3. alloc_input函数

   `pub fn alloc_input(&mut self, value: F) -> Variable`

   分配公开变量。先分配变量，再设置成公开变量。

   a. 输入值

   | 参数  | 数据类型        | 描述信息                                |
   | ----- | --------------- | --------------------------------------- |
   | self  | Composer<Field> | Composer 结构体，包含电路相关的所有数据 |
   | value | Field           | 变量值                                  |

   b. 输出值

   | 输出类型 | 描述信息   |
   | -------- | ---------- |
   | Variable | 分配的变量 |

4. set_variable_public_input 函数

   `pub fn set_variable_public_input(&mut self, var: Variable)`

   设置公开变量。

   a. 输入值

   | 参数 | 数据类型        | 描述信息                                |
   | ---- | --------------- | --------------------------------------- |
   | self | Composer<Field> | Composer 结构体，包含电路相关的所有数据 |
   | var  | Variable        | 要设置的变量                            |

5. compute_prover_key函数

   `pub fn compute_prover_key<D: Domain<F>>(&mut self) -> Result<ProverKey<F, D>, Error>`

   根据Composer 结构体中的信息产生ProverKey。

   a. 输入值

   | 参数 | 数据类型      | 描述信息        |
   | ---- | ------------- | --------------- |
   | D    | Domain<Field> | 做 FFT 运算的域 |

   b. 输出值

   | 输出类型                        | 描述信息         |
   | ------------------------------- | ---------------- |
   | ProverKey<Field, Domain<Field>> | ProverKey 结构体 |
   | Error                           | 错误信息         |

6. compute_public_input 函数

   `pub fn compute_public_input(&mut self) -> Vec<F>`

   获取公开输入值。

   a. 输入值

   | 参数 | 数据类型        | 描述信息                                |
   | ---- | --------------- | --------------------------------------- |
   | self | Composer<Field> | Composer 结构体，包含电路相关的所有数据 |

   b. 输出值

   | 输出类型   | 描述信息       |
   | ---------- | -------------- |
   | Vec<Field> | public input值 |

7. poly_gate 函数

   `pub fn poly_gate(&mut self, wires: Vec<(Variable, F)>, mul_scaling: F, const_scaling: F)`

   插入算术门。

   a. 输入值

   | 参数          | 数据类型               | 描述信息                                |
   | ------------- | ---------------------- | --------------------------------------- |
   | self          | Composer<Field>        | Composer 结构体，包含电路相关的所有数据 |
   | wires         | Vec<(Variable, Field)> | 所有变量及其系数                        |
   | mul_scaling   | Field                  | qm                                      |
   | const_scaling | Field                  | qc                                      |

8. add_substring_mask_poly 函数

   `pub fn add_substring_mask_poly(&mut self, a: &Vec<Variable>, b: &Vec<Variable>, mask: Variable, l: Variable, m: Variable,) -> Result<(Vec<Variable>, Variable), Error>`

   添加秘密值字符串匹配的电路，约束b的前m个字符一定能从 a 的 l 位置开始匹配，a字符串的长度上限为2048字节。

   a. 输入值

   | 参数 | 数据类型        | 描述信息                 |
   | ---- | --------------- | ------------------------ |
   | self | Composer<Field> | Composer 结构体          |
   | a    | &Vec<Variable>  | 匹配的原字符串           |
   | b    | &Vec<Variable>  | 匹配的子串               |
   | mask | Variable        | 字符串匹配算法中的随机数 |
   | l    | Variable        | b 在 a 中的起始位置      |
   | m    | Variable        | b 的长度                 |

   b. 输出值

   | 输出类型      | 描述信息                                                     |
   | ------------- | ------------------------------------------------------------ |
   | Vec<Variable> | 标记位置的变量，用‘01串’来标记b在a中的位置，l开始的m个位置为1，其它为0 |
   | Variable      | 标记位置的变量，用‘01串’来标记b，前m个位置为1，其它为0       |
   | Error         | 错误信息                                                     |

   *注：由于a字符串的长度过长，无法用一个Field表示，所以分配多个变量来表示。当字符串长度上限为2048字节时，需要占用9个Field才能表示出来，因此需要分配9个变量Variable*

9. add_substring_mask_poly_1024

   `pub fn add_substring_mask_poly_1024(&mut self, a: &Vec<Variable>, b: &Vec<Variable>, mask: Variable, l: Variable, m: Variable,) -> Result<(Vec<Variable>, Variable), Error>`

   添加秘密值字符串匹配的电路，约束b的前m个字符一定能从 a 的 l 位置开始匹配，a字符串的长度上限为 1024 字节。

   a. 输入值

   | 参数 | 数据类型        | 描述信息                 |
   | ---- | --------------- | ------------------------ |
   | self | Composer<Field> | Composer 结构体          |
   | a    | &Vec<Variable>  | 匹配的原字符串           |
   | b    | &Vec<Variable>  | 匹配的子串               |
   | mask | Variable        | 字符串匹配算法中的随机数 |
   | l    | Variable        | b 在 a 中的起始位置      |
   | m    | Variable        | b 的长度                 |

   b. 输出值

   | 输出类型      | 描述信息                                                     |
   | ------------- | ------------------------------------------------------------ |
   | Vec<Variable> | 标记位置的变量，用‘01串’来标记b在a中的位置，l开始的m个位置为1，其它为0 |
   | Variable      | 标记位置的变量，用‘01串’来标记b，前m个位置为1，其它为0       |
   | Error         | 错误信息                                                     |

10. add_public_match

    `pub fn add_public_match(&mut self, a: &Vec<Variable>, b: &Vec<Variable>,max_lens: usize,) -> Result<(), Error>`

    添加公开字符串匹配，a和b的长度相等。默认当b的某个字节为0时，对应的a字符串的字符不会公开，b的不为0的字节都必须与a相匹配。

    a. 输入值

    | 参数     | 数据类型        | 描述信息           |
    | -------- | --------------- | ------------------ |
    | self     | Composer<Field> | Composer 结构体    |
    | a        | &Vec<Variable>  | 匹配的原字符串     |
    | b        | &Vec<Variable>  | 待匹配的公开字符串 |
    | max_lens | usize           | 字符串 a和 b的长度 |

    b. 输出值

    | 输出类型 | 描述信息 |
    | -------- | -------- |
    | Error    | 错误信息 |

##### 3.2.1.3 Prover

```rust
pub struct ProverKey<F: Field, D: Domain<F>> {
    pub circuit_size: usize, // 电路的数量
    pub input_size: usize, // 公开输入的数量
    pub program_width: usize, // 电路的宽度
    pub domain: D, // 做FFT运算的域
    pub coset: D, // 做coset FFT运算的域
    domain_values: Map<String, Vec<F>>, // domain上做计算的多项式取值
    coset_values: Map<String, Vec<F>>, // coset domain上做计算的多项式取值
    polynomials: Map<String, DensePolynomial<F>>, // 做计算的多项式

    pub contain_range: bool, // 是否包含range电路的标记
    pub contain_lookup: bool, // 是否包含lookup电路的标记
    pub contain_mimc: bool, // 是否包含mimc电路的标记
    pub contain_mask_poly: bool, // 是否包含子串匹配（子串为秘密值）电路的标记
    pub contain_pubmatch: bool, // 是否包含子串匹配（子串为公开值）电路的标记
}

pub struct Prover<F: Field, D: Domain<F>, E: PairingEngine> {
    domain_values: Map<String, Vec<F>>, // domain上做计算的多项式取值
    coset_values: Map<String, Vec<F>>,  // coset domain上做计算的多项式取值
    polynomials: Map<String, DensePolynomial<F>>, // 做计算的多项式

    challenges: Map<String, F>, // 所有随机挑战数
    pub evaluations: Map<String, F>, //多项式在open点处的计算值
    pub commitments: Map<String, Commitment<E>>, // 多项式的承诺

    pub domain: D, // 做FFT运算的域
    pub coset: D, // 做coset FFT运算的域
    pub program_width: usize, // 电路的宽度
    pub contain_range: bool, // 是否包含range电路的标记
    pub contain_lookup: bool, // 是否包含lookup电路的标记
    pub contain_mimc: bool, // 是否包含mimc电路的标记
    pub contain_mask_poly: bool, // 是否包含子串匹配（子串为秘密值）电路的标记
    pub contain_pubmatch: bool, // 是否包含子串匹配（子串为公开值）电路的标记
}
```

Prover 下主要是产生证明的相关函数。主要API接口：

1. （ProverKey）new函数

   `pub fn new(circuit_size: usize, input_size: usize, program_width: usize, contain_range: bool, contain_lookup: bool, contain_mimc: bool, contain_mask_poly: bool, contain_pubmatch: bool) -> Result<ProverKey<Field, Domain<Field>>, Error> `

   创建ProverKey结构体。

   a. 输入值

   | 参数              | 数据类型 | 描述信息                  |
   | ----------------- | -------- | ------------------------- |
   | circuit_size      | usize    | 电路数量                  |
   | input_size        | usize    | 公开输入长度              |
   | program_width     | usize    | 电路宽度                  |
   | contain_range     | bool     | 是否包含range proof的电路 |
   | contain_lookup    | bool     | 是否包含lookup的电路      |
   | contain_mimc      | bool     | 是否包含mimc的电路        |
   | contain_mask_poly | bool     | 是否包含秘密值匹配的电路  |
   | contain_pubmatch  | bool     | 是否包含公开值匹配的电路  |

   b. 输出值

   | 输出类型                        | 描述信息         |
   | ------------------------------- | ---------------- |
   | ProverKey<Field, Domain<Field>> | 结构体 ProverKey |
   | Error                           | 错误信息         |

2. （Prover）new函数

   `pub fn new(prover_key: ProverKey<F, D>) -> Prover<Field, Domain<Field>, PairingEngine>`

   创建Prover结构体。

   a. 输入值

   | 参数       | 数据类型                       | 描述信息     |
   | ---------- | ------------------------------ | ------------ |
   | prover_key | ProverKey<Field, Domain<Field> | 结构体Prover |

   b. 输出值

   | 输出类型                                    | 描述信息      |
   | ------------------------------------------- | ------------- |
   | Prover<Field, Domain<Field>, PairingEngine> | 结构体 Prover |

3. init_comms 函数

   `pub fn init_comms(&mut self, pckey: &PCKey<E>) -> Vec<Commitment<E>>`

   对电路中所有的多项式做多项式承诺。

   a. 输入值

   | 参数  | 数据类型                                    | 描述信息      |
   | ----- | ------------------------------------------- | ------------- |
   | self  | Prover<Field, Domain<Field>, PairingEngine> | 结构体 Prover |
   | pckey | &PCKey<PairingEngine>                       | pk 的结构体   |

   b. 输出值

   | 输出类型                       | 描述信息                 |
   | ------------------------------ | ------------------------ |
   | Vec<Commitment<PairingEngine>> | 电路中所有的多项式的承诺 |

4. prove函数

   `pub fn prove<R: RngCore>(&mut self, cs: &mut Composer<F>, pckey: &PCKey<E>, rng: &mut R,) -> Result<Proof<F, E>, Error> `

   产生plonk证明。

   a. 输入值

   | 参数  | 数据类型                                    | 描述信息             |
   | ----- | ------------------------------------------- | -------------------- |
   | self  | Prover<Field, Domain<Field>, PairingEngine> | 结构体 Prover        |
   | cs    | &mut Composer<Field>                        | 电路Composer的结构体 |
   | pckey | &PCKey<PairingEngine>                       | pk 的结构体          |
   | rng   | &mut RngCore                                | 随机数生成源         |

   b. 输出值

   | 输出类型                    | 描述信息         |
   | --------------------------- | ---------------- |
   | Proof<Field, PairingEngine> | 产生的证明结构体 |
   | Error                       | 错误信息         |

##### 3.2.1.4 Verifier

```rust
pub struct Verifier<F: Field, D: Domain<F>, E: PairingEngine> {
    pub program_width: usize,   // 电路的宽度
    pub contain_range: bool,   // 是否包含range电路的标记
    pub contain_lookup: bool,   // 是否包含lookup电路的标记
    pub contain_mimc: bool,  // 是否包含mimc电路的标记
    pub contain_mask_poly: bool,  // 是否包含子串匹配（子串为秘密值）电路的标记
    pub contain_pubmatch: bool,  // 是否包含子串匹配（子串为公开值）电路的标记

    pub public_input: Vec<F>, // 公共输入值
    pub commitments: Map<String, Commitment<E>>, // 多项式的承诺
    pub evaluations: Map<String, F>, //多项式在open点处的计算值

    pub domain_generator: F, // domain 域上的生成元

    pub domain: D, // 做FFT运算的域
}
```

Verifier 下主要是验证证明的相关函数。主要API接口：

1. new函数

   `pub fn new(prover: &Prover<F, D, E>, public_input: &Vec<F>, v_comms: &Vec<Commitment<E>>) -> Verifier<Field, Domain<F>, PairingEngine>`

   创建Verifier结构体。

   a. 输入值

   | 参数         | 数据类型                                 | 描述信息                 |
   | ------------ | ---------------------------------------- | ------------------------ |
   | prover       | &Prover<Field, Domain<F>, PairingEngine> | Prover 结构体            |
   | public_input | &Vec<Field>                              | 公开输入值               |
   | v_comms      | &Vec<Commitment<PairingEngine>>          | 电路中所有的多项式的承诺 |

   b. 输出值

   | 输出类型                                      | 描述信息        |
   | --------------------------------------------- | --------------- |
   | Verifier<Field, Domain<Field>, PairingEngine> | 结构体 Verifier |

2. verify函数

   `pub fn verify(&mut self, pcvk: &VKey<E>, proof: &Proof<F, E>)`

   对证明进行验证。

   a. 输入值

   | 参数  | 数据类型                                      | 描述信息        |
   | ----- | --------------------------------------------- | --------------- |
   | self  | Verifier<Field, Domain<Field>, PairingEngine> | 结构体 Verifier |
   | pcvk  | &VKey<PairingEngine>                          | vk的结构体      |
   | proof | &Proof<Field, PairingEngine>                  | proof 的结构体  |

#### 3.2.2 Solidity 合约代码主要接口

合约代码中总共包含两个library和两个合约。

##### 3.2.2.1 library PairingsBn254 

用来处理Bn254曲线下的相关运算。

##### 3.2.2.2 library TranscriptLibrary

用来处理 Fiat-Shamir 变换的相关接口。

1. new_transcript 函数

   `function new_transcript() internal pure returns (Transcript memory t)`

   构造一个transcript 结构体，用来做Fiat-Shamir 变换产生随机数。

   a. 输出值

   | 输出值 | 输出类型          | 描述信息          |
   | ------ | ----------------- | ----------------- |
   | t      | Transcript memory | 结构体 Transcript |

2. update_with_u256 函数

   `function update_with_u256(Transcript memory self, uint256 value)`

   更新一个 uint256 值到transcript中。

   a. 输入值

   | 参数  | 数据类型          | 描述信息          |
   | ----- | ----------------- | ----------------- |
   | self  | Transcript memory | 结构体 Transcript |
   | value | uint256           | 输入值            |

3. update_with_fr 函数

   `function update_with_fr(Transcript memory self, PairingsBn254.Fr memory value)`

   更新一个 Fr 值到transcript中。

   a. 输入值

   | 参数  | 数据类型                | 描述信息          |
   | ----- | ----------------------- | ----------------- |
   | self  | Transcript memory       | 结构体 Transcript |
   | value | PairingsBn254.Fr memory | 输入值            |

4. update_with_g1 函数

   `function update_with_g1(Transcript memory self, PairingsBn254.G1Point memory p)`

   更新一个 G1上的点到transcript中。

   a. 输入值

   | 参数 | 数据类型                     | 描述信息          |
   | ---- | ---------------------------- | ----------------- |
   | self | Transcript memory            | 结构体 Transcript |
   | p    | PairingsBn254.G1Point memory | G1上的一个点      |

5. get_challenge 函数

   `function get_challenge(Transcript memory self)  internal pure returns (PairingsBn254.Fr memory challenge)`

   从 transcript 产生一个随机值。

   a. 输入值

   | 参数 | 数据类型          | 描述信息          |
   | ---- | ----------------- | ----------------- |
   | self | Transcript memory | 结构体 Transcript |

   b. 输出值

   | 输出值    | 输出类型                | 描述信息   |
   | --------- | ----------------------- | ---------- |
   | challenge | PairingsBn254.Fr memory | 随机挑战数 |

##### 3.2.2.3 contract Plonk4SingleVerifierWithAccessToDNext

实现了 Plonk 的 verify。

1. 函数

   `function evaluate_lagrange_poly_out_of_domain(uint256 poly_num, uint256 domain_size,  PairingsBn254.Fr memory omega, PairingsBn254.Fr memory at) internal view returns (PairingsBn254.Fr memory res)`

   计算一个与FFT域相关的拉格朗日多项式的取值。

   a. 输入值

   | 参数        | 数据类型                | 描述信息           |
   | ----------- | ----------------------- | ------------------ |
   | poly_num    | uint256                 | 多项式的位置       |
   | domain_size | uint256                 | 域大小             |
   | omega       | PairingsBn254.Fr memory | 域的生成元         |
   | at          | PairingsBn254.Fr memory | 多项式带入计算的值 |

   b. 输出值

   | 输出值 | 输出类型                | 描述信息             |
   | ------ | ----------------------- | -------------------- |
   | res    | PairingsBn254.Fr memory | 拉格朗日多项式的取值 |

2. batch_evaluate_lagrange_poly_out_of_domain 函数

   `function batch_evaluate_lagrange_poly_out_of_domain(uint256[] memory poly_nums,   uint256 domain_size, PairingsBn254.Fr memory omega,  PairingsBn254.Fr memory at) internal view returns (PairingsBn254.Fr[] memory res, PairingsBn254.Fr memory res_Ln, PairingsBn254.Fr memory return_zeta_pow_n)`

   批量计算多个拉格朗日多项式的取值。

   a. 输入值

   | 参数        | 数据类型                | 描述信息           |
   | ----------- | ----------------------- | ------------------ |
   | poly_nums   | uint256[] memory        | 多项式位置         |
   | domain_size | uint256                 | 域大小             |
   | omega       | PairingsBn254.Fr memory | 域的生成元         |
   | at          | PairingsBn254.Fr memory | 多项式带入计算的值 |

   b. 输出值

   | 输出值            | 输出类型                  | 描述信息             |
   | ----------------- | ------------------------- | -------------------- |
   | res               | PairingsBn254.Fr[] memory | 拉格朗日多项式的取值 |
   | res_Ln            | PairingsBn254.Fr memory   | 第n个多项式的取值    |
   | return_zeta_pow_n | PairingsBn254.Fr memory   | at^domain_size       |

3. evaluate_vanishing 函数

   `function evaluate_vanishing(uint256 domain_size, PairingsBn254.Fr memory at) internal view returns (PairingsBn254.Fr memory res)`

   计算 `at^domain_size -1`。

   a. 输入值

   | 参数        | 数据类型                | 描述信息           |
   | ----------- | ----------------------- | ------------------ |
   | domain_size | uint256                 | 域大小             |
   | at          | PairingsBn254.Fr memory | 多项式带入计算的值 |

   b. 输出值

   | 输出值 | 输出类型                  | 描述信息          |
   | ------ | ------------------------- | ----------------- |
   | res    | PairingsBn254.Fr[] memory | at^domain_size -1 |

4. verify_at_z 函数

   `function verify_at_z(PairingsBn254.Fr memory zeta_n, PartialVerifierState memory state, Proof memory proof, VerificationKey memory vk ) internal view returns (bool)`

   verify中检查有限域上运算结果的部分。

   令`lhs = t(z) * v(z)`, `rhs = r(z) - q_arith(z) \* pi(z) - (r_permu + r_lookup + r_substring)`，检查 `lhs ?= rhs`。

   a. 输入值

   | 参数   | 数据类型                    | 描述信息                    |
   | ------ | --------------------------- | --------------------------- |
   | zeta_n | PairingsBn254.Fr memory     | at^domain_size              |
   | state  | PartialVerifierState memory | PartialVerifierState 结构体 |
   | proof  | Proof memory                | 证明                        |
   | vk     | VerificationKey memory      | vk 的结构体                 |

   b. 输出值

   | 输出类型 | 描述信息 |
   | -------- | -------- |
   | bool     | 验证结果 |

5. reconstruct_d 函数

   `function reconstruct_d(PartialVerifierState memory state, Proof memory proof, VerificationKey memory vk) internal view returns (PairingsBn254.G1Point memory res, PairingsBn254.Fr memory out_vu)`

   计算验证数据 D，`[D] = v[r] + v*u[z] + v2*u[s] + v3*u[zlookup] . v3*u`（参考plonk论文）。

   a. 输入值

   | 参数  | 数据类型                    | 描述信息                    |
   | ----- | --------------------------- | --------------------------- |
   | state | PartialVerifierState memory | PartialVerifierState 结构体 |
   | proof | Proof memory                | 证明                        |
   | vk    | VerificationKey memory      | vk 的结构体                 |

   b. 输出值

   | 输出值 | 输出类型                     | 描述信息 |
   | ------ | ---------------------------- | -------- |
   | res    | PairingsBn254.G1Point memory | D        |
   | out_vu | PairingsBn254.Fr memory      | v^3*u    |

6. verify_commitments 函数

   `function verify_commitments(PairingsBn254.Fr memory zeta_n, PartialVerifierState memory state, Proof memory proof, VerificationKey memory vk) internal view returns (bool)`

   批量验证多项式承诺。

   a. 输入值

   | 参数   | 数据类型                    | 描述信息                    |
   | ------ | --------------------------- | --------------------------- |
   | zeta_n | PairingsBn254.Fr memory     | at^domain_size              |
   | state  | PartialVerifierState memory | PartialVerifierState 结构体 |
   | proof  | Proof memory                | 证明                        |
   | vk     | VerificationKey memory      | vk 的结构体                 |

   b. 输出值

   | 输出类型 | 描述信息 |
   | -------- | -------- |
   | bool     | 验证结果 |

7. verify_initial 函数

   `function verify_initial(PartialVerifierState memory state, Proof memory proof, VerificationKey memory vk) internal view returns (bool, PairingsBn254.Fr memory return_zeta_pow_n)`

   verify的准备工作，包括读取proof，生成随机挑战数，并批量计算拉格朗日多项式值。

   a. 输入值

   | 参数  | 数据类型                    | 描述信息                    |
   | ----- | --------------------------- | --------------------------- |
   | state | PartialVerifierState memory | PartialVerifierState 结构体 |
   | proof | Proof memory                | 证明                        |
   | vk    | VerificationKey memory      | vk 的结构体                 |

   b. 输出值

   | 输出值            | 输出类型                | 描述信息       |
   | ----------------- | ----------------------- | -------------- |
   |                   | bool                    | 验证结果       |
   | return_zeta_pow_n | PairingsBn254.Fr memory | at^domain_size |

8. verify 函数

   `function verify(Proof memory proof, VerificationKey memory vk) view internal returns (bool)`

   Plonk 的 verify 函数。

   a. 输入值

   | 参数  | 数据类型               | 描述信息    |
   | ----- | ---------------------- | ----------- |
   | proof | Proof memory           | 证明        |
   | vk    | VerificationKey memory | vk 的结构体 |

   b. 输出值

   | 输出类型 | 描述信息 |
   | -------- | -------- |
   | bool     | 验证结果 |

##### 3.2.2.4 contract SingleVerifierWithDeserialize

它继承了Plonk4SingleVerifierWithAccessToDNext函数，对其做了封装，以及对数据的处理。

1. vkhash_init 函数

   `function test_vkhash_init (uint64 string_length, uint64 num_inputs, uint128 domain_size, uint256[] memory vkdata) public returns (bool)`

   对 vkdata, num_inputs 和 domain_size 做sha256哈希运算。

   a. 输入值

   | 参数          | 数据类型         | 描述信息                 |
   | ------------- | ---------------- | ------------------------ |
   | string_length | uint64           | 字符串长度，1024或者2048 |
   | num_inputs    | uint64           | 输入值长度               |
   | domain_size   | uint128          | 域大小                   |
   | vkdata        | uint256[] memory | vk数据                   |

   b. 输出值

   | 输出类型 | 描述信息         |
   | -------- | ---------------- |
   | bool     | 是否计算哈希成功 |

2. multy_verify1024 函数

   `function multy_verify1024 (uint64 num_inputs, uint128 domain_size, uint256[] memory vkdata, uint256[] memory public_inputs, uint256[] memory serialized_proof) public returns (bool)`

   对sha256长度上限为1024的电路上产生的证明的验证。

   a. 输入值

   | 参数             | 数据类型         | 描述信息                 |
   | ---------------- | ---------------- | ------------------------ |
   | num_inputs       | uint64           | 输入值长度               |
   | domain_size      | uint128          | 域大小                   |
   | vkdata           | uint256[] memory | vk数据                   |
   | public_inputs    | uint256[] memory | 字符串长度，1024或者2048 |
   | serialized_proof | uint256[] memory | 序列化后的证明数据       |

   b. 输出值

   | 输出类型 | 描述信息 |
   | -------- | -------- |
   | bool     | 验证结果 |

3. multy_verify2048 函数

   `function multy_verify2048 (uint64 num_inputs, uint128 domain_size, uint256[] memory vkdata, uint256[] memory public_inputs, uint256[] memory serialized_proof) public returns (bool)`

   对sha256长度上限为2048 的电路上产生的证明的验证。

   a. 输入值

   | 参数             | 数据类型         | 描述信息                 |
   | ---------------- | ---------------- | ------------------------ |
   | num_inputs       | uint64           | 输入值长度               |
   | domain_size      | uint128          | 域大小                   |
   | vkdata           | uint256[] memory | vk数据                   |
   | public_inputs    | uint256[] memory | 字符串长度，1024或者2048 |
   | serialized_proof | uint256[] memory | 序列化后的证明数据       |

   b. 输出值

   | 输出类型 | 描述信息 |
   | -------- | -------- |
   | bool     | 验证结果 |

4. deserialize_proof 函数

   ` function deserialize_proof(uint256[] memory public_inputs, uint256[] memory serialized_proof) internal pure returns (Proof memory proof)`

   证明数据的反序列化。

   a. 输入值

   | 参数             | 数据类型         | 描述信息           |
   | ---------------- | ---------------- | ------------------ |
   | public_inputs    | uint256[] memory | 公开输入值         |
   | serialized_proof | uint256[] memory | 序列化后的证明数据 |

   b. 输出值

   | 输出值 | 输出类型     | 描述信息             |
   | ------ | ------------ | -------------------- |
   | proof  | Proof memory | 反序列化后的证明数据 |



## 4. 测试数据

由于sha256的哈希原文长度上限不同，完成mailheader验证的电路大小也分为两种：

| 长度上限  | 电路大小 |
| --------- | -------- |
| 1024 字节 | 192397   |
| 2048 字节 | 346160   |

两种不同电路下产生证明和验证（rust）时间为（MacBook Pro 内存 32GB）：

| 长度上限  | 产生证明时间 | 验证时间 |
| --------- | ------------ | -------- |
| 1024 字节 | 144,496 ms   | 281 ms   |
| 2048 字节 | 288,547 ms   | 436 ms   |

两种不同电路下合约Gas消耗为：

| 长度上限  | Gas消耗 |
| --------- | ------- |
| 1024 字节 | 741608  |
| 2048 字节 | 759625  |



## 5. 相关文档

1. [PLONK](https://eprint.iacr.org/2019/953.pdf)
2. [PLOOKUP](https://eprint.iacr.org/2020/315.pdf)
3. [KZG10](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
4. [SHA256](https://zcash.github.io/halo2/design/gadgets/sha256/table16.html)
5. Unipass 实现方案文档
6. 「Unipass 邮件验证zk化」
7. 「DKIM原理介绍.pdf」

## 6. License

// 待定

 

