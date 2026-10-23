# pgJDBC 42.7.3 原生 SCRAM-SM3 认证改造方案

> 历史分析稿（2026-10-22）：以下“尚未实现”等描述保留用于追溯当时方案。2026-10-23 已进入实现与测试；实际交付仅普通 SCRAM-SM3，不含 SM3-PLUS。最终行为、构建方式和验收以配套《Linux部署与Java验证.md》及交付验证记录为准。

本文件分析如何让 Java 驱动连接配套改造的 PostgreSQL 17.10。当前仅完成源码获取与分析，尚未实现 SM3、运行构建或验证数据库连接。

## 1. 源码基线和结论

| 项目 | 已核实结果 |
|---|---|
| 用户 fork | <https://github.com/xiahuhu1/pgjdbc-sm3> |
| 官方上游 | <https://github.com/pgjdbc/pgjdbc> |
| Maven 坐标 | `org.postgresql:postgresql:42.7.3` |
| 稳定标签 | `REL42.7.3` |
| 标签对应源码提交 | `818953a2b30480ecc874f812e46fcb82d1a395fd` |
| 本地工作分支 | `codex/sm3-42.7.3` |
| 下载范围 | `--depth 1 --branch REL42.7.3`；未下载完整分支历史 |
| 构建体系 | Gradle Wrapper 8.6；模块名 `:postgresql`，源码目录 `pgjdbc/` |
| Java 要求 | Gradle 启动要求 Java 17+；默认构建 JDK 17、目标 Java 8 |
| 当前 SCRAM 依赖 | `com.ongres.scram:client:2.1`，随驱动 shaded 打包 |

标签与版本依据：[gradle.properties:17](../../gradle.properties)、[settings.gradle.kts:29](../../settings.gradle.kts)、[settings.gradle.kts:42](../../settings.gradle.kts)、[构建参数:19](../../build-logic/build-parameters/build.gradle.kts)、[依赖:87](../../pgjdbc/build.gradle.kts)。下文行号均为该提交的行号。

**建议实施方案：在 JDBC 内新增 SM3 原语与私有 SM3 会话，保留现有 SHA256 的 OnGres 路径。** 登录与修改密码共用 SM3 原语；通过现有 PostgreSQL SASL 消息承载，第一阶段支持普通 `SCRAM-SM3`，可运行于 TLS 连接内。

这样只需要维护当前 PostgreSQL、pgJDBC 两个 fork。OnGres 2.1 确有自定义机制扩展点，但原样复用会话仍继承迭代下限、签名比较和解析限制，详见第 4 节。若后续选择维护定制 OnGres 依赖，也可复用其会话，不能只增加算法名就宣布完整支持。

**成功标准：** 新驱动与配套 PostgreSQL 17.10 使用 SM3 完成相互认证；服务端签名必须通过验证才允许登录；驱动能生成 SM3 verifier 并通过 `alterUserPassword` 修改密码；SHA256/MD5/认证插件保留原有有效行为；最终发布 JAR 在 Java 8/17 中可独立加载所需算法。

## 2. 与 PostgreSQL 17.10 对齐的协议

| 层次 | 双端约定 |
|---|---|
| 服务器生成口令配置 | `password_encryption = 'scram-sm3'` |
| 服务器 HBA | `scram-sm3` |
| 第一阶段 JDBC SASL 机制 | `SCRAM-SM3`，大小写严格匹配 |
| 后续可选机制 | `SCRAM-SM3-PLUS`，需实现真实 channel binding |
| 存储格式 | `SCRAM-SM3$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>` |
| 算法 | SM3、HMAC-SM3、PBKDF2-HMAC-SM3 |
| 摘要、派生密钥、签名长度 | 32 字节；SM3 分组长度为 64 字节 |
| 默认参数 | 16 字节随机盐、4096 次迭代；登录时使用服务端给出的实际参数 |
| PG wire 消息 | 保留认证请求 10/11/12 与客户端 `p` 消息，无须新增认证编号 |
| JDBC API | 保留 `org.postgresql.Driver`、`jdbc:postgresql:`、DataSource 与连接池接口 |

普通 SM3 的消息示意如下，nonce、盐和 proof 均为运行时值：

```text
Server → Client  AuthenticationSASL: SCRAM-SM3\0\0
Client → Server  SASLInitialResponse: SCRAM-SM3, n,,n=*,r=<client nonce>
Server → Client  AuthenticationSASLContinue: r=<combined nonce>,s=<salt>,i=4096
Client → Server  SASLResponse: c=biws,r=<combined nonce>,p=<proof>
Server → Client  AuthenticationSASLFinal: v=<server signature>
Server → Client  AuthenticationOk
```

`n=*` 沿用 PostgreSQL 使用 StartupMessage 用户名的现有语义；不要将用户名混入口令派生。`c=biws` 是普通机制的 GS2 header `n,,` 的 Base64，不能用于冒充 PLUS。

```text
P               = PostgreSQL 兼容的 SASLprep；失败时使用原口令的 UTF-8 字节
SaltedPassword  = PBKDF2-HMAC-SM3(P, salt, iterations, 32 bytes)
ClientKey       = HMAC-SM3(key=SaltedPassword, data="Client Key")
StoredKey       = SM3(ClientKey)
ServerKey       = HMAC-SM3(key=SaltedPassword, data="Server Key")
AuthMessage     = client-first-bare + "," + 原始 server-first + "," + client-final-without-proof
ClientSignature = HMAC-SM3(key=StoredKey, data=AuthMessage)
ClientProof     = ClientKey XOR ClientSignature
ServerSignature = HMAC-SM3(key=ServerKey, data=AuthMessage)
```

这是一套与本项目 PostgreSQL fork 配套的协议约定；不能据此认为官方 PostgreSQL、官方 pgJDBC 或 openGauss 驱动已经支持或彼此兼容。

## 3. 当前 42.7.3 的调用链和具体改动

```text
ConnectionFactoryImpl.doAuthentication()
  ├─ AuthenticationSASL(10)
  │    ├─ AuthenticationPluginManager.withPassword(SASL, ...)
  │    ├─ new ScramAuthenticator(...)
  │    ├─ processServerMechanismsAndInit()
  │    └─ sendScramClientFirstMessage()
  ├─ AuthenticationSASLContinue(11) → processServerFirstMessage()
  ├─ AuthenticationSASLFinal(12)    → verifyServerSignature()
  └─ AuthenticationOk(0)           → 结束认证
```

| 文件和基线位置 | 现有行为 | 建议修改 |
|---|---|---|
| [ConnectionFactoryImpl.java:671](../../pgjdbc/src/main/java/org/postgresql/core/v3/ConnectionFactoryImpl.java) | 统一认证循环 | 保留现有入口；为 SM3 增加握手状态约束与失败清理。 |
| [同文件:840](../../pgjdbc/src/main/java/org/postgresql/core/v3/ConnectionFactoryImpl.java) | 通过认证插件获取 SASL 口令 | 继续使用 `AuthenticationRequestType.SASL`；不新增插件类型。 |
| [同文件:855](../../pgjdbc/src/main/java/org/postgresql/core/v3/ConnectionFactoryImpl.java) | 读取机制列表没有传入消息长度 | 将 `msgLen - 8` 传入解析入口；先检查长度合法，机制列表严格限制在本条消息内。 |
| [同文件:868](../../pgjdbc/src/main/java/org/postgresql/core/v3/ConnectionFactoryImpl.java)、[同文件:872](../../pgjdbc/src/main/java/org/postgresql/core/v3/ConnectionFactoryImpl.java) | Continue/Final 委派给认证器 | 根据选中的会话处理 SM3；不完整或错序消息转为明确认证异常。 |
| [同文件:875](../../pgjdbc/src/main/java/org/postgresql/core/v3/ConnectionFactoryImpl.java) | `AuthenticationOk` 直接结束循环 | 已启动 SM3 时必须确认服务端签名已验证；不能跳过 Final 或在中途换另一认证方式。 |
| [ScramAuthenticator.java:59](../../pgjdbc/src/main/java/org/postgresql/jre7/sasl/ScramAuthenticator.java) | 无外层长度边界地读取 NUL 机制列表 | 有界读取，校验列表终止符、完整名称、无多余残留；未知机制忽略，全部不支持则拒绝。 |
| [同文件:75](../../pgjdbc/src/main/java/org/postgresql/jre7/sasl/ScramAuthenticator.java) | OnGres 自动选择机制 | 广告包含 `SCRAM-SM3` 时创建 SM3 会话；否则保留原 SHA 选择路径。混合列表明确优先 SM3；选中后的失败不自动换机制重试。 |
| [同文件:95](../../pgjdbc/src/main/java/org/postgresql/jre7/sasl/ScramAuthenticator.java)、[同文件:118](../../pgjdbc/src/main/java/org/postgresql/jre7/sasl/ScramAuthenticator.java)、[同文件:164](../../pgjdbc/src/main/java/org/postgresql/jre7/sasl/ScramAuthenticator.java) | client-first、server-first、server-final 处理 | 各入口窄分派到 SM3 私有会话；保留 SHA 原处理。无需新建通用插件框架。 |
| 新增 `pgjdbc/src/main/java/org/postgresql/jre7/sasl/Sm3ScramMechanism.java` | 尚不存在 | 共享 SM3/HMAC/PBKDF2 与口令准备；供登录及 PasswordUtil 使用。可实现现有 `ScramMechanism` 接口以复用公共派生辅助函数。 |
| 新增 `pgjdbc/src/main/java/org/postgresql/jre7/sasl/Sm3ScramSession.java` | 尚不存在 | 负责普通 SM3 的 nonce、完整消息解析、proof、签名验证、状态与清理；不实现 PLUS。 |
| [PasswordUtil.java:51](../../pgjdbc/src/main/java/org/postgresql/util/PasswordUtil.java)、[同文件:168](../../pgjdbc/src/main/java/org/postgresql/util/PasswordUtil.java) | 固定 SHA256 原语和 verifier 前缀；分派不接受 SM3 | 增加 `encodeScramSm3` 的指定盐/迭代及默认参数重载，`encodePassword` 接受 `scram-sm3`。 |
| [PGConnection.java:264](../../pgjdbc/src/main/java/org/postgresql/PGConnection.java) | Javadoc 仅列 md5/SHA256 | 增加 SM3 支持值说明；默认方法的查询和执行结构可以保留。 |
| [pgjdbc/build.gradle.kts:87](../../pgjdbc/build.gradle.kts) | 已内置 OnGres 2.1 | 加入选定 SM3 算法库及打包、重定位、许可证配置；保留旧 SCRAM 依赖。 |

[AuthenticationPlugin.java:31](../../pgjdbc/src/main/java/org/postgresql/plugin/AuthenticationPlugin.java) 只供应口令，不提供 SASL 算法或协议实现。因此不能只写一个 AuthenticationPlugin 来增加 SM3。

“私有会话”指驱动内部实现。`PasswordUtil` 与 SM3 原语位于不同包，原语入口需要适当的跨包可见性；不将内部算法类设计为面向业务的新扩展 SPI。

## 4. OnGres 2.1 的扩展能力与路线取舍

已核查官方 Maven Central 发布的准确源码，而非最新主分支：

- [client 2.1 sources](https://repo.maven.apache.org/maven2/com/ongres/scram/client/2.1/client-2.1-sources.jar)
- [common 2.1 sources](https://repo.maven.apache.org/maven2/com/ongres/scram/common/2.1/common-2.1-sources.jar)

以下路径均相对相应 sources JAR：

| 依赖内位置 | 核实结果 |
|---|---|
| `common/ScramMechanism.java:36`，完整包 `com/ongres/scram/common/` | 公共接口包含 `getName`、`digest`、`hmac`、`algorithmKeyLength`、`supportsChannelBinding`、`saltedPassword`。 |
| `client/ScramClient.java:230`，完整包 `com/ongres/scram/client/` | `selectClientMechanism(ScramMechanism)` 可显式传入 SM3 对象。 |
| `common/ScramMechanisms.java:60`、`:194` | 自动选择依赖 SHA1/SHA256 静态枚举；安装一个 SM3 provider 不会使自动选择识别 SM3。 |
| `common/message/ServerFirstMessage.java:53`、`:75` | 强制迭代次数至少 4096；PostgreSQL 17.10 的 `scram_iterations` 范围为 `1..INT_MAX`。自定义算法接口无法解除此会话限制。 |
| `common/ScramFunctions.java:245` | 签名比较使用 `Arrays.equals`，不能描述为已采用恒定时间比较。 |
| `common/message/ServerFinalMessage.java:197` 与 `common/util/StringWritableCsv.java:87` | 解析只取第一项，额外字段会截断；需检查重复 `v`、`v/e` 同时出现等非法消息。server-first 同样取固定前三项。 |
| `client/ScramSession.java:163`、`:255` | 派生状态和 final 验证封装于私有字段/处理器；接口不能替换上述比较和解析。 |
| `common/stringprep/StringPreparations.java:52` | SASLprep 失败抛异常；没有 PostgreSQL 的原始口令回退语义。 |

因此有三种实际路线：

| 路线 | 代价和适用范围 |
|---|---|
| 自定义机制 + 原样复用 2.1 会话 | 最少代码即可验证默认 4096 次 SM3 互通；仍有上述限制。仅作为原型，不能作为本方案完整验收结果。 |
| 自定义机制 + 定制 OnGres 依赖 | 可继续复用会话；需修复签名比较、完整消息验证及迭代策略，管理匹配的 client/common 版本、源码和许可证。可行，但增加一份依赖发布维护工作。 |
| **JDBC 私有 SM3 会话，SHA 路径继续使用原依赖** | **本方案建议。** 改动集中于新增 SM3 路径；需要自行验证下节列出的协议责任，不能把会话实现当作几个散列函数。 |

如果改选定制依赖路线，低迭代支持应增加仅供 SM3 使用的显式会话参数，旧 API 继续保持原策略；不要直接把全局下限改为 1，意外改变既有 SHA 行为。签名函数应比较相应算法的实际摘要长度，不要把通用函数写死为 32 字节而破坏 SHA1。不要用反射、改写服务端消息或重复计算一整遍 PBKDF2 来绕过私有实现。

接口还有两个容易弄错的单位/顺序：`algorithmKeyLength()` 返回 **位数 256**；`ScramMechanism.hmac(key, message)` 与工具函数 `ScramFunctions.hmac(mechanism, message, key)` 的参数顺序不同。

## 5. SM3 私有实现的具体责任

### 5.1 算法与口令准备

建议采用 Bouncy Castle lightweight API，实施时固定经项目核查的版本：

- [SM3Digest](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/digests/SM3Digest.html)
- [HMac](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/macs/HMac.html)，显式传 `new SM3Digest()`。
- [PKCS5S2ParametersGenerator](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/generators/PKCS5S2ParametersGenerator.html)，显式传 `new SM3Digest()`；无参默认摘要不能用于 SM3。

先确定口令 UTF-8 字节，再执行 PBKDF2，输出 256 位。每次操作独立创建有状态 digest/MAC/generator，不能把可变算法对象共享为跨连接单例。不注册全局 `Security.addProvider`；不假设目标 JVM 默认具有 SM3、HmacSM3、PBKDF2 的完整 provider 组合。使用成熟算法库，避免自行实现 SM3 压缩函数。

口令准备必须双端一致：SASLprep 成功用规范化结果，禁止字符/无法准备时按 PostgreSQL 规则回退；登录和 verifier 生成调用同一实现。现有 OnGres `StringPreparations.SASL_PREPARATION` 抛异常的行为不能原样当成 PostgreSQL 全部语义。映射后为空等情况需对照服务器实际行为测试，不能笼统归入普通 Unicode 用例。

还要对齐 Unicode 3.2 未分配码点、检查顺序和规范化版本，不能只给现有包装器加一层 catch。PostgreSQL `src/common/saslprep.c:1145` 检查映射后的输入码点；例如 `U+1D2C` 位于其未分配范围，触发原始口令回退，而较新 Unicode 的 NFKC 可将其映射为 `A`。准确的 [saslprep 1.1 源码](https://repo.maven.apache.org/maven2/com/ongres/stringprep/saslprep/1.1/saslprep-1.1-sources.jar) 中 `true` 表示 storedString，检查的是规范化结果，不能据此认为与服务器完全相同。再加入 `A\u1680B`：PostgreSQL 会把 U+1680 映射为空格，单靠 JDK NFKC 不会。共享 helper 必须复现 PostgreSQL 的映射、未分配字符检查和失败回退；不能以 OnGres 正常返回作为兼容性证明。

Java String 的有效 Unicode/UTF-8 是本驱动的输入范围；不要承诺 Java 字符串接口能表达 PostgreSQL 原始口令中的任意非法 UTF-8 字节。对 NUL/非法 UTF-16 输入明确验证行为。

### 5.2 会话与消息校验

会话只保存本次连接需要的状态，成功、失败、多主机重连均不得复用 nonce、密钥或已验证标志。

```text
NEW → FIRST_SENT → PROOF_SENT → SERVER_VERIFIED → AuthenticationOk
```

1. `SecureRandom` 生成客户端 nonce，构造 `n,,n=*,r=...`；保留 client-first-bare。
2. server-first 只在 `FIRST_SENT` 接受。检查 `r/s/i`、字段顺序和完整语法，拒绝重复关键字段、未知 mandatory `m`、空 nonce、仅返回客户端 nonce、非法 Base64 和无效迭代数。允许的扩展按 SCRAM 规则处理，不简单截断。迭代数字在转换前核查十进制语法与 `1..Integer.MAX_VALUE` 范围，随后才运行派生。
3. 必须保留收到的原始 server-first 构造 `AuthMessage`，不能解析后重排字段再签名。
4. 派生并发送 client proof，进入 `PROOF_SENT`。此后不得接受重复 Continue 或新的认证方式。
5. server-final 只在 `PROOF_SENT` 接受；`e=` 一律失败，未知错误码也必须失败。要求唯一 `v=`，拒绝同时出现 `v/e`、重复签名、缺签名和非法编码；签名解码长度必须为 32 字节。
6. 采用审查过的恒定时间比较方法，例如固定长度后使用 `MessageDigest.isEqual`，验证通过再进入 `SERVER_VERIFIED`。`AuthenticationOk` 不能代替签名校验。
7. 解析、算法不可用、状态和签名错误统一映射为清晰的 `PSQLException`；不要把库的 NPE/IllegalArgumentException 直接泄漏为认证结果。服务端 ErrorResponse 在任一阶段都可终止。

`ConnectionFactoryImpl` 保证消息 framing、认证循环和会话生命周期；`Sm3ScramSession` 保证 SCRAM 状态和签名。这两个层次都要检查，单独新增一个 `isComplete` 布尔值不足以拒绝重复或中途换协议。

收到极高但语法有效的迭代数可能消耗大量 CPU；首版应明确是否沿用原有无客户端上限的兼容策略。不要暗中添加任意上限；若之后新增上限配置，需写入双端约定和测试。本方案边界测试不实际执行数十亿次派生。

### 5.3 敏感数据生命周期

新增口令数组、UTF-8 字节、SaltedPassword、ClientKey、StoredKey、ServerKey、proof 等在不再需要时尽早清零；预期服务端签名在 final 处理后清理。临时口令准备结果同样清理可擦除缓冲区。

当前 [ConnectionFactoryImpl.java:853](../../pgjdbc/src/main/java/org/postgresql/core/v3/ConnectionFactoryImpl.java) 会把密码转为不可擦除 String。第一批可保留旧构造调用，明确这一现状；若将 SM3 入口改为持有 char[]，必须核对认证插件 callback 退出即清零数组的约定，复制所需数据并负责释放。不能声称修改后已擦除所有 String 或算法库内部副本。

## 6. 修改密码与 PLUS 的边界

### 6.1 修改密码是必改链路

[PGConnection.alterUserPassword:274](../../pgjdbc/src/main/java/org/postgresql/PGConnection.java) 在算法参数为 null 时执行 `SHOW password_encryption`，然后调用 `PasswordUtil.genAlterUserPasswordSQL`。

如果只改登录，服务器返回 `scram-sm3` 后，这个 API 仍会报不支持算法。因此需要：

```java
PasswordUtil.encodeScramSm3(char[] password, int iterations, byte[] salt);
PasswordUtil.encodeScramSm3(char[] password);
PasswordUtil.encodePassword(user, password, "scram-sm3");
```

生成与服务器完全一致的 verifier，沿用默认盐长/迭代数；成功和失败清零调用方密码数组，参数检查异常也要覆盖。共享原语即可，不需要重构现有 MD5/SHA256 公共 API。现有 SQL 转义和 PGConnection 查询结构可以继续使用。

### 6.2 42.7.3 没有现成 channel binding

[ScramAuthenticator.java:76](../../pgjdbc/src/main/java/org/postgresql/jre7/sasl/ScramAuthenticator.java) 固定为 `ChannelBinding.NO`；这个版本没有 `channelBinding` 连接属性，也没有接通 TLS endpoint 绑定。不能照抄新版本驱动说明来声称 42.7.3 已具备 PLUS。

第一阶段服务器在 TLS 下广告 `SCRAM-SM3-PLUS` 和 `SCRAM-SM3`，本驱动选择普通 `SCRAM-SM3`。仅提供 PLUS 时明确拒绝。TLS 仍可使用 `sslmode=verify-full` 验证服务器身份，但这不等于 channel binding。

若以后明确需要 PLUS，还需实现绑定策略、GS2 header、TLS 证书 endpoint 摘要、`c=` 的绑定字节、绑定错误和降级测试。[PGStream.getSocket:169](../../pgjdbc/src/main/java/org/postgresql/core/PGStream.java)、[MakeSSL.convert:30](../../pgjdbc/src/main/java/org/postgresql/ssl/MakeSSL.java) 可提供 TLS socket。证书摘要按 `tls-server-end-point` 规则计算，不能一律替换为 SM3；数据库认证摘要与 TLS 证书算法是不同配置层。

## 7. 打包与业务替换

[pgjdbc/build.gradle.kts:63](../../pgjdbc/build.gradle.kts) 的测试使用未重定位依赖；[同文件:224](../../pgjdbc/build.gradle.kts) 的 shadowJar 才把 `com.ongres` 重定位到驱动私有包。因此业务额外加入另一个 `com.ongres.scram:client`，不会替换驱动 JAR 内的副本。

增加 BC 轻量算法库时，需将所需依赖纳入 shaded 配置、增加 `org.bouncycastle` 的私有包重定位并核查与应用现有 BC 共存；更新许可证收集。使用轻量 API，不依赖被重定位的 provider 注册机制。检查签名 JAR 的 `META-INF/*.SF/*.RSA/*.DSA` 和多版本 JAR 元数据，避免打包后签名失效或 Java 8 加载失败；具体排除/保留规则以选定依赖和产物检查为准，不随意排除全部 META-INF。

真正发布的主 JAR 来自 `osgiJar → shadowJar`，见 [同文件:239](../../pgjdbc/build.gradle.kts)、[同文件:413](../../pgjdbc/build.gradle.kts) 和 [发布物替换逻辑:21](../../build-logic/publishing/src/main/kotlin/build-logic.publish-to-central.gradle.kts)。验收不能只使用裸 `jar` 输出。

建议开发版本为 `org.postgresql:postgresql:42.7.3-sm3.1-SNAPSHOT`，保留 Driver 类、包名和 URL。`pgjdbc.version` 不写 `-SNAPSHOT`，构建脚本会自动追加。不要覆盖官方 `42.7.3` 同坐标内容。

如果将来改 Maven group，只修改 publication 的 groupId 更集中；根 `project.group` 同时影响 shaded 目标包，而 OSGi 排除规则固定使用 `org.postgresql.shaded.*`。新 GA 还要排除应用间接引入的官方驱动，确保只有一份 Driver。

业务验收应检查 Maven/Gradle 依赖树、Spring Boot fat JAR、容器共享 lib，记录 `org.postgresql.Driver` 实际来源 JAR，确认连接池使用定制驱动。第一阶段不要求业务 SQL、JDBC URL 协议头或 Hikari API 改造；TLS 地址和证书配置仍按实际环境设置。

## 8. 测试清单和构建入口

| 测试层次 | 必须覆盖 |
|---|---|
| 独立原语向量 | SM3 标准向量、跨分组输入；HMAC 短/长密钥；PBKDF2 迭代 1/2/4096；与独立 OpenSSL/已固定向量交叉验证。不能只让本项目 C/Java 两端互相验证。 |
| verifier | 固定盐、指定迭代数、32 字节 keys、完整格式；客户端与服务端生成相同结果；空口令、非法参数、成功/失败数组清零。 |
| 协议负向测试 | 消息边界/缺 NUL；未知/混合/仅 PLUS 机制；非法 nonce、salt、iterations、重复字段、mandatory 扩展；缺/错签名、服务端 e、提前 OK、重复/错序消息、中途换认证方式。 |
| 真实 SM3 登录 | 正误密码、角色不存在/过期、中文/空格/SASLprep 映射和回退、U+1680、U+1D2C、仅映射为空的口令、TLS；SM3/SHA verifier 错配明确失败；迭代 1/2/4096 对齐服务端。 |
| 改密 API | 显式 `scram-sm3` 与 null 读取服务器默认值两条路径；校验存储值、正确新密码重连、旧密码拒绝。 |
| 兼容性 | 新驱动连原版 SHA256/MD5；认证插件仍收到 SASL 请求；旧驱动连 SM3 明确拒绝；不替换原 SHA 测试。 |
| 最终交付 JAR | Java 8/17 单独 JVM，只加载最终主驱动 JAR和测试程序，不额外放原始 OnGres/BC JAR；与应用已有 BC 共存；实际连接修改后的服务器。 |

测试落点：

- 保留 [ScramTest.java:38](../../pgjdbc/src/test/java/org/postgresql/jdbc/ScramTest.java) 的 SHA256 回归，新增同目录 `ScramSm3Test`；已有建角色函数在 [同文件:128](../../pgjdbc/src/test/java/org/postgresql/jdbc/ScramTest.java) 固定 SHA256，不要直接改成 SM3。
- 扩展 [PasswordUtilTest.java:65](../../pgjdbc/src/test/java/org/postgresql/test/util/PasswordUtilTest.java)，增加独立、不依赖数据库的原语/会话测试；已有 PasswordUtilTest 包含数据库访问，不能把它当纯算法单测。
- 扩展 [AuthenticationPluginTest.java:70](../../pgjdbc/src/test/java/org/postgresql/test/plugin/AuthenticationPluginTest.java) 的 SASL 取口令回归。
- SM3 数据库集成测试采用显式能力开关，例如拟新增 `-Dpgjdbc.test.sm3=true`；原版 PG17 不支持 SM3，不能仅凭版本号跳过/启用。`pgjdbc.*` 系统属性已有 [传递机制:40](../../build-logic/jvm/src/main/kotlin/build-logic.test-base.gradle.kts)。该 SM3 开关和新测试类目前尚未实现。

下面是实施后使用的命令，当前未运行，也不代表已通过：

```sh
./gradlew :postgresql:assemble
./gradlew :postgresql:styleCheck
./gradlew :postgresql:test --tests org.postgresql.jdbc.ScramTest --tests org.postgresql.test.util.PasswordUtilTest
./gradlew :postgresql:test -Dpgjdbc.test.sm3=true --tests org.postgresql.jdbc.ScramSm3Test
./gradlew :postgresql:test -PjdkTestVersion=8 -Dpgjdbc.test.sm3=true --tests org.postgresql.jdbc.ScramSm3Test
./gradlew :postgresql:publishToMavenLocal -Ppgjdbc.version=42.7.3-sm3.1 -PskipJavadoc
```

Java 8 测试需要可用的 Java 8 toolchain；仅指定参数不证明环境已安装。测试连接写入不提交的 `build.local.properties`，字段参照 [build.properties:5](../../build.properties)：

```properties
server=127.0.0.1
port=55433
database=test
username=test
password=<测试专用口令>
privilegedUser=postgres
privilegedPassword=<测试管理员口令>
```

使用专用数据库实例。SM3 与 SHA256 回归角色使用匹配的 HBA 规则或独立端口；不要把整个测试端口全部改为 SM3 导致原 SHA 测试无法连接。[TESTING.md:24](../../TESTING.md) 的测试会创建/删除对象，全套还有额外权限与服务器配置要求。

## 9. 建议实施顺序与当前状态

1. **共享原语及 verifier。** 固定 SM3 算法依赖，新增 Sm3ScramMechanism 与 PasswordUtil SM3 分派；先用独立向量对齐 C/Java，验证打包后的算法可加载。
2. **普通 SM3 会话。** 新增私有会话、有界机制选择和完成状态检查；fake server 负向测试与 PostgreSQL 17.10 实际登录同时验证。
3. **业务交付。** 改密 API、认证插件与旧算法回归；Java 8/17 的最终主 JAR 验证；再由实际 Java 项目替换依赖做连接池验收。
4. **PLUS。** 仅在明确需要时增加完整 channel binding，单独验收；不能在第一阶段广告或发送虚假 PLUS。

切换顺序为先升级客户端，再重置测试角色 SM3 口令，最后限定角色/HBA 范围启用。已有 SHA256/MD5 verifier 不能直接转换；`password_encryption` 的变化也不会批量重写现有角色密码。同一角色当前只有一份 verifier，迁移和回退均需安排口令重置。

**当前完成：** fork 下载、42.7.3 精确版本锁定、认证/改密/依赖/打包源码分析及本方案。**当前未完成：** 认证代码、SM3 算法依赖选版、构建、测试、数据库联调、业务替换和远程提交。
