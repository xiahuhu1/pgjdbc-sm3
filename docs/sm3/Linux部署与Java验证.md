# PostgreSQL 17.10 / JDBC 42.7.3 SM3 测试部署与验收

适用本项目配套改造的 PostgreSQL 与 JDBC。SM3 用于口令存储与 SCRAM 登录认证，SQL/查询结果传输加密仍由 TLS 负责。本次仅实现普通 `SCRAM-SM3`，没有 SM3-PLUS。

## 1. 交付物

- Linux x86_64 镜像：`172.16.61.68:8080/library/postgres-sm3:17.10-sm3.2`。最终交付记录提供镜像 digest 和测试结果。
- Linux 启动脚本：`deploy/sm3/run-linux.sh`，使用同目录 `.env` 配置密码及参数，默认独立数据卷和 `55433` 测试端口。
- JDBC 压缩包：内含定制驱动主 JAR、源码 JAR、Maven POM、校验和、验证程序和本文。
- JDBC 源码基线为 `REL42.7.3`；业务依赖只替换为本次定制版本，Driver 类、URL 协议和 JDBC API 保持一致。

以下命令中的 `<Linux测试机IP>`、`<Nexus地址>`、密码均由你在内网实际环境填写。示例不包含实际凭据。

本轮镜像 `17.10-sm3.2` 的入口直接支持 `POSTGRES_PASSWORD`，启动脚本采用停止、删除同名容器后重新创建的方式；数据库二进制沿用 `17.10-sm3.1`。JDBC 版本仍为 `42.7.3-sm3.1`，主压缩包、源码压缩包及 patch 保持首次交付内容；其中旧的 Docker 启动章节由当前交付根目录的本文替代，Java/Nexus 验证步骤仍适用。

## 2. Linux Docker 仓库配置

仓库使用 HTTP。Linux Docker 的 `/etc/docker/daemon.json` 需要合并该配置，保留原有键：

```json
{
  "insecure-registries": ["172.16.61.68:8080"]
}
```

若需要重启 Docker 使配置生效，先安排该主机其他容器的运行窗口；不要直接覆盖整份配置。之后执行：

```sh
docker login 172.16.61.68:8080
docker pull 172.16.61.68:8080/library/postgres-sm3:17.10-sm3.2
docker image inspect --format '{{.Os}}/{{.Architecture}}' \
  172.16.61.68:8080/library/postgres-sm3:17.10-sm3.2
# 应为 linux/amd64
```

首次启动前确认端口 `55433` 未占用，并仅对 Java 测试机开放防火墙访问。

## 3. 初始化并启动独立测试库

在交付脚本所在目录首次运行：

```sh
cp .env.example .env
# 编辑 .env，填写测试密码及所需端口、容器名、数据卷名。
vi .env
chmod +x run-linux.sh
./run-linux.sh
docker logs -f postgres-sm3-test
```

启动包也附带可直接编辑的示例 `.env`；若已填写配置，直接编辑该文件即可，不要再次复制模板覆盖。所有参数统一放在脚本同目录的 `.env`：

```bash
POSTGRES_PASSWORD='ChangeMeForTest_123'
HOST_PORT=55433
CONTAINER=postgres-sm3-test
VOLUME=postgres-sm3-test-data
IMAGE=172.16.61.68:8080/library/postgres-sm3:17.10-sm3.2
```

`.env` 按 Bash 赋值语法读取，等号两侧不要加空格，密码建议用单引号包裹。将示例密码改成自己的测试密码。脚本通过 `docker run -e POSTGRES_PASSWORD` 将密码交给镜像入口，挂载同一个数据卷。

每次执行 `./run-linux.sh` 都会先停止、删除同名容器，再按 `.env` 重新创建；同名数据卷保留并继续使用。若原来部署的是 `17.10-sm3.1`，先拉取上面的 `17.10-sm3.2`，将现有 `.env` 的 `IMAGE` 改为新版本，再执行脚本。保留原来的 `CONTAINER`、`VOLUME` 和 `HOST_PORT` 即可接续原测试库。

镜像仅在空数据目录初始化。修改 `.env` 中的密码不会重置已有集群口令；已有账号需通过 SQL/`\password` 改密。测试数据在 Docker named volume，停止/删除容器不自动删除数据；**不要执行 `docker volume rm` 或带 `-v` 的清理来重启测试。** 不要把生产数据卷挂入本测试镜像。

容器 healthcheck 只证明服务器响应，不证明 SM3 登录成功。执行后面的新连接正反例才能验收认证。

容器内部管理员入口使用 Unix socket + peer：

```sh
docker exec -it --user postgres postgres-sm3-test psql -d postgres
```

这条本地管理连接不是 SM3 验收路径；Java 和后面的 TCP 连接才经过 `scram-sm3` HBA。初始化生成的远程规则对匹配连接要求 SM3，没有 trust 放行；日志记录认证方式。

## 4. 创建 Java 专用测试账号

在上述 psql 内执行：

```sql
SHOW password_encryption;
-- 预期 scram-sm3

CREATE ROLE sm3_app LOGIN;
\password sm3_app
-- 两次交互输入 Java 测试账号密码
CREATE DATABASE sm3_test OWNER sm3_app;

SELECT rolname,
       rolpassword LIKE 'SCRAM-SM3$%' AS sm3_verifier,
       rolpassword IS NOT NULL AS has_password
FROM pg_authid
WHERE rolname IN ('postgres', 'sm3_app');
-- sm3_verifier/has_password 应均为 t；不要导出完整校验值。

SELECT line_number, type, database, user_name, address, auth_method, error
FROM pg_hba_file_rules
ORDER BY line_number;
```

`password_encryption` 只影响之后设置的密码，不会转换旧账号的 verifier。使用旧账号测试必须重新设置密码。HBA 匹配按文件顺序，提前匹配的 trust/password/旧算法规则会使结果与预期不同。

## 5. 上传 JDBC 到 Nexus

先核查压缩包内 `SHA256SUMS`：

```sh
tar -xzf pgjdbc-42.7.3-sm3.1.tar.gz
cd pgjdbc-42.7.3-sm3.1
sha256sum -c SHA256SUMS
```

定制 release 坐标为：

```xml
<dependency>
  <groupId>org.postgresql</groupId>
  <artifactId>postgresql</artifactId>
  <version>42.7.3-sm3.1</version>
</dependency>
```

可使用 Nexus UI 上传 JAR、POM 和 sources（classifier=`sources`），或执行：

```sh
mvn deploy:deploy-file \
  -DrepositoryId=internal-nexus \
  -Durl=https://<Nexus地址>/repository/maven-releases/ \
  -Dfile=postgresql-42.7.3-sm3.1.jar \
  -DpomFile=postgresql-42.7.3-sm3.1.pom \
  -Dsources=postgresql-42.7.3-sm3.1-sources.jar
```

凭据放 Maven `settings.xml` 对应 `server id`，不要写在命令行或提交到源码。使用你现有 Nexus release hosted 仓库地址；不要上传覆盖官方 `42.7.3`。

应用替换依赖后执行：

```sh
mvn dependency:tree -Dincludes=org.postgresql:postgresql
```

只应存在选中的定制版本。Spring Boot `BOOT-INF/lib`、应用服务器公共 lib 和容器外挂目录都要核查，避免仍加载旧 JAR。主驱动 JAR已包含重定位的所需算法，不需要业务额外添加 OnGres/BC 来启用 SM3。

## 6. Java 项目连接配置

以 Spring Boot/Hikari 为例：

```properties
spring.datasource.url=jdbc:postgresql://<Linux测试机IP>:55433/sm3_test?ApplicationName=sm3-java-test&connectTimeout=10
spring.datasource.username=sm3_app
spring.datasource.password=${SM3_DB_PASSWORD}
spring.datasource.driver-class-name=org.postgresql.Driver
```

先完成普通连接验收。当前示例镜像没有自动配置 TLS 证书；如需传输加密，配置服务器证书及 `ssl=on` 后，再使用 `sslmode=verify-full` 与可信 CA。不要以 `sslmode=require` 或关闭证书校验代替服务器身份验证。

依赖更新和账号改密后，必须重启应用或关闭并重建连接池；已有物理连接不会重新执行密码认证。

## 7. Java 启动后的完整验证

### 7.1 确认运行时真正加载新驱动

在应用日志/诊断代码打印：

```java
System.out.println(org.postgresql.Driver.class.getProtectionDomain()
    .getCodeSource().getLocation());
try (java.sql.Connection c = dataSource.getConnection()) {
    System.out.println(c.getMetaData().getDriverVersion());
}
```

期望版本 `42.7.3-sm3.1`，来源为本次上传到 Nexus 的 JAR，而不是旧 42.7.3。

### 7.2 在应用真实连接中执行只读查询

```sql
SELECT current_user, system_user, current_database(), pg_backend_pid();
SHOW password_encryption;
SELECT ssl, version, cipher
FROM pg_stat_ssl
WHERE pid = pg_backend_pid();
```

- `current_user=sm3_app`。
- `system_user=scram-sm3:sm3_app`，证明该连接通过 SM3 HBA 认证。
- `password_encryption=scram-sm3` 是新密码生成配置，单独这一项不能证明当前连接使用 SM3。
- `pg_stat_ssl.ssl` 只说明 TLS 状态，不是 SM3 算法标志。

若应用执行 `SET ROLE`，`current_user` 可能改变，认证身份 `system_user` 仍应对应登录角色。

### 7.3 核对服务端认证日志

```sh
docker logs postgres-sm3-test 2>&1 | grep -E 'authenticated|authorized|authentication failed'
```

新建连接应出现 `method=scram-sm3`，并显示匹配的 HBA 文件行。不得用单纯的“连接成功”替代这项证据；trust 连接也可能成功。

### 7.4 独立程序做正确/错误密码新连接

压缩包自带 `examples/sm3/Sm3Verify.java` 和 `verify.sh`，Java 8+ 可运行，编译需要 JDK：

```sh
export SM3_JDBC_URL='jdbc:postgresql://<Linux测试机IP>:55433/sm3_test?ApplicationName=sm3-acceptance&connectTimeout=10'
export SM3_DB_USER=sm3_app
read -r -s -p 'sm3_app password: ' SM3_DB_PASSWORD; echo
export SM3_DB_PASSWORD
JDBC_JAR="$PWD/postgresql-42.7.3-sm3.1.jar" ./examples/sm3/verify.sh
unset SM3_DB_PASSWORD
```

程序打印实际 JAR、驱动版本、认证身份，随后用错误口令创建第二条物理连接。正确结果是 `SM3 verification PASS`，且错误口令得到 `SQLSTATE 28P01`。它不会修改账号密码或数据库数据。

也可用镜像内新 libpq 强制 SM3：

```sh
docker exec -it postgres-sm3-test psql \
  'host=127.0.0.1 dbname=sm3_test user=sm3_app require_auth=scram-sm3' -W \
  -c 'SELECT current_user, system_user;'
```

旧版官方 JDBC 42.7.3 连接同一 SM3 账号/HBA 应明确拒绝不支持的机制，这是兼容性负向用例；不能为了让旧驱动成功而临时改 trust。

### 7.5 验证 JDBC 修改密码

在专用测试角色上调用：

```java
org.postgresql.PGConnection pg = connection.unwrap(org.postgresql.PGConnection.class);
pg.alterUserPassword("sm3_app", newPasswordChars, "scram-sm3");
// 也要验证第三参数为 null 时跟随服务器 password_encryption 的路径。
```

JDBC 改密默认迭代为 4096；第三参数 null 跟随服务端算法，不会读取服务端 `scram_iterations`。

`newPasswordChars` 使用后应被清零。通过管理员查询 `sm3_verifier` 布尔值，关闭连接池后用新密码建新连接成功，旧密码建新连接失败。切勿在仍用该账号的其他应用上随意改密；此步骤用于专用测试账号。

## 8. 停止、恢复与回退

```sh
docker stop postgres-sm3-test
docker start postgres-sm3-test
```

上述命令恢复现有容器；执行 `./run-linux.sh` 则会停止、删除并重新创建同名容器，两者都复用数据，不会重新初始化或重设密码。更换镜像前先对测试库及角色信息备份，记录卷名和镜像 digest；不要让未改造的 PostgreSQL 镜像接管含 SM3 口令的账号并期待正常认证。

回退到 SHA256 需要在支持的管理连接内设置 `password_encryption='scram-sha-256'`、重新设置账号密码并配置对应 HBA，然后切回官方驱动。SM3 verifier 不能直接转换回 SHA256 verifier。

## 9. 常见问题定位

| 现象 | 检查位置 |
|---|---|
| 旧驱动提示不支持机制 | 运行时 JAR 路径、版本、依赖树，确认已重建连接池。 |
| `28P01` | 账号实际密码、SM3 verifier 布尔值、HBA 首条匹配规则、是否改过 `.env` 却误以为会更新已有集群口令。 |
| `system_user` 为 peer/trust 或其他方法 | 使用了本地管理入口或匹配了别的 HBA；改用 TCP 新连接验证。 |
| 无法连接 55433 | 容器日志、端口映射、防火墙、目标主机地址；与 SM3 算法错误区分。 |
| Docker 报 HTTP/HTTPS 错误 | 合并 insecure-registries 配置并在合适窗口重启 Docker。 |
| PLUS/channel binding 错误 | 首版仅普通 SM3；libpq 不使用 `channel_binding=require`。 |
| 健康但业务失败 | healthcheck 不验证账号密码，执行新连接正反例及认证日志检查。 |
