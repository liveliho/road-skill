# 云、容器与 Kubernetes 安全

> 云安全的第一性问题通常不是“漏洞”，而是**身份与暴露**：谁拥有什么权限、从哪里能访问、是否有长期凭据。容器/K8s 则把这个问题放大到镜像、RBAC、网络策略和运行时。

## 1. 适用场景

- 云账号/订阅/项目的外部暴露与 IAM 审查。
- Kubernetes 集群 RBAC、admission、网络策略、镜像供应链。
- 容器镜像/主机基线、IaC 配置审查。
- 云上事件响应（身份滥用、存储暴露、加密挖矿）。

前提：只读权限、明确账号/订阅/项目范围；不要用管理员凭据做扫描。

## 2. 共享责任与范围

- 云厂商负责“云的安全”，客户负责“云中的安全”（配置、身份、数据、工作负载）。
- 不要测试云厂商底层基础设施；只测试你拥有的资源。
- 跨账号/跨订阅的资产要单独授权；共享 VPC/网络账户尤其注意。
- 托管服务（RDS、S3、Lambda、AKS/EKS/GKE 控制面）的可用测试面不同；以厂商文档和授权为准。

## 3. 身份优先

检查顺序：

1. **人类身份**：MFA、条件访问、长期访问密钥、休眠账号、离职账号。
2. **机器身份**：服务账号、实例角色、CI/CD token、OIDC 信任、密钥轮换。
3. **权限**：`*:*`、`iam:*`、`roles/owner`、`cluster-admin`、通配符资源。
4. **信任关系**：跨账号 role trust、OIDC provider、SAML、来宾账号。
5. **凭据暴露**：代码/环境变量/CI 日志/公开仓库/元数据。

### 3.1 AWS（只读示例）

```bash
# 确认身份与账号
aws sts get-caller-identity

# 访问密钥与轮换状态（IAM）
aws iam list-users --query 'Users[].UserName' --output table
aws iam list-access-keys --query 'AccessKeyMetadata[].{User:UserName,Key:AccessKeyId,Status:Status,Created:CreateDate}' --output table
aws iam get-account-summary

# S3 公共访问块/策略（只读）
aws s3api get-public-access-block --bucket example-bucket
aws s3api get-bucket-policy-status --bucket example-bucket
aws s3api get-bucket-acl --bucket example-bucket

# CloudTrail 状态
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name example-trail

# GuardDuty 探测器
aws guardduty list-detectors
```

不要用 `aws s3 sync`/`cp` 拉取未知桶；只读元数据即可。发现公开桶时，记录 URL、对象列表是否可读、是否含敏感数据；不要批量下载。

### 3.2 Azure（只读示例）

```bash
az account show
az ad signed-in-user show
az role assignment list --all --include-inherited --output table
az storage account list --query '[].{Name:name,RG:resourceGroup,Public:allowBlobPublicAccess}' -o table
az monitor activity-log list --max-events 20 -o table
```

### 3.3 GCP（只读示例）

```bash
gcloud auth list
gcloud config get-value project
gcloud projects get-iam-policy "$PROJECT_ID" --format=json
gcloud storage buckets list --format='table(name,location,iamConfiguration.uniformBucketLevelAccess.enabled)'
gcloud logging read 'logName:"cloudaudit.googleapis.com"' --limit 20 --format=json
```

## 4. 常见云风险

| 风险 | 观察 | 验证/修复 |
|---|---|---|
| 公开存储桶 | 匿名 List/Get | 只读确认；关闭 public access；审计对象 |
| 长期 AK/SK | 90+ 天未轮换、代码/CI 中出现 | 禁用/轮换；迁移到角色/OIDC |
| 过度权限 | `*:*`、`iam:PassRole` + `ec2:RunInstances` | 最小权限；权限边界；SCP |
| 公开快照/镜像 | 共享给 `all` | 移除公共共享；加密 |
| 元数据服务可达 | SSRF 可访问 169.254.169.254 | IMDSv2；网络策略；SSRF 修复 |
| 日志缺失 | CloudTrail 未开、日志桶公开 | 开启组织 trail；保护日志 |
| 跨账号信任过宽 | `Principal: "*"` + 条件缺失 | 收紧 trust policy；外部 ID |
| 无 MFA/条件访问 | 管理员仅密码 | 强制 MFA；条件访问；FIDO2 |

## 5. 容器镜像

```bash
# 漏洞 + 密钥 + 配置（Trivy）
trivy image --scanners vuln,secret,misconfig example/app:1.2.3

# 生成 SBOM（Syft）
syft example/app:1.2.3 -o spdx-json > sbom.spdx.json

# 用 SBOM 扫漏洞（Grype）
grype sbom:sbom.spdx.json

# Dockerfile/IaC 配置扫描
trivy config .
checkov -d .
```

要点：

- 先看基础镜像（是否 EOL、是否含包管理器/编译工具）、运行用户（root？）、entrypoint、暴露端口。
- 镜像 digest 固定，不用浮动 tag；生产禁用 `latest`。
- 多阶段构建，最小运行时；非 root；只读根文件系统；删除 shell/包管理器（如可行）。
- 镜像签名/ attestation（cosign/Sigstore）；准入控制验证签名。
- 不要把密钥烘进镜像；构建时 secret mount。

## 6. Kubernetes

### 6.1 基线

```bash
# kube-bench：按 CIS Benchmark 检查控制面/节点
kube-bench run --targets master,node

# Kubescape：RBAC/配置/NSA 框架（MITRE 框架可另跑一次）
kubescape scan framework nsa --submit=false

# 查看当前身份权限
kubectl auth can-i --list
kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'
```

### 6.2 RBAC 高危信号

- `cluster-admin` 绑定到用户/组/服务账号，尤其是默认 SA。
- `create pods` + `attach`/`exec` + `get secrets` 组合可横向。
- `escalate`/`bind`/`impersonate` 权限。
- `system:authenticated` 组被授予宽权限。
- 服务账号 token 自动挂载到不需要的 Pod。
- CI/CD 的 kubeconfig 长期有效、权限过大。

```bash
# 只读审计
kubectl get clusterrolebindings -o wide
kubectl get rolebindings -A -o wide
kubectl get sa -A
# 先检查权限；list/get secrets 的 API 会把 Secret 数据返回客户端，
# 即使 kubectl 的表格只显示名称，也不是纯元数据读取。
kubectl auth can-i list secrets --all-namespaces
```

不要在未授权集群上创建 Pod/Job 来“验证逃逸”；用配置和 RBAC 证明风险，必要时在隔离测试集群做最小 PoC。

### 6.3 工作负载

- `privileged: true`、`hostPID`/`hostNetwork`/`hostPath`、`CAP_SYS_ADMIN`。
- 没有 `runAsNonRoot`、`allowPrivilegeEscalation: false`、`readOnlyRootFilesystem`。
- 没有资源限制/网络策略；默认允许所有入站/出站。
- Ingress 暴露 admin/dashboard/未认证服务。
- Secret 以 env/volume 明文、etcd 未加密、RBAC 可读。
- 镜像来自不可信 registry、未固定 digest、未签名。

### 6.4 网络策略

- 默认拒绝 ingress/egress；按 namespace/app 放行。
- 限制到元数据服务、kubelet、API server、数据库的访问。
- 用 NetworkPolicy/Cilium/Calico 验证；不要在生产随意改策略。

## 7. IaC 与 CI/CD

```bash
# Terraform/CloudFormation/K8s manifest
trivy config .
checkov -d .
tfsec .
kics scan -p .
```

重点：

- 安全组 `0.0.0.0/0` 到 22/3389/数据库。
- 公开 S3/Blob、未加密磁盘、未开日志。
- IAM 通配符、硬编码密钥、明文变量。
- K8s `privileged`、hostPath、latest tag。
- CI 使用长期云密钥；应迁移 OIDC + 短期凭据。
- `pull_request_target` + secrets + 未固定 action SHA（供应链风险）。

## 8. 云上事件响应

- 先确认身份：哪个 principal、从哪、用什么凭据、是否 MFA。
- 保存 CloudTrail/Activity/Audit 日志（攻击者可能尝试删除；检查日志完整性）。
- 撤销会话/禁用密钥/轮换；不要只删用户（可能保留角色/信任）。
- 检查持久化：新 IAM 用户/角色、访问密钥、OIDC provider、Lambda 触发器、EC2 启动脚本、K8s DaemonSet。
- 检查数据访问：对象存储 Get/List、快照共享、数据库导出。
- 通知/合规：按数据分类和地区要求。

## 9. 常见坑

- 用管理员账号跑扫描器，产生高权限 API 调用/日志污染。
- 把“公开桶”直接下载全部对象，造成二次泄露。
- 只看漏洞分数，不看 IAM/网络暴露。
- 把 K8s `cluster-admin` 当普通运维权限。
- 忽略控制面日志（EKS/AKS/GKE 审计）和数据面日志。
- 认为“镜像扫描通过”=运行时安全；忽略 RBAC/网络/逃逸。
- 不固定 action/镜像 digest，供应链可被替换。
- 跨账号 role trust 没有外部 ID/条件， confused deputy。

## 10. 交付

```markdown
## 云/容器评估摘要
- 范围：AWS 123456789012 (us-east-1)；EKS cluster prod-1
- 身份：3 个长期 AK、2 个无 MFA 管理员、1 个跨账号 trust
- 暴露：2 个公开 S3、1 个公开快照、1 个 admin ingress
- 工作负载：7 个 privileged、12 个 latest tag、无默认拒绝 NetworkPolicy

## 发现
| ID | 资源 | 问题 | 证据 | 风险 | 修复 |
...

## 修复顺序
1. 24h：关闭公开桶/快照；禁用泄露 AK；限制 admin ingress
2. 7d：收紧 IAM/ RBAC；启用 IMDSv2；默认拒绝网络策略
3. 30d：镜像签名/准入；OIDC CI；CIS 基线
```

## 11. 参考

- CIS Benchmarks: <https://www.cisecurity.org/cis-benchmarks>
- AWS Security Best Practices: <https://docs.aws.amazon.com/security/>
- Azure Security Benchmark: <https://learn.microsoft.com/azure/security/benchmarks/>
- GCP Security Best Practices: <https://cloud.google.com/security/best-practices>
- Kubernetes Security: <https://kubernetes.io/docs/concepts/security/>
- kube-bench: <https://github.com/aquasecurity/kube-bench>
- Kubescape: <https://kubescape.io/>
- Trivy: <https://trivy.dev/>
- Sigstore: <https://www.sigstore.dev/>
