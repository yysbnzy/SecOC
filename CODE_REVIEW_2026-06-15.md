# SecOC Toolkit 代码审查报告

> **审查日期**: 2026-06-15  
> **审查范围**: `secoc_toolkit/` 全部 Python 源码（2392 行）  
> **仓库**: https://github.com/yysbnzy/SecOC

---

## 审查结论

整体架构清晰，代码质量良好，核心逻辑（SecOC Engine、Freshness Manager、KDF/CMAC）与 Toyota Demo 的 CAPL 实现一致。**发现 2 个严重逻辑错误、4 个中等问题**，需修复后才能用于实际测试。

---

## 🔴 严重问题（需立即修复）

### BUG-1: `replay_attack()` 攻击成功判断逻辑错误

**文件**: `secoc_toolkit/attacks/attack_modules.py:75-120`

**问题**: `AttackResult.success` 被设为 `replayed`（即 `can_driver.send()` 的返回值），表示"帧是否成功发到CAN总线"。但**重放攻击的"成功"应指"接收节点是否接受了重放报文"**——这需要监听总线看接收节点是否发送了错误帧或NACK。

当前逻辑：
```python
return AttackResult(
    attack_name='Replay Attack',
    success=replayed,  # ❌ 这只是send()返回值，不是攻击效果
    ...
)
```

**修复建议**: 
- 方案A：攻击后监听总线一段时间，检查是否有错误帧（被动检测）
- 方案B：添加 `--expect-reject` 标志，将 `success` 重定义为"报文被拒绝"（防御成功）
- 方案C：提供回调机制，由调用方根据实际ECU响应判断

---

### BUG-2: `freshness_rollback()` 攻击成功判断逻辑颠倒

**文件**: `secoc_toolkit/attacks/attack_modules.py:184-220`

**问题**: `success = sent and not local_valid` 逻辑反了。

- `local_valid = False` 意味着本地单调性检查**失败**（检测到了回滚）→ **防御成功**
- `local_valid = True` 意味着检查**通过**（回滚未被检测）→ **攻击成功**

当前代码把"检测到回滚"当作攻击成功，这是错的。

```python
# 当前（错误）
success=sent and not local_valid  # 防御成功时 attack.success=True ❌

# 应为
success=sent and local_valid  # 攻击成功 = 发送成功 且 验证通过（回滚未被检测）
```

**注意**: 即使修复后，`local_valid` 只是本地 FreshnessManager 的验证，不是真实ECU的行为。实际攻击效果仍需总线监听确认。

---

## 🟡 中等问题

### BUG-3: `replay_attack()` 残留混乱代码

**文件**: `secoc_toolkit/attacks/attack_modules.py:89-108`

问题代码段残留了一段被注释标记为 "This is wrong" 的废弃逻辑，虽然后面重写了，但应该清理：

```python
# Step 3: Replay old frame
old_frame = self.history[-1]
replayed = self._send_frame(
    msg_id, raw_data,
    old_frame['freshness'],  # This is wrong - should be trip/reset from old frame
    old_frame['message']     # But we need to reconstruct
)
# Actually, let's do it properly
# Extract trip/reset/message from the old frame's freshness
# But we don't have them separately... Let's recapture with explicit values
# Re-do with explicit capture
```

**修复**: 删除这段废弃代码，直接使用后面的正确实现。

---

### BUG-4: `pack_can_frame()` Motorola 位布局需验证

**文件**: `secoc_toolkit/core/secoc_engine.py:240-280`

**问题**: CAN 帧打包使用 Motorola（大端/MSB-first）格式，但位偏移计算需要与实际 DBC 文件严格对照。

```python
byte_pos = (63 - fv_start_bit) // 8  # 假设bit 63是最高位
bit_offset = (63 - fv_start_bit) % 8
```

DBC 中 `SG_ FV3BF : 39|4@0+` 表示：
- start_bit = 39（Intel格式下是LSB位置，Motorola格式下是MSB位置）
- `@0` 表示 Motorola 格式（big-endian / MSB-first）

当前代码假设 `63 - start_bit` 的换算方式对 Motorola 格式是否正确，**需要与 CANoe 的实际打包结果交叉验证**。

**建议**: 添加一个验证测试，用已知的 Trip=0x1234, Reset=0x56789, Message=0xA 计算 CMAC，然后与 CANoe 的 CAPL 输出对比。

---

### BUG-5: TOSUN 驱动 API 为推测实现

**文件**: `secoc_toolkit/can_drivers/can_interface.py:300-460`

TOSUN 驱动的 API 调用（`tsapp_connect`, `tscan_set_can_channel`, `tscan_transmit_can_sync` 等）是**基于常见模式的推测**，没有实际 TOSUN SDK 文档确认。函数签名和返回值可能与实际 DLL 不符。

**风险**: 运行时可能出现 ctypes 调用失败。

**建议**: 
- 添加详细的错误处理和日志
- 标注 `@experimental` 或 `@untested`
- 联系 TOSUN 获取官方 SDK 文档

---

### BUG-6: `run_normal_mode()` 硬编码消息索引

**文件**: `secoc_toolkit/main.py:45`

```python
secoc_config = config['secoc']['messages'][1]  # ECT1G01
```

硬编码取索引 1，如果 YAML 配置顺序变化就会出错。应通过 `can_id` 或 `name` 查找。

---

## 🟢 建议改进

| # | 建议 | 优先级 |
|---|------|--------|
| 1 | 添加单元测试（至少覆盖 SecOCEngine.build_payload / compute_cmac 与 CANoe 输出对比） | P1 |
| 2 | 添加 `--dry-run` 模式，不连接CAN硬件，仅打印构造的报文 | P1 |
| 3 | 将 `pack_can_frame` 的位布局逻辑提取为可配置模块（支持Intel/Motorola/不同OEM布局） | P2 |
| 4 | 攻击模块添加总线监听能力（接收错误帧/响应帧） | P2 |
| 5 | 添加 BLF/ASC 日志回放功能（替代实时CAN硬件测试） | P2 |
| 6 | 为 ZLG/TOSUN 驱动添加 mock 模式（无硬件时测试代码路径） | P2 |

---

## 验证清单（修复后必须做的）

- [ ] `replay_attack` 的 `success` 语义明确（文档化或改为枚举：ATTACK_SUCCEEDED / DEFENSE_WORKED / UNKNOWN）
- [ ] `freshness_rollback` 的 `success` 逻辑修复并通过测试
- [ ] `pack_can_frame` 输出与 CANoe CAPL 的 `output(msgECT1G01)` 字节级对比一致
- [ ] TOSUN 驱动在实际硬件上验证（或标记为 experimental）
- [ ] 所有攻击模块在无CAN硬件的 `--dry-run` 模式下能正常执行

---

## 代码质量评分

| 维度 | 评分 | 说明 |
|------|------|------|
| 架构设计 | ⭐⭐⭐⭐⭐ | 模块化清晰，工厂模式驱动抽象 |
| 代码规范 | ⭐⭐⭐⭐ | 类型注解完整，日志规范 |
| 核心算法 | ⭐⭐⭐⭐ | KDF/CMAC 与 Demo 一致，位打包待验证 |
| 攻击逻辑 | ⭐⭐⭐ | 2个严重逻辑错误，成功判断语义混乱 |
| 硬件驱动 | ⭐⭐⭐ | ZLG 较完整，TOSUN 为推测实现 |
| 测试覆盖 | ⭐⭐ | 无单元测试，仅有集成入口 |

**总体**: 架构优秀，细节需打磨。修复 BUG-1/2 后可进入实际测试阶段。
