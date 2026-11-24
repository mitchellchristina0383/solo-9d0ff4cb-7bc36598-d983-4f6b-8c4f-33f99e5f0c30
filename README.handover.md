# 隔离集群交接卷（OCI Image Layout）

已放行（release）的镜像需要从挂载的源 OCI Image Layout 复制到交接卷，供隔离集群按同一
OCI Image Layout 格式导入。本功能在「已放行」页对每条放行记录提供「交接」操作，并在
「交接卷」页列出审计记录与每个 blob 的实际摘要、大小核对结果。

## 数据流

```
源卷 /volumes/source (OCI Image Layout)
  oci-layout / index.json / blobs/sha256/<hex>
        │  按放行 digest 解析（manifest list 只取目标平台子清单）
        ▼
交接卷 /volumes/handover (OCI Image Layout)
  oci-layout / index.json（全部 blob 齐全后才原子追加描述符）
  blobs/sha256/<hex>（内容寻址，校验通过的 blob 全卷只存一份）
  .locks/（flock 跨进程锁）、.tmp/（复制中的临时文件，失败即清）
```

## 关键保证

1. **只交接单架构清单**：放行 digest 指向 manifest list 时，仅解析并复制配置目标平台
   （默认 `linux/amd64`，可用 `ADMISSION_HANDOVER_PLATFORM_OS/ARCH` 调整）的子清单、
   其 config 与 layers；清单列表本身和其它架构不复制。
2. **大层不进内存**：所有 blob 按 1 MiB 分块流式复制，边读边算 sha256 与字节数；
   落盘后再分块回读复核卷内实际摘要与大小。200 MiB 层实测 Python 峰值占用约 2 MiB。
3. **blob 去重与重试复用**：blob 按摘要寻址，同一 blob 全卷只存一份。复制由
   线程锁 + `flock` 串行化，已校验 blob 在重试或并发交接时直接回读复核后复用。
4. **失败不留索引项**：缺件、摘要/大小不符、写盘失败、复制中断都在写索引前中止，
   临时文件立即清理，`index.json` 保持原样；已有放行记录和已交接镜像不受影响。
5. **并发安全**：`index.json` 在全局索引锁内读—改—写，并以临时文件 + `rename` 原子
   替换；并发交接不会互相覆盖条目，同一 digest 重复交接只列一次。
6. **大镜像不阻塞小镜像**：复制在请求线程内进行且不持有全局索引锁，大层仍在流式
   复制时，内容已齐的另一单可以先完成并先写索引。

## 本地启动

```bash
docker compose up --build
# seed 服务先在 oci-source 卷生成示例布局（单架构 + 多架构 + 8 MiB 大层），
# admission 服务随后在 http://localhost:8000 提供界面
```

无 Docker 环境时（仅需 Python 3.11 与 requirements.txt 中的依赖）：

```bash
python3 -I scripts/seed_layout.py   # 默认路径可用 SOURCE_OCI_DIR/TARGET_OCI_DIR 覆盖
uvicorn app.web:create_app --factory --host 0.0.0.0 --port 8000
```

## 配置项

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMISSION_HANDOVER_SOURCE_DIR` | `volumes/source` | 挂载的源 OCI Image Layout |
| `ADMISSION_HANDOVER_TARGET_DIR` | `volumes/handover` | 交接卷 OCI Image Layout |
| `ADMISSION_HANDOVER_PLATFORM_OS` | `linux` | 从 manifest list 选择的目标 OS |
| `ADMISSION_HANDOVER_PLATFORM_ARCH` | `amd64` | 从 manifest list 选择的目标架构 |

## 自测

```bash
pytest -q
# tests/test_handover.py 覆盖：单/多架构解析、缺件、大小与摘要不符、写盘失败、
# 复制中断重试、线程与进程并发、同 digest 去重、有界内存、Web 全流程
```
