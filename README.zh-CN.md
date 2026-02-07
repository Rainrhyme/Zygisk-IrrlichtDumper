# Zygisk-IrrlichtDumper

专门针对 **Irrlicht 3D 引擎 + CEGUI + Lua** 架构游戏的 Zygisk 模块，在游戏运行时自动分析引擎结构和 Lua 环境。

## 适用游戏

本模块专门为使用以下技术栈的游戏设计：
- **3D 引擎**: Irrlicht Engine
- **UI 系统**: CEGUI (Crazy Eddie's GUI System)
- **脚本语言**: Lua (通过 CEGUI Lua 模块)
- **游戏逻辑**: C++ Native 代码

### 如何判断游戏是否适用

检查游戏 APK 的 `lib/` 目录是否包含：
- `libIrrlicht.so` - Irrlicht 引擎核心
- `libCEGUIBase-0.so` - CEGUI UI 系统
- `libCEGUILuaScriptModule-0.so` - Lua 脚本支持

## 功能特性

- ✅ 自动检测 Irrlicht 引擎
- ✅ 识别 CEGUI UI 系统组件
- ✅ 检测 Lua 脚本模块
- ✅ 分析游戏主逻辑库
- ✅ 列出所有相关 SDK 和保护机制
- ✅ 提供逆向工程建议
- ✅ 支持 x86/x64 模拟器（通过 NativeBridge）

## 输出文件

模块会在游戏的 data 目录生成以下文件：

### 1. irrlicht_dump.txt
包含：
- Irrlicht 引擎检测结果
- CEGUI 库列表
- 游戏逻辑库信息
- 音频库检测
- SDK 和保护机制列表
- 逆向工程建议

### 2. lua_dump.lua
包含：
- Lua API 函数地址
- Lua 全局变量（如果成功捕获 Lua State）
- Lua 字节码提取指南

## 使用方法

### 1. 安装 Magisk
- 需要 [Magisk](https://github.com/topjohnwu/Magisk) v24 或更高版本
- 启用 Zygisk 功能

### 2. 生成模块

#### 方法 A: GitHub Actions（推荐）
1. Fork 本项目
2. 进入你 fork 的项目，点击 **Actions** 标签
3. 选择左侧的 **Build** workflow
4. 点击 **Run workflow**
5. 输入游戏包名（例如：`com.example.game`）
6. 等待构建完成并下载生成的 zip 文件

#### 方法 B: Android Studio
1. 克隆本项目
2. 编辑 `module/src/main/cpp/game.h`
3. 修改 `GamePackageName` 为目标游戏的包名
4. 运行 Gradle 任务：`:module:assembleRelease`
5. 生成的 zip 文件位于 `out/` 目录

### 3. 安装模块
1. 打开 Magisk Manager
2. 点击 "模块" 标签
3. 点击 "从本地安装"
4. 选择生成的 zip 文件
5. 重启设备

### 4. 运行游戏
1. 启动目标游戏
2. 等待游戏完全加载（约 15-20 秒）
3. 模块会自动执行分析

### 5. 查看结果
使用 adb 或文件管理器查看：
```bash
/data/data/<游戏包名>/files/irrlicht_dump.txt
/data/data/<游戏包名>/files/lua_dump.lua
```

或使用 adb 命令：
```bash
adb pull /data/data/<游戏包名>/files/irrlicht_dump.txt
adb pull /data/data/<游戏包名>/files/lua_dump.lua
```

## 查看日志

实时查看模块运行日志：
```bash
adb logcat | grep "Zygisk"
```

你会看到类似输出：
```
✓ Irrlicht engine detected
✓ CEGUI Lua module detected
✓ Game library (libyworld.so) detected
Starting dump process...
Dump completed!
```

## 逆向工程指南

### 1. Lua 脚本分析

#### 提取 Lua 文件
```bash
# 拉取 APK
adb pull /data/app/*/base.apk

# 解压
unzip base.apk

# 查找 Lua 文件
find assets -name "*.lua" -o -name "*.luac"
```

#### 反编译 Lua 字节码
```bash
# 使用 unluac
java -jar unluac.jar script.luac > script.lua

# 或使用 luadec
luadec script.luac
```

### 2. Native 代码分析

#### 使用 IDA Pro
1. 加载游戏的主逻辑库（如 `libyworld.so`）
2. 查找 Lua 注册函数：
   - `lua_register`
   - `luaL_register`
   - `luaL_newmetatable`
3. 分析游戏逻辑函数

#### 使用 Ghidra
1. 导入 `libyworld.so`
2. 自动分析
3. 搜索字符串引用找到关键函数

### 3. 内存修改

#### Hook Lua 函数
使用 Frida 或 Xposed 框架：
```javascript
// Frida 示例
Interceptor.attach(Module.findExportByName("libCEGUILuaScriptModule-0.so", "lua_getglobal"), {
    onEnter: function(args) {
        console.log("lua_getglobal called:", Memory.readUtf8String(args[1]));
    }
});
```

#### 修改 Lua 全局变量
```lua
-- 注入自定义 Lua 代码
Player.health = 9999
Player.gold = 999999
```

### 4. 资源提取

#### CEGUI 布局文件
```bash
# 查找 XML 布局
find assets -name "*.layout" -o -name "*.scheme"
```

#### Irrlicht 场景文件
```bash
# 查找场景文件
find assets -name "*.irr" -o -name "*.xml"
```

## 常见问题

### Q: 模块没有生成输出文件？
A: 检查：
1. 游戏是否使用 Irrlicht 引擎
2. Zygisk 是否正确启用
3. 查看 logcat 日志确认模块是否运行

### Q: Lua dump 文件是空的？
A: Lua State 可能还未初始化，尝试：
1. 等待游戏完全加载后再检查
2. 进入游戏主界面或开始游戏
3. Lua 可能在特定场景才初始化

### Q: 如何找到游戏包名？
```bash
# 查看当前运行的应用
adb shell dumpsys window | grep mCurrentFocus

# 或列出所有已安装应用
adb shell pm list packages
```

### Q: 支持模拟器吗？
A: 支持，包括：
- x86/x64 模拟器运行 ARM 游戏（通过 Houdini/NativeBridge）
- ARM 模拟器

## 技术细节

### 检测流程
```
游戏启动
    ↓
Zygisk 注入
    ↓
等待库加载（最多 15 秒）
    ↓
检测 libIrrlicht.so
    ↓
检测 libCEGUILuaScriptModule-0.so
    ↓
检测 libyworld.so（游戏逻辑）
    ↓
执行 Irrlicht dump
    ↓
执行 Lua dump
    ↓
生成报告文件
```

### 架构支持
- ✅ armeabi-v7a (32-bit ARM)
- ✅ arm64-v8a (64-bit ARM)
- ✅ x86 (通过 NativeBridge)
- ✅ x86_64 (通过 NativeBridge)

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

基于原项目 [Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper) 修改

## 免责声明

本工具仅供学习和研究使用，请勿用于非法用途。使用本工具造成的任何后果由使用者自行承担。
