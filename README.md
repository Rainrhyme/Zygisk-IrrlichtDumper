# Zygisk-IrrlichtDumper

A Zygisk module specifically designed for games built with **Irrlicht 3D Engine + CEGUI + Lua** architecture. Automatically analyzes engine structure and Lua environment at runtime.

## Target Games

This module is designed for games using:
- **3D Engine**: Irrlicht Engine
- **UI System**: CEGUI (Crazy Eddie's GUI System)
- **Scripting**: Lua (via CEGUI Lua module)
- **Game Logic**: C++ Native code

### How to Check Compatibility

Check if your game's APK `lib/` directory contains:
- `libIrrlicht.so` - Irrlicht engine core
- `libCEGUIBase-0.so` - CEGUI UI system
- `libCEGUILuaScriptModule-0.so` - Lua script support

## Features

- ✅ Auto-detect Irrlicht engine
- ✅ Identify CEGUI UI components
- ✅ Detect Lua script modules
- ✅ Analyze game logic libraries
- ✅ List all SDKs and protection mechanisms
- ✅ Provide reverse engineering suggestions
- ✅ Support x86/x64 emulators (via NativeBridge)

## Output Files

The module generates files in the game's data directory:

### 1. irrlicht_dump.txt
Contains:
- Irrlicht engine detection results
- CEGUI library list
- Game logic library info
- Audio library detection
- SDK and protection mechanism list
- Reverse engineering suggestions

### 2. lua_dump.lua
Contains:
- Lua API function addresses
- Lua global variables (if Lua State captured)
- Lua bytecode extraction guide

## Usage

### 1. Install Magisk
- Requires [Magisk](https://github.com/topjohnwu/Magisk) v24 or higher
- Enable Zygisk feature

### 2. Build Module

#### Method A: GitHub Actions (Recommended)
1. Fork this repository
2. Go to **Actions** tab in your fork
3. Select **Build** workflow
4. Click **Run workflow**
5. Enter game package name (e.g., `com.example.game`)
6. Wait for build to complete and download the zip

#### Method B: Android Studio
1. Clone this repository
2. Edit `module/src/main/cpp/game.h`
3. Change `GamePackageName` to your target game
4. Run Gradle task: `:module:assembleRelease`
5. Find the zip in `out/` directory

### 3. Install Module
1. Open Magisk Manager
2. Go to "Modules" tab
3. Click "Install from storage"
4. Select the generated zip file
5. Reboot device

### 4. Run Game
1. Launch target game
2. Wait for full load (about 15-20 seconds)
3. Module will automatically analyze

### 5. View Results
Use adb or file manager:
```bash
/data/data/<package_name>/files/irrlicht_dump.txt
/data/data/<package_name>/files/lua_dump.lua
```

Or use adb:
```bash
adb pull /data/data/<package_name>/files/irrlicht_dump.txt
adb pull /data/data/<package_name>/files/lua_dump.lua
```

## View Logs

Monitor module execution:
```bash
adb logcat | grep "Zygisk"
```

Expected output:
```
✓ Irrlicht engine detected
✓ CEGUI Lua module detected
✓ Game library (libyworld.so) detected
Starting dump process...
Dump completed!
```

## Reverse Engineering Guide

### 1. Lua Script Analysis

#### Extract Lua Files
```bash
# Pull APK
adb pull /data/app/*/base.apk

# Extract
unzip base.apk

# Find Lua files
find assets -name "*.lua" -o -name "*.luac"
```

#### Decompile Lua Bytecode
```bash
# Using unluac
java -jar unluac.jar script.luac > script.lua

# Or using luadec
luadec script.luac
```

### 2. Native Code Analysis

#### Using IDA Pro
1. Load game's main library (e.g., `libyworld.so`)
2. Find Lua registration functions:
   - `lua_register`
   - `luaL_register`
   - `luaL_newmetatable`
3. Analyze game logic functions

#### Using Ghidra
1. Import `libyworld.so`
2. Auto-analyze
3. Search string references for key functions

### 3. Memory Modification

#### Hook Lua Functions
Using Frida or Xposed:
```javascript
// Frida example
Interceptor.attach(Module.findExportByName("libCEGUILuaScriptModule-0.so", "lua_getglobal"), {
    onEnter: function(args) {
        console.log("lua_getglobal called:", Memory.readUtf8String(args[1]));
    }
});
```

#### Modify Lua Globals
```lua
-- Inject custom Lua code
Player.health = 9999
Player.gold = 999999
```

### 4. Resource Extraction

#### CEGUI Layouts
```bash
# Find XML layouts
find assets -name "*.layout" -o -name "*.scheme"
```

#### Irrlicht Scenes
```bash
# Find scene files
find assets -name "*.irr" -o -name "*.xml"
```

## FAQ

### Q: Module doesn't generate output files?
A: Check:
1. Is the game using Irrlicht engine?
2. Is Zygisk properly enabled?
3. Check logcat for module execution

### Q: Lua dump file is empty?
A: Lua State may not be initialized yet:
1. Wait for game to fully load
2. Enter main menu or start gameplay
3. Lua may initialize in specific scenes

### Q: How to find package name?
```bash
# View current app
adb shell dumpsys window | grep mCurrentFocus

# Or list all packages
adb shell pm list packages
```

### Q: Emulator support?
A: Yes, including:
- x86/x64 emulators running ARM games (via Houdini/NativeBridge)
- ARM emulators

## Technical Details

### Detection Flow
```
Game Launch
    ↓
Zygisk Injection
    ↓
Wait for Libraries (max 15s)
    ↓
Detect libIrrlicht.so
    ↓
Detect libCEGUILuaScriptModule-0.so
    ↓
Detect libyworld.so (game logic)
    ↓
Execute Irrlicht dump
    ↓
Execute Lua dump
    ↓
Generate reports
```

### Architecture Support
- ✅ armeabi-v7a (32-bit ARM)
- ✅ arm64-v8a (64-bit ARM)
- ✅ x86 (via NativeBridge)
- ✅ x86_64 (via NativeBridge)

## Contributing

Issues and Pull Requests are welcome!

## License

Modified from [Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)

## Disclaimer

This tool is for educational and research purposes only. Do not use for illegal activities. Users are responsible for any consequences.
