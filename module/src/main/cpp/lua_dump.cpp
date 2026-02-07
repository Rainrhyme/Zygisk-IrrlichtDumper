//
// Lua Script Dumper
//

#include "lua_dump.h"
#include "lua-api-functions.h"
#include "log.h"
#include "xdl.h"
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>

// Global Lua state pointer (captured via hook)
static lua_State *g_lua_state = nullptr;
static pthread_mutex_t lua_mutex = PTHREAD_MUTEX_INITIALIZER;

// Original lua_newstate function
static lua_State *(*original_lua_newstate)(void *(*alloc)(void *, void *, size_t, size_t), void *ud) = nullptr;

// Hook for lua_newstate to capture Lua state
static lua_State *hooked_lua_newstate(void *(*alloc)(void *, void *, size_t, size_t), void *ud) {
    lua_State *L = original_lua_newstate(alloc, ud);
    if (L) {
        pthread_mutex_lock(&lua_mutex);
        if (!g_lua_state) {
            g_lua_state = L;
            LOGI("Captured Lua state: %p", L);
        }
        pthread_mutex_unlock(&lua_mutex);
    }
    return L;
}

void lua_api_init(void *handle) {
    // Use direct casting instead of DO_API macro for complex function pointers
    lua_newstate = (lua_State *(*)(void *(*)(void *, void *, size_t, size_t), void *))dlsym(handle, "lua_newstate");
    lua_close = (void (*)(lua_State *))dlsym(handle, "lua_close");
    lua_gettop = (int (*)(lua_State *))dlsym(handle, "lua_gettop");
    lua_settop = (void (*)(lua_State *, int))dlsym(handle, "lua_settop");
    lua_pushvalue = (void (*)(lua_State *, int))dlsym(handle, "lua_pushvalue");
    lua_remove = (void (*)(lua_State *, int))dlsym(handle, "lua_remove");
    lua_type = (int (*)(lua_State *, int))dlsym(handle, "lua_type");
    lua_typename = (const char *(*)(lua_State *, int))dlsym(handle, "lua_typename");
    lua_isnumber = (int (*)(lua_State *, int))dlsym(handle, "lua_isnumber");
    lua_isstring = (int (*)(lua_State *, int))dlsym(handle, "lua_isstring");
    lua_iscfunction = (int (*)(lua_State *, int))dlsym(handle, "lua_iscfunction");
    lua_isuserdata = (int (*)(lua_State *, int))dlsym(handle, "lua_isuserdata");
    lua_toboolean = (int (*)(lua_State *, int))dlsym(handle, "lua_toboolean");
    lua_tonumber = (lua_Number (*)(lua_State *, int))dlsym(handle, "lua_tonumber");
    lua_tointeger = (lua_Integer (*)(lua_State *, int))dlsym(handle, "lua_tointeger");
    lua_tolstring = (const char *(*)(lua_State *, int, size_t *))dlsym(handle, "lua_tolstring");
    lua_touserdata = (void *(*)(lua_State *, int))dlsym(handle, "lua_touserdata");
    lua_pushnil = (void (*)(lua_State *))dlsym(handle, "lua_pushnil");
    lua_pushnumber = (void (*)(lua_State *, lua_Number))dlsym(handle, "lua_pushnumber");
    lua_pushinteger = (void (*)(lua_State *, lua_Integer))dlsym(handle, "lua_pushinteger");
    lua_pushlstring = (void (*)(lua_State *, const char *, size_t))dlsym(handle, "lua_pushlstring");
    lua_pushstring = (void (*)(lua_State *, const char *))dlsym(handle, "lua_pushstring");
    lua_pushboolean = (void (*)(lua_State *, int))dlsym(handle, "lua_pushboolean");
    lua_getfield = (void (*)(lua_State *, int, const char *))dlsym(handle, "lua_getfield");
    lua_setfield = (void (*)(lua_State *, int, const char *))dlsym(handle, "lua_setfield");
    lua_gettable = (void (*)(lua_State *, int))dlsym(handle, "lua_gettable");
    lua_settable = (void (*)(lua_State *, int))dlsym(handle, "lua_settable");
    lua_next = (int (*)(lua_State *, int))dlsym(handle, "lua_next");
    lua_getglobal = (void (*)(lua_State *, const char *))dlsym(handle, "lua_getglobal");
    lua_setglobal = (void (*)(lua_State *, const char *))dlsym(handle, "lua_setglobal");
    luaL_loadstring = (int (*)(lua_State *, const char *))dlsym(handle, "luaL_loadstring");
    lua_pcall = (int (*)(lua_State *, int, int, int))dlsym(handle, "lua_pcall");
    
    // Try to hook lua_newstate
    if (lua_newstate) {
        original_lua_newstate = lua_newstate;
        // Note: Actual hooking would require a hooking framework like Dobby or Substrate
        LOGI("Lua API initialized, lua_newstate at %p", (void*)lua_newstate);
    }
}

static void dump_lua_value(FILE *file, lua_State *L, int idx, int depth, const char *key);

static void dump_lua_table(FILE *file, lua_State *L, int idx, int depth) {
    if (depth > 3) {
        fprintf(file, "{...}");
        return;
    }
    
    char indent[64] = {0};
    for (int i = 0; i < depth; i++) strcat(indent, "  ");
    
    fprintf(file, "{\n");
    
    lua_pushnil(L);
    int count = 0;
    while (lua_next(L, idx) != 0) {
        if (count++ > 50) {
            fprintf(file, "%s  ...(more items)\n", indent);
            lua_settop(L, lua_gettop(L) - 2);
            break;
        }
        
        fprintf(file, "%s  ", indent);
        
        // Key
        if (lua_type(L, -2) == LUA_TSTRING) {
            fprintf(file, "[%s] = ", lua_tolstring(L, -2, nullptr));
        } else if (lua_type(L, -2) == LUA_TNUMBER) {
            fprintf(file, "[%d] = ", (int)lua_tonumber(L, -2));
        } else {
            fprintf(file, "[%s] = ", lua_typename(L, lua_type(L, -2)));
        }
        
        // Value
        dump_lua_value(file, L, -1, depth + 1, nullptr);
        fprintf(file, ",\n");
        
        lua_settop(L, lua_gettop(L) - 1);
    }
    
    fprintf(file, "%s}", indent);
}

static void dump_lua_value(FILE *file, lua_State *L, int idx, int depth, const char *key) {
    int type = lua_type(L, idx);
    
    switch (type) {
        case LUA_TNIL:
            fprintf(file, "nil");
            break;
        case LUA_TBOOLEAN:
            fprintf(file, lua_toboolean(L, idx) ? "true" : "false");
            break;
        case LUA_TNUMBER:
            fprintf(file, "%g", lua_tonumber(L, idx));
            break;
        case LUA_TSTRING: {
            const char *str = lua_tolstring(L, idx, nullptr);
            if (str && strlen(str) < 100) {
                fprintf(file, "\"%s\"", str);
            } else {
                fprintf(file, "\"(long string)\"");
            }
            break;
        }
        case LUA_TTABLE:
            dump_lua_table(file, L, idx, depth);
            break;
        case LUA_TFUNCTION:
            fprintf(file, "function");
            break;
        case LUA_TUSERDATA:
            fprintf(file, "userdata(%p)", lua_touserdata(L, idx));
            break;
        case LUA_TTHREAD:
            fprintf(file, "thread");
            break;
        default:
            fprintf(file, "%s", lua_typename(L, type));
            break;
    }
}

void lua_dump(const char *output_dir) {
    LOGI("Starting Lua dump...");
    
    char dump_path[256];
    snprintf(dump_path, sizeof(dump_path), "%s/lua_dump.lua", output_dir);
    FILE *dump_file = fopen(dump_path, "w");
    if (!dump_file) {
        LOGE("Failed to create dump file: %s", dump_path);
        return;
    }

    fprintf(dump_file, "-- Lua Environment Dump\n");
    fprintf(dump_file, "-- Generated by Zygisk-IrrlichtDumper\n\n");
    
    // Check if we have Lua API
    if (!lua_gettop) {
        fprintf(dump_file, "-- ERROR: Lua API not initialized\n");
        fclose(dump_file);
        return;
    }
    
    fprintf(dump_file, "-- Lua API Functions Detected:\n");
    fprintf(dump_file, "-- lua_gettop: %p\n", (void*)lua_gettop);
    fprintf(dump_file, "-- lua_type: %p\n", (void*)lua_type);
    fprintf(dump_file, "-- lua_getglobal: %p\n", (void*)lua_getglobal);
    fprintf(dump_file, "-- lua_next: %p\n\n", (void*)lua_next);
    
    // Try to find Lua state
    pthread_mutex_lock(&lua_mutex);
    lua_State *L = g_lua_state;
    pthread_mutex_unlock(&lua_mutex);
    
    if (L && lua_gettop) {
        LOGI("Dumping Lua globals from captured state");
        fprintf(dump_file, "-- Lua State: %p\n\n", L);
        fprintf(dump_file, "-- Global Variables:\n\n");
        
        // Try to dump some common globals
        const char *common_globals[] = {
            "_G", "_VERSION", "package", "string", "table", "math",
            "io", "os", "debug", "coroutine",
            // Game-specific globals (you may need to adjust these)
            "Game", "Player", "Scene", "UI", "Config",
            nullptr
        };
        
        for (int i = 0; common_globals[i] != nullptr; i++) {
            lua_getglobal(L, common_globals[i]);
            if (!lua_isnil(L, -1)) {
                fprintf(dump_file, "%s = ", common_globals[i]);
                dump_lua_value(dump_file, L, -1, 0, common_globals[i]);
                fprintf(dump_file, "\n\n");
            }
            lua_settop(L, lua_gettop(L) - 1);
        }
    } else {
        fprintf(dump_file, "-- WARNING: Lua state not captured yet\n");
        fprintf(dump_file, "-- The game may not have initialized Lua\n");
        fprintf(dump_file, "-- Or lua_newstate hook failed\n\n");
    }
    
    fprintf(dump_file, "\n-- How to get full Lua dump:\n");
    fprintf(dump_file, "-- 1. Wait for game to fully load\n");
    fprintf(dump_file, "-- 2. Hook lua_newstate to capture Lua state\n");
    fprintf(dump_file, "-- 3. Extract .lua files from APK assets\n");
    fprintf(dump_file, "-- 4. Use unluac or luadec to decompile bytecode\n\n");
    
    fprintf(dump_file, "-- Lua Bytecode Extraction:\n");
    fprintf(dump_file, "-- adb pull /data/app/*/base.apk\n");
    fprintf(dump_file, "-- unzip base.apk\n");
    fprintf(dump_file, "-- find assets -name '*.lua' -o -name '*.luac'\n");

    fclose(dump_file);
    LOGI("Lua dump completed: %s", dump_path);
}
