//
// Lua API Functions
//

#ifndef ZYGISK_IL2CPPDUMPER_LUA_API_FUNCTIONS_H
#define ZYGISK_IL2CPPDUMPER_LUA_API_FUNCTIONS_H

#include <cstddef>

// Lua types
typedef struct lua_State lua_State;
typedef double lua_Number;
typedef ptrdiff_t lua_Integer;

// Lua constants
#define LUA_TNONE           (-1)
#define LUA_TNIL            0
#define LUA_TBOOLEAN        1
#define LUA_TLIGHTUSERDATA  2
#define LUA_TNUMBER         3
#define LUA_TSTRING         4
#define LUA_TTABLE          5
#define LUA_TFUNCTION       6
#define LUA_TUSERDATA       7
#define LUA_TTHREAD         8

#define LUA_GLOBALSINDEX    (-10002)
#define LUA_REGISTRYINDEX   (-10000)

// Lua API function pointers
lua_State *(*lua_newstate)(void *(*alloc)(void *, void *, size_t, size_t), void *ud);
void (*lua_close)(lua_State *L);
int (*lua_gettop)(lua_State *L);
void (*lua_settop)(lua_State *L, int idx);
void (*lua_pushvalue)(lua_State *L, int idx);
void (*lua_remove)(lua_State *L, int idx);
int (*lua_type)(lua_State *L, int idx);
const char *(*lua_typename)(lua_State *L, int tp);
int (*lua_isnumber)(lua_State *L, int idx);
int (*lua_isstring)(lua_State *L, int idx);
int (*lua_iscfunction)(lua_State *L, int idx);
int (*lua_isuserdata)(lua_State *L, int idx);
int (*lua_toboolean)(lua_State *L, int idx);
lua_Number (*lua_tonumber)(lua_State *L, int idx);
lua_Integer (*lua_tointeger)(lua_State *L, int idx);
const char *(*lua_tolstring)(lua_State *L, int idx, size_t *len);
void *(*lua_touserdata)(lua_State *L, int idx);
void (*lua_pushnil)(lua_State *L);
void (*lua_pushnumber)(lua_State *L, lua_Number n);
void (*lua_pushinteger)(lua_State *L, lua_Integer n);
void (*lua_pushlstring)(lua_State *L, const char *s, size_t len);
void (*lua_pushstring)(lua_State *L, const char *s);
void (*lua_pushboolean)(lua_State *L, int b);
void (*lua_getfield)(lua_State *L, int idx, const char *k);
void (*lua_setfield)(lua_State *L, int idx, const char *k);
void (*lua_gettable)(lua_State *L, int idx);
void (*lua_settable)(lua_State *L, int idx);
int (*lua_next)(lua_State *L, int idx);
void (*lua_getglobal)(lua_State *L, const char *name);
void (*lua_setglobal)(lua_State *L, const char *name);
int (*luaL_loadstring)(lua_State *L, const char *s);
int (*lua_pcall)(lua_State *L, int nargs, int nresults, int errfunc);

void lua_api_init(void *handle);

#endif //ZYGISK_IL2CPPDUMPER_LUA_API_FUNCTIONS_H
