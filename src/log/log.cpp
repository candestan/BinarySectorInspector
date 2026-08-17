#include "log/log.h"
#include "persist/settings.h"

#include <windows.h>

#include <deque>
#include <mutex>
#include <string>
#include <vector>
#include <stdio.h>
#include <string.h>

struct LogPluginRec
{
    std::string id;
    std::string name;
    std::vector<std::string> modules;
};

static std::deque<LogEntry>  g_entries;
static std::recursive_mutex  g_mu;
static std::mutex            g_reg_mu;
static std::vector<LogPluginRec> g_plugins;
static std::vector<std::string>  g_builtin_mods[8];
static uint64_t              g_seq;
static bool                  g_show_sev[LogSevCount];
static bool                  g_show_builtin[6];
static bool                  g_show_plugins = true;
static bool                  g_follow = true;
static bool                  g_show_time = true;
static bool                  g_show_level = true;
static bool                  g_show_source = true;
static int                   g_max_entries = 10000;
static bool                  g_collapse_repeats = true;

static LogOrigin OriginBuiltin(LogBuiltin src)
{
    LogOrigin o{};
    o.source_id = (uint32_t)src;
    o.module_id = 0;
    return o;
}

const char* LogSeverityLabel(LogSeverity sev)
{
    switch (sev)
    {
    case LogSevTrace:    return "TRACE";
    case LogSevDebug:    return "DEBUG";
    case LogSevInfo:     return "INFO";
    case LogSevSuccess:  return "OK";
    case LogSevWarning:  return "WARN";
    case LogSevError:    return "ERROR";
    case LogSevCritical: return "CRIT";
    default:             return "?";
    }
}

const char* LogBuiltinLabel(LogBuiltin src)
{
    switch (src)
    {
    case LogBuiltinCore:       return "Core";
    case LogBuiltinUI:         return "UI";
    case LogBuiltinAnalyzer:   return "Analyzer";
    case LogBuiltinPeAnalyzer: return "PE Analyzer";
    case LogBuiltinFile:       return "File";
    default:                   return "Unknown";
    }
}

static void FormatStamp(char* time_out, int time_cap, char* stamp_out, int stamp_cap)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    if (time_out && time_cap > 0)
        snprintf(time_out, time_cap, "%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
    if (stamp_out && stamp_cap > 0)
    {
        snprintf(stamp_out, stamp_cap, "%04u-%02u-%02u %02u:%02u:%02u",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }
}

static int PluginIndex(uint32_t source_id)
{
    if (source_id < LogPluginBase)
        return -1;
    return (int)source_id - (int)LogPluginBase;
}

static void FormatSource(char* out, int cap, uint32_t source_id, uint32_t module_id)
{
    if (!out || cap < 2)
        return;
    out[0] = 0;
    if (source_id < LogPluginBase)
    {
        const char* lab = LogBuiltinLabel((LogBuiltin)source_id);
        if (source_id < 8 && module_id > 0 && module_id <= g_builtin_mods[source_id].size())
            snprintf(out, cap, "%s > %s", lab, g_builtin_mods[source_id][module_id - 1].c_str());
        else
            snprintf(out, cap, "%s", lab);
        return;
    }
    std::lock_guard<std::mutex> lock(g_reg_mu);
    int pi = PluginIndex(source_id);
    if (pi < 0 || pi >= (int)g_plugins.size())
    {
        snprintf(out, cap, "Plugin");
        return;
    }
    const LogPluginRec& p = g_plugins[pi];
    if (module_id == 0 || module_id > p.modules.size())
        snprintf(out, cap, "Plugin > %s", p.name.c_str());
    else
        snprintf(out, cap, "Plugin > %s > %s", p.name.c_str(), p.modules[module_id - 1].c_str());
}

static bool SettingsKeyBool(const char* key, bool def)
{
    return SettingsGetBool(key, def);
}

static void SetDefaults()
{
    g_show_sev[LogSevTrace] = false;
    g_show_sev[LogSevDebug] = false;
    g_show_sev[LogSevInfo] = true;
    g_show_sev[LogSevSuccess] = true;
    g_show_sev[LogSevWarning] = true;
    g_show_sev[LogSevError] = true;
    g_show_sev[LogSevCritical] = true;
    g_show_builtin[LogBuiltinCore] = true;
    g_show_builtin[LogBuiltinUI] = true;
    g_show_builtin[LogBuiltinAnalyzer] = true;
    g_show_builtin[LogBuiltinPeAnalyzer] = true;
    g_show_builtin[LogBuiltinFile] = true;
    g_show_plugins = true;
    g_follow = true;
    g_show_time = true;
    g_show_level = true;
    g_show_source = true;
    g_max_entries = 10000;
    g_collapse_repeats = true;
}

void LogLoadSettings()
{
    SetDefaults();
    g_show_sev[LogSevTrace] = SettingsKeyBool("log.show.trace", g_show_sev[LogSevTrace]);
    g_show_sev[LogSevDebug] = SettingsKeyBool("log.show.debug", g_show_sev[LogSevDebug]);
    g_show_sev[LogSevInfo] = SettingsKeyBool("log.show.info", g_show_sev[LogSevInfo]);
    g_show_sev[LogSevSuccess] = SettingsKeyBool("log.show.success", g_show_sev[LogSevSuccess]);
    g_show_sev[LogSevWarning] = SettingsKeyBool("log.show.warning", g_show_sev[LogSevWarning]);
    g_show_sev[LogSevError] = SettingsKeyBool("log.show.error", g_show_sev[LogSevError]);
    g_show_sev[LogSevCritical] = SettingsKeyBool("log.show.critical", g_show_sev[LogSevCritical]);
    g_show_builtin[LogBuiltinCore] = SettingsKeyBool("log.show.core", true);
    g_show_builtin[LogBuiltinUI] = SettingsKeyBool("log.show.ui", true);
    g_show_builtin[LogBuiltinAnalyzer] = SettingsKeyBool("log.show.analyzer", true);
    g_show_builtin[LogBuiltinPeAnalyzer] = SettingsKeyBool("log.show.pe_analyzer", true);
    g_show_builtin[LogBuiltinFile] = SettingsKeyBool("log.show.file", true);
    g_show_plugins = SettingsKeyBool("log.show.plugins", true);
    g_follow = SettingsKeyBool("log.follow", true);
    g_show_time = SettingsKeyBool("log.show.time", true);
    g_show_level = SettingsKeyBool("log.show.level", true);
    g_show_source = SettingsKeyBool("log.show.source", true);
    g_max_entries = SettingsGetInt("log.max_entries", 10000);
    if (g_max_entries < 256)
        g_max_entries = 256;
    if (g_max_entries > 100000)
        g_max_entries = 100000;
    g_collapse_repeats = SettingsKeyBool("log.collapse_repeats", true);
}

void LogSaveSettings()
{
    SettingsSetBool("log.show.trace", g_show_sev[LogSevTrace]);
    SettingsSetBool("log.show.debug", g_show_sev[LogSevDebug]);
    SettingsSetBool("log.show.info", g_show_sev[LogSevInfo]);
    SettingsSetBool("log.show.success", g_show_sev[LogSevSuccess]);
    SettingsSetBool("log.show.warning", g_show_sev[LogSevWarning]);
    SettingsSetBool("log.show.error", g_show_sev[LogSevError]);
    SettingsSetBool("log.show.critical", g_show_sev[LogSevCritical]);
    SettingsSetBool("log.show.core", g_show_builtin[LogBuiltinCore]);
    SettingsSetBool("log.show.ui", g_show_builtin[LogBuiltinUI]);
    SettingsSetBool("log.show.analyzer", g_show_builtin[LogBuiltinAnalyzer]);
    SettingsSetBool("log.show.pe_analyzer", g_show_builtin[LogBuiltinPeAnalyzer]);
    SettingsSetBool("log.show.file", g_show_builtin[LogBuiltinFile]);
    SettingsSetBool("log.show.plugins", g_show_plugins);
    SettingsSetBool("log.follow", g_follow);
    SettingsSetBool("log.show.time", g_show_time);
    SettingsSetBool("log.show.level", g_show_level);
    SettingsSetBool("log.show.source", g_show_source);
    SettingsSetInt("log.max_entries", g_max_entries);
    SettingsSetBool("log.collapse_repeats", g_collapse_repeats);
    SettingsSave();
}

void LogInit()
{
    SetDefaults();
    LogLoadSettings();
}

void LogShutdown()
{
    std::lock_guard<std::recursive_mutex> lock(g_mu);
    g_entries.clear();
}

void LogClear()
{
    std::lock_guard<std::recursive_mutex> lock(g_mu);
    g_entries.clear();
}

uint32_t LogRegisterPlugin(const char* id, const char* display_name)
{
    if (!id || !id[0] || !display_name || !display_name[0])
        return 0;
    std::lock_guard<std::mutex> lock(g_reg_mu);
    for (int i = 0; i < (int)g_plugins.size(); i++)
    {
        if (g_plugins[i].id == id)
            return LogPluginBase + (uint32_t)i;
    }
    LogPluginRec rec;
    rec.id = id;
    rec.name = display_name;
    g_plugins.push_back(rec);
    return LogPluginBase + (uint32_t)g_plugins.size() - 1;
}

uint32_t LogRegisterPluginModule(uint32_t plugin_source_id, const char* module_name)
{
    if (!module_name || !module_name[0])
        return 0;
    std::lock_guard<std::mutex> lock(g_reg_mu);
    int pi = PluginIndex(plugin_source_id);
    if (pi < 0 || pi >= (int)g_plugins.size())
        return 0;
    LogPluginRec& p = g_plugins[pi];
    for (int i = 0; i < (int)p.modules.size(); i++)
    {
        if (p.modules[i] == module_name)
            return (uint32_t)i + 1;
    }
    p.modules.push_back(module_name);
    return (uint32_t)p.modules.size();
}

static bool SameEntry(const LogEntry& a, LogSeverity sev, LogOrigin origin, const char* msg)
{
    return a.severity == sev &&
        a.source_id == origin.source_id &&
        a.module_id == origin.module_id &&
        strcmp(a.message, msg) == 0;
}

void LogWriteV(LogSeverity sev, LogOrigin origin, const char* fmt, va_list ap)
{
    if (!fmt)
        return;
    char msg[512];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    msg[sizeof(msg) - 1] = 0;

    std::lock_guard<std::recursive_mutex> lock(g_mu);
    if (g_collapse_repeats && !g_entries.empty())
    {
        LogEntry& last = g_entries.back();
        if (SameEntry(last, sev, origin, msg))
        {
            last.repeat++;
            FormatStamp(last.time, (int)sizeof(last.time), last.stamp, (int)sizeof(last.stamp));
            if (last.repeat > 1)
                snprintf(last.full, sizeof(last.full), "%s  x%u", last.message, last.repeat);
            return;
        }
    }

    LogEntry e{};
    e.seq = ++g_seq;
    e.severity = sev;
    e.source_id = origin.source_id;
    e.module_id = origin.module_id;
    e.repeat = 1;
    FormatStamp(e.time, (int)sizeof(e.time), e.stamp, (int)sizeof(e.stamp));
    snprintf(e.level, sizeof(e.level), "%s", LogSeverityLabel(sev));
    FormatSource(e.source, (int)sizeof(e.source), origin.source_id, origin.module_id);
    snprintf(e.message, sizeof(e.message), "%s", msg);
    snprintf(e.full, sizeof(e.full), "%s  %s  %s  %s", e.time, e.level, e.source, e.message);
    g_entries.push_back(e);
    while ((int)g_entries.size() > g_max_entries)
        g_entries.pop_front();
}

void LogWrite(LogSeverity sev, LogOrigin origin, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    LogWriteV(sev, origin, fmt, ap);
    va_end(ap);
}

#define LOGV(fn, sev, src) \
    void fn(LogBuiltin src, const char* fmt, ...) \
    { \
        va_list ap; \
        va_start(ap, fmt); \
        LogWriteV(sev, OriginBuiltin(src), fmt, ap); \
        va_end(ap); \
    }

LOGV(LogTrace, LogSevTrace, src)
LOGV(LogDebug, LogSevDebug, src)
LOGV(LogInfo, LogSevInfo, src)
LOGV(LogSuccess, LogSevSuccess, src)
LOGV(LogWarning, LogSevWarning, src)
LOGV(LogError, LogSevError, src)
LOGV(LogCritical, LogSevCritical, src)

bool LogSettingsShowSeverity(LogSeverity sev)
{
    if (sev >= LogSevCount)
        return false;
    return g_show_sev[sev];
}

void LogSettingsSetShowSeverity(LogSeverity sev, bool on)
{
    if (sev < LogSevCount)
        g_show_sev[sev] = on;
}

bool LogSettingsShowBuiltin(LogBuiltin src)
{
    if (src >= 6)
        return false;
    return g_show_builtin[src];
}

void LogSettingsSetShowBuiltin(LogBuiltin src, bool on)
{
    if (src < 6)
        g_show_builtin[src] = on;
}

bool LogSettingsShowPlugins() { return g_show_plugins; }
void LogSettingsSetShowPlugins(bool on) { g_show_plugins = on; }
bool LogSettingsFollow() { return g_follow; }
void LogSettingsSetFollow(bool on) { g_follow = on; }
bool LogSettingsShowTime() { return g_show_time; }
void LogSettingsSetShowTime(bool on) { g_show_time = on; }
bool LogSettingsShowLevel() { return g_show_level; }
void LogSettingsSetShowLevel(bool on) { g_show_level = on; }
bool LogSettingsShowSource() { return g_show_source; }
void LogSettingsSetShowSource(bool on) { g_show_source = on; }
int LogSettingsMaxEntries() { return g_max_entries; }
void LogSettingsSetMaxEntries(int n)
{
    if (n < 256)
        n = 256;
    if (n > 100000)
        n = 100000;
    g_max_entries = n;
}
bool LogSettingsCollapseRepeats() { return g_collapse_repeats; }
void LogSettingsSetCollapseRepeats(bool on) { g_collapse_repeats = on; }

bool LogEntryPassesSettings(const LogEntry& e)
{
    if (e.severity >= LogSevCount || !g_show_sev[e.severity])
        return false;
    if (e.source_id >= LogPluginBase)
        return g_show_plugins;
    if (e.source_id < 6)
        return g_show_builtin[e.source_id];
    return true;
}

void LogLockEntries() { g_mu.lock(); }
void LogUnlockEntries() { g_mu.unlock(); }
int LogEntryCount() { return (int)g_entries.size(); }
const LogEntry* LogEntryAt(int index)
{
    if (index < 0 || index >= (int)g_entries.size())
        return nullptr;
    return &g_entries[index];
}

void LogFormatLine(const LogEntry& e, char* out, int cap)
{
    if (!out || cap < 2)
        return;
    if (e.repeat > 1)
        snprintf(out, cap, "[%s] [%s] [%s] %s  x%u", e.stamp, e.level, e.source, e.message, e.repeat);
    else
        snprintf(out, cap, "[%s] [%s] [%s] %s", e.stamp, e.level, e.source, e.message);
}

void LogPluginParts(uint32_t source_id, uint32_t module_id, char* plugin, int plugin_cap, char* module, int module_cap)
{
    if (plugin && plugin_cap > 0)
        plugin[0] = 0;
    if (module && module_cap > 0)
        module[0] = 0;
    if (source_id < LogPluginBase)
        return;
    std::lock_guard<std::mutex> lock(g_reg_mu);
    int pi = PluginIndex(source_id);
    if (pi < 0 || pi >= (int)g_plugins.size())
        return;
    const LogPluginRec& p = g_plugins[pi];
    if (plugin && plugin_cap > 0)
        snprintf(plugin, plugin_cap, "%s", p.name.c_str());
    if (module && module_cap > 0 && module_id > 0 && module_id <= p.modules.size())
        snprintf(module, module_cap, "%s", p.modules[module_id - 1].c_str());
}

static void ScopeWrite(LogScope s, LogSeverity sev, const char* fmt, va_list ap)
{
    LogOrigin o{};
    o.source_id = s.source_id;
    o.module_id = s.module_id;
    LogWriteV(sev, o, fmt, ap);
}

void LogScope::Trace(const char* fmt, ...) const
{
    va_list ap;
    va_start(ap, fmt);
    ScopeWrite(*this, LogSevTrace, fmt, ap);
    va_end(ap);
}

void LogScope::Debug(const char* fmt, ...) const
{
    va_list ap;
    va_start(ap, fmt);
    ScopeWrite(*this, LogSevDebug, fmt, ap);
    va_end(ap);
}

void LogScope::Info(const char* fmt, ...) const
{
    va_list ap;
    va_start(ap, fmt);
    ScopeWrite(*this, LogSevInfo, fmt, ap);
    va_end(ap);
}

void LogScope::Success(const char* fmt, ...) const
{
    va_list ap;
    va_start(ap, fmt);
    ScopeWrite(*this, LogSevSuccess, fmt, ap);
    va_end(ap);
}

void LogScope::Warning(const char* fmt, ...) const
{
    va_list ap;
    va_start(ap, fmt);
    ScopeWrite(*this, LogSevWarning, fmt, ap);
    va_end(ap);
}

void LogScope::Error(const char* fmt, ...) const
{
    va_list ap;
    va_start(ap, fmt);
    ScopeWrite(*this, LogSevError, fmt, ap);
    va_end(ap);
}

void LogScope::Critical(const char* fmt, ...) const
{
    va_list ap;
    va_start(ap, fmt);
    ScopeWrite(*this, LogSevCritical, fmt, ap);
    va_end(ap);
}

LogScope LogScope::Module(const char* module_name) const
{
    LogScope out = *this;
    if (source_id < LogPluginBase)
    {
        if (!module_name || !module_name[0] || source_id >= 8)
            return out;
        std::lock_guard<std::mutex> lock(g_reg_mu);
        auto& v = g_builtin_mods[source_id];
        for (int i = 0; i < (int)v.size(); i++)
        {
            if (v[i] == module_name)
            {
                out.module_id = (uint32_t)i + 1;
                return out;
            }
        }
        if (v.size() >= 32)
            return out;
        v.push_back(module_name);
        out.module_id = (uint32_t)v.size();
        return out;
    }
    out.module_id = LogRegisterPluginModule(source_id, module_name);
    return out;
}

LogScope LogFor(LogBuiltin src)
{
    LogScope s{};
    s.source_id = (uint32_t)src;
    s.module_id = 0;
    return s;
}

LogScope LogPlugin(const char* id, const char* display_name)
{
    LogScope s{};
    s.source_id = LogRegisterPlugin(id, display_name);
    s.module_id = 0;
    return s;
}
