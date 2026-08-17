#pragma once

#include <stdint.h>
#include <stdarg.h>

enum LogSeverity : uint8_t
{
    LogSevTrace = 0,
    LogSevDebug,
    LogSevInfo,
    LogSevSuccess,
    LogSevWarning,
    LogSevError,
    LogSevCritical,
    LogSevCount,
};

enum LogBuiltin : uint32_t
{
    LogBuiltinCore       = 1,
    LogBuiltinUI         = 2,
    LogBuiltinAnalyzer   = 3,
    LogBuiltinPeAnalyzer = 4,
    LogBuiltinFile       = 5,
};

static const uint32_t LogPluginBase = 1000;

struct LogOrigin
{
    uint32_t source_id;
    uint32_t module_id;
};

struct LogEntry
{
    uint64_t     seq;
    LogSeverity  severity;
    uint32_t     source_id;
    uint32_t     module_id;
    char         time[12];
    char         stamp[20];
    char         level[12];
    char         source[128];
    char         message[512];
    char         full[640];
    uint32_t     repeat;
};

void LogInit();
void LogShutdown();
void LogLoadSettings();
void LogSaveSettings();

void LogClear();

void LogWriteV(LogSeverity sev, LogOrigin origin, const char* fmt, va_list ap);
void LogWrite(LogSeverity sev, LogOrigin origin, const char* fmt, ...);

void LogTrace(LogBuiltin src, const char* fmt, ...);
void LogDebug(LogBuiltin src, const char* fmt, ...);
void LogInfo(LogBuiltin src, const char* fmt, ...);
void LogSuccess(LogBuiltin src, const char* fmt, ...);
void LogWarning(LogBuiltin src, const char* fmt, ...);
void LogError(LogBuiltin src, const char* fmt, ...);
void LogCritical(LogBuiltin src, const char* fmt, ...);

uint32_t LogRegisterPlugin(const char* id, const char* display_name);
uint32_t LogRegisterPluginModule(uint32_t plugin_source_id, const char* module_name);
const char* LogBuiltinLabel(LogBuiltin src);
const char* LogSeverityLabel(LogSeverity sev);

bool LogSettingsShowSeverity(LogSeverity sev);
void LogSettingsSetShowSeverity(LogSeverity sev, bool on);
bool LogSettingsShowBuiltin(LogBuiltin src);
void LogSettingsSetShowBuiltin(LogBuiltin src, bool on);
bool LogSettingsShowPlugins();
void LogSettingsSetShowPlugins(bool on);
bool LogSettingsFollow();
void LogSettingsSetFollow(bool on);
bool LogSettingsShowTime();
void LogSettingsSetShowTime(bool on);
bool LogSettingsShowLevel();
void LogSettingsSetShowLevel(bool on);
bool LogSettingsShowSource();
void LogSettingsSetShowSource(bool on);
int  LogSettingsMaxEntries();
void LogSettingsSetMaxEntries(int n);
bool LogSettingsCollapseRepeats();
void LogSettingsSetCollapseRepeats(bool on);

bool LogEntryPassesSettings(const LogEntry& e);

struct LogScope
{
    uint32_t source_id;
    uint32_t module_id;

    void Trace(const char* fmt, ...) const;
    void Debug(const char* fmt, ...) const;
    void Info(const char* fmt, ...) const;
    void Success(const char* fmt, ...) const;
    void Warning(const char* fmt, ...) const;
    void Error(const char* fmt, ...) const;
    void Critical(const char* fmt, ...) const;
    LogScope Module(const char* module_name) const;
};

LogScope LogPlugin(const char* id, const char* display_name);

void LogLockEntries();
void LogUnlockEntries();
int  LogEntryCount();
const LogEntry* LogEntryAt(int index);
void LogFormatLine(const LogEntry& e, char* out, int cap);
void LogPluginParts(uint32_t source_id, uint32_t module_id, char* plugin, int plugin_cap, char* module, int module_cap);
