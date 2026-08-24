#include "app/about_contributors.h"

#include "ui/theme.h"
#include "ui/tex.h"
#include "ui/widgets.h"
#include "i18n/i18n.h"

#include "imgui.h"

#include <nlohmann/json.hpp>
// credit: https://github.com/nlohmann/json (MIT, third_party/nlohmann_json)

#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace {

enum
{
    StIdle = 0,
    StLoading,
    StReady,
    StFail
};

struct Contrib
{
    std::string login;
    std::string name;
    std::string bio;
    std::string location;
    std::string company;
    std::string blog;
    std::string html_url;
    int id = 0;
    int contributions = 0;

    std::atomic<int> avatar_st{ StIdle };
    std::mutex avatar_mu;
    std::vector<uint8_t> avatar_bytes;
    ID3D11ShaderResourceView* srv = nullptr;
    int tw = 0;
    int th = 0;

    std::atomic<int> profile_st{ StIdle };
};

static std::atomic<int> g_list_st{ StIdle };
static std::mutex g_list_mu;
static std::vector<std::unique_ptr<Contrib>> g_list;
static int g_list_total = 0;

static const int kMaxShow = 48;
static const char* kRepoOwner = "candestan";
static const char* kRepoName = "BinarySectorInspector";

static void OpenUrl(const char* url)
{
    if (url && url[0])
        ShellExecuteA(nullptr, "open", url, nullptr, nullptr, SW_SHOWNORMAL);
}

static bool HttpGetHttps(const wchar_t* host, const wchar_t* path, std::vector<uint8_t>* out)
{
    if (!host || !path || !out)
        return false;
    out->clear();
    HINTERNET ses = WinHttpOpen(L"BinarySectorInspector/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses)
        return false;
    WinHttpSetTimeouts(ses, 3000, 3000, 3000, 8000);
    HINTERNET con = WinHttpConnect(ses, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!con)
    {
        WinHttpCloseHandle(ses);
        return false;
    }
    HINTERNET req = WinHttpOpenRequest(con, L"GET", path, nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req)
    {
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return false;
    }
    const wchar_t* hdr =
        L"User-Agent: BinarySectorInspector\r\n"
        L"Accept: application/vnd.github+json\r\n";
    BOOL ok = WinHttpSendRequest(req, hdr, (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok)
        ok = WinHttpReceiveResponse(req, nullptr);
    DWORD status = 0;
    DWORD slen = sizeof(status);
    if (ok)
        ok = WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
    if (!ok || status != 200)
    {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return false;
    }
    const size_t kMax = 2 * 1024 * 1024;
    for (;;)
    {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail))
            break;
        if (!avail)
            break;
        if (out->size() + avail > kMax)
        {
            out->clear();
            break;
        }
        size_t at = out->size();
        out->resize(at + avail);
        DWORD rd = 0;
        if (!WinHttpReadData(req, out->data() + at, avail, &rd))
        {
            out->clear();
            break;
        }
        out->resize(at + rd);
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return !out->empty();
}

static void KickList()
{
    int expect = StIdle;
    if (!g_list_st.compare_exchange_strong(expect, StLoading))
        return;
    std::thread([] {
        std::vector<uint8_t> buf;
        wchar_t path[160];
        swprintf(path, 160, L"/repos/%hs/%hs/contributors?per_page=100", kRepoOwner, kRepoName);
        bool ok = HttpGetHttps(L"api.github.com", path, &buf);
        std::vector<std::unique_ptr<Contrib>> parsed;
        int total = 0;
        if (ok)
        {
            try
            {
                auto j = nlohmann::json::parse(buf.begin(), buf.end());
                if (j.is_array())
                {
                    total = (int)j.size();
                    for (const auto& e : j)
                    {
                        if (!e.is_object())
                            continue;
                        auto c = std::make_unique<Contrib>();
                        c->login = e.value("login", "");
                        c->id = e.value("id", 0);
                        c->contributions = e.value("contributions", 0);
                        c->html_url = e.value("html_url", "");
                        if (c->html_url.empty() && !c->login.empty())
                            c->html_url = std::string("https://github.com/") + c->login;
                        if (c->login.empty() || c->id <= 0)
                            continue;
                        parsed.push_back(std::move(c));
                        if ((int)parsed.size() >= kMaxShow)
                            break;
                    }
                }
            }
            catch (...)
            {
                ok = false;
            }
        }
        {
            std::lock_guard<std::mutex> lock(g_list_mu);
            g_list = std::move(parsed);
            g_list_total = total > 0 ? total : (int)g_list.size();
            ok = ok && !g_list.empty();
        }
        g_list_st.store(ok ? StReady : StFail);
    }).detach();
}

static void KickAvatar(Contrib* c)
{
    if (!c)
        return;
    int expect = StIdle;
    if (!c->avatar_st.compare_exchange_strong(expect, StLoading))
        return;
    int id = c->id;
    std::thread([c, id] {
        std::vector<uint8_t> buf;
        wchar_t path[64];
        swprintf(path, 64, L"/u/%d?s=128&v=4", id);
        bool ok = HttpGetHttps(L"avatars.githubusercontent.com", path, &buf);
        if (ok)
        {
            std::lock_guard<std::mutex> lock(c->avatar_mu);
            c->avatar_bytes.swap(buf);
            c->avatar_st.store(StReady);
        }
        else
            c->avatar_st.store(StFail);
    }).detach();
}

static std::string JsonStr(const nlohmann::json& j, const char* key)
{
    auto it = j.find(key);
    if (it == j.end() || it->is_null() || !it->is_string())
        return {};
    return it->get<std::string>();
}

static void KickProfile(Contrib* c)
{
    if (!c || c->login.empty())
        return;
    int expect = StIdle;
    if (!c->profile_st.compare_exchange_strong(expect, StLoading))
    {
        // Allow one retry after a failed parse/network attempt.
        expect = StFail;
        if (!c->profile_st.compare_exchange_strong(expect, StLoading))
            return;
    }
    std::string login = c->login;
    std::thread([c, login] {
        std::vector<uint8_t> buf;
        wchar_t path[128];
        swprintf(path, 128, L"/users/%hs", login.c_str());
        bool ok = HttpGetHttps(L"api.github.com", path, &buf);
        if (ok)
        {
            try
            {
                auto j = nlohmann::json::parse(buf.begin(), buf.end());
                std::lock_guard<std::mutex> lock(g_list_mu);
                c->name = JsonStr(j, "name");
                c->bio = JsonStr(j, "bio");
                c->location = JsonStr(j, "location");
                c->company = JsonStr(j, "company");
                c->blog = JsonStr(j, "blog");
                if (c->html_url.empty())
                    c->html_url = JsonStr(j, "html_url");
                c->profile_st.store(StReady);
            }
            catch (...)
            {
                c->profile_st.store(StFail);
            }
        }
        else
            c->profile_st.store(StFail);
    }).detach();
}

static ID3D11ShaderResourceView* EnsureAvatar(Contrib* c)
{
    if (!c)
        return nullptr;
    KickAvatar(c);
    if (c->avatar_st.load() == StReady && !c->srv)
    {
        std::vector<uint8_t> bytes;
        {
            std::lock_guard<std::mutex> lock(c->avatar_mu);
            bytes.swap(c->avatar_bytes);
        }
        if (!bytes.empty())
            TexLoadMemory(bytes.data(), bytes.size(), &c->srv, &c->tw, &c->th);
        if (!c->srv)
            c->avatar_st.store(StFail);
    }
    if (c->srv)
        return c->srv;
    return TexPlaceholder();
}

static void DrawHoverCard(Contrib* c, ID3D11ShaderResourceView* pic)
{
    if (!c)
        return;
    KickProfile(c);

    std::string name, bio, location, company, blog, login;
    int contributions = 0;
    int pst = c->profile_st.load();
    {
        std::lock_guard<std::mutex> lock(g_list_mu);
        login = c->login;
        contributions = c->contributions;
        if (pst == StReady)
        {
            name = c->name;
            bio = c->bio;
            location = c->location;
            company = c->company;
            blog = c->blog;
        }
    }

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(ThemePx(12.f), ThemePx(12.f)));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(ThemePx(8.f), ThemePx(6.f)));
    ImGui::BeginTooltip();

    const float av = ThemePx(56.f);
    ImGui::InvisibleButton("##hc_av", ImVec2(av, av));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 a = ImGui::GetItemRectMin();
    ImVec2 b = ImGui::GetItemRectMax();
    if (pic)
        dl->AddImageRounded(ImTextureRef((void*)pic), a, b, ImVec2(0, 0), ImVec2(1, 1), IM_COL32_WHITE, av * 0.5f);
    else
        dl->AddCircleFilled(ImVec2((a.x + b.x) * 0.5f, (a.y + b.y) * 0.5f), av * 0.5f, ThemeColHover(), 32);

    ImGui::Dummy(ImVec2(0.f, ThemePx(2.f)));

    if (ImFont* t = ThemeFontTitle())
        ImGui::PushFont(t);
    ImGui::TextUnformatted(login.c_str());
    if (ThemeFontTitle())
        ImGui::PopFont();

    if (pst == StReady)
    {
        if (!name.empty())
        {
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
            ImGui::TextUnformatted(name.c_str());
            ImGui::PopStyleColor();
        }
        if (!bio.empty())
        {
            ImGui::PushTextWrapPos(ImGui::GetCursorPos().x + ThemePx(280.f));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
            ImGui::TextUnformatted(bio.c_str());
            ImGui::PopStyleColor();
            ImGui::PopTextWrapPos();
        }
        if (!location.empty())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
            ImGui::Text("%s  %s", I18nGet("about.location"), location.c_str());
            ImGui::PopStyleColor();
        }
        if (!company.empty())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
            ImGui::Text("%s  %s", I18nGet("about.company"), company.c_str());
            ImGui::PopStyleColor();
        }
        if (!blog.empty())
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
            ImGui::TextUnformatted(blog.c_str());
            ImGui::PopStyleColor();
            if (ImGui::IsItemClicked())
            {
                std::string u = blog;
                if (u.find("://") == std::string::npos)
                    u = std::string("https://") + u;
                OpenUrl(u.c_str());
            }
            if (ImGui::IsItemHovered())
                UiHandIfHovered();
        }
    }
    else if (pst == StLoading || pst == StIdle)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(I18nGet("about.contributors_loading"));
        ImGui::PopStyleColor();
    }

    char contrib[64];
    snprintf(contrib, sizeof(contrib), I18nGet("about.contributions"), contributions);
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextUnformatted(contrib);
    ImGui::PopStyleColor();

    ImGui::EndTooltip();
    ImGui::PopStyleVar(2);
}

static void DrawBadge(int count)
{
    char num[16];
    snprintf(num, sizeof(num), "%d", count);
    ImVec2 ts = ImGui::CalcTextSize(num);
    float pad_x = ThemePx(8.f);
    float pad_y = ThemePx(2.f);
    float h = ts.y + pad_y * 2.f;
    float w = ts.x + pad_x * 2.f;
    if (w < h)
        w = h;
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(w, h));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p1(p0.x + w, p0.y + h);
    dl->AddRectFilled(p0, p1, ThemeColHover(), h * 0.5f);
    dl->AddText(ImVec2(p0.x + (w - ts.x) * 0.5f, p0.y + pad_y), ThemeColMuted(), num);
}

} // namespace

void AboutContributorsDraw()
{
    KickList();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("about.contributors"));
    if (ThemeFontTitle())
        ImGui::PopFont();

    int st = g_list_st.load();
    int total = 0;
    int n = 0;
    {
        std::lock_guard<std::mutex> lock(g_list_mu);
        total = g_list_total;
        n = (int)g_list.size();
    }

    ImGui::SameLine(0.f, ThemePx(10.f));
    if (st == StReady)
        DrawBadge(total > 0 ? total : n);
    else if (st == StLoading)
        DrawBadge(0);

    ImGui::Spacing();

    if (st == StLoading || st == StIdle)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(I18nGet("about.contributors_loading"));
        ImGui::PopStyleColor();
        return;
    }
    if (st == StFail)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextWrapped("%s", I18nGet("about.contributors_fail"));
        ImGui::PopStyleColor();
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
        ImGui::TextUnformatted(I18nGet("about.contributors_on_github"));
        ImGui::PopStyleColor();
        if (ImGui::IsItemClicked())
        {
            char url[160];
            snprintf(url, sizeof(url), "https://github.com/%s/%s/graphs/contributors", kRepoOwner, kRepoName);
            OpenUrl(url);
        }
        if (ImGui::IsItemHovered())
            UiHandIfHovered();
        return;
    }

    const float av = ThemePx(40.f);
    const float gap = ThemePx(10.f);
    const float cell_w = av + ThemePx(8.f);
    const float name_h = ImGui::GetTextLineHeight() * 2.f + ThemePx(4.f);
    const float cell_h = av + ThemePx(6.f) + name_h;
    float avail = ImGui::GetContentRegionAvail().x;
    int cols = (int)((avail + gap) / (cell_w + gap));
    if (cols < 1)
        cols = 1;
    if (cols > 12)
        cols = 12;

    // Kick profile fetches without holding the list lock across UI.
    {
        std::lock_guard<std::mutex> lock(g_list_mu);
        for (auto& c : g_list)
            KickProfile(c.get());
    }

    for (int i = 0; i < n; i++)
    {
        Contrib* cp = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_list_mu);
            if (i < (int)g_list.size())
                cp = g_list[(size_t)i].get();
        }
        if (!cp)
            break;
        Contrib& c = *cp;

        if (i % cols != 0)
            ImGui::SameLine(0.f, gap);

        ImGui::PushID(c.id ? c.id : i);
        bool hit = ImGui::InvisibleButton("##av", ImVec2(cell_w, cell_h));
        bool hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup);
        ImVec2 amin = ImGui::GetItemRectMin();
        ImDrawList* dl = ImGui::GetWindowDrawList();

        ID3D11ShaderResourceView* pic = EnsureAvatar(&c);
        ImVec2 a0(amin.x + (cell_w - av) * 0.5f, amin.y);
        ImVec2 a1(a0.x + av, a0.y + av);
        if (pic)
            dl->AddImageRounded(ImTextureRef((void*)pic), a0, a1, ImVec2(0, 0), ImVec2(1, 1), IM_COL32_WHITE, av * 0.5f);
        else
            dl->AddCircleFilled(ImVec2((a0.x + a1.x) * 0.5f, (a0.y + a1.y) * 0.5f), av * 0.5f, ThemeColHover(), 32);

        if (hovered)
        {
            dl->AddCircle(ImVec2((a0.x + a1.x) * 0.5f, (a0.y + a1.y) * 0.5f), av * 0.5f + 1.f,
                ThemeColAccentA(0.85f), 32, ThemePx(1.5f));
            UiHandIfHovered();
            DrawHoverCard(&c, pic);
        }

        std::string name_copy;
        std::string login_copy;
        std::string url_copy;
        int pst = c.profile_st.load();
        {
            std::lock_guard<std::mutex> lock(g_list_mu);
            login_copy = c.login;
            url_copy = c.html_url;
            if (pst == StReady)
                name_copy = c.name;
        }
        const char* label = login_copy.c_str();
        if (pst == StReady && !name_copy.empty())
            label = name_copy.c_str();
        float tx = amin.x;
        float ty = a1.y + ThemePx(4.f);
        dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(), ImVec2(tx, ty),
            hovered ? ThemeColAccent() : ThemeColMuted(), label, nullptr, cell_w);

        if (hit)
            OpenUrl(url_copy.c_str());

        ImGui::PopID();
    }

    if (total > n)
    {
        ImGui::Spacing();
        char more[96];
        snprintf(more, sizeof(more), I18nGet("about.contributors_more"), total - n);
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
        ImGui::TextUnformatted(more);
        ImGui::PopStyleColor();
        if (ImGui::IsItemClicked())
        {
            char url[160];
            snprintf(url, sizeof(url), "https://github.com/%s/%s/graphs/contributors", kRepoOwner, kRepoName);
            OpenUrl(url);
        }
        if (ImGui::IsItemHovered())
            UiHandIfHovered();
    }
}
