#include "ui/open_target_dialog.h"
#include "platform/file_picker.h"
#include "platform/utf8.h"
#include "imgui.h"

#include <filesystem>
#include <string>

void OpenTargetDialog::set_path(std::wstring path)
{
    selected_path_ = std::move(path);
    status_ = selected_path_.empty()
        ? "No target selected."
        : ("Target: " + wide_to_utf8(selected_path_));
}

void OpenTargetDialog::refresh_processes()
{
    entries_ = snapshot_window_processes();
    selected_row_ = -1;
    snapshot_ready_ = true;
}

bool OpenTargetDialog::draw(HWND owner)
{
    if (!snapshot_ready_)
        refresh_processes();

    bool confirmed = false;

    ImGui::SetNextWindowPos(ImVec2(48.f, 48.f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(900.f, 520.f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Open target"))
    {
        ImGui::End();
        return false;
    }

    if (ImGui::Button("Browse file..."))
    {
        std::wstring path;
        if (pick_pe_file(owner, path))
            set_path(std::move(path));
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh windows"))
        refresh_processes();

    ImGui::InputTextWithHint("##filter", "Filter title / pid / path", filter_, sizeof(filter_));

    const ImGuiTableFlags flags =
        ImGuiTableFlags_Borders |
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_Resizable |
        ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_SizingStretchProp;

    if (ImGui::BeginTable("window_processes", 4, flags, ImVec2(0.f, -96.f)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Window");
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 80.f);
        ImGui::TableSetupColumn("Image");
        ImGui::TableSetupColumn("Path");
        ImGui::TableHeadersRow();

        for (int i = 0; i < static_cast<int>(entries_.size()); ++i)
        {
            const WindowProcessEntry& entry = entries_[i];
            const std::string title = wide_to_utf8(entry.title);
            const std::string path = wide_to_utf8(entry.image_path);
            const std::string image = entry.image_path.empty()
                ? std::string("(access denied)")
                : wide_to_utf8(std::filesystem::path(entry.image_path).filename().wstring());

            if (filter_[0] != '\0')
            {
                const std::string pid = std::to_string(entry.pid);
                if (title.find(filter_) == std::string::npos &&
                    pid.find(filter_) == std::string::npos &&
                    path.find(filter_) == std::string::npos)
                    continue;
            }

            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            const bool is_selected = (selected_row_ == i);
            if (ImGui::Selectable(title.c_str(), is_selected,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
            {
                selected_row_ = i;
                if (!entry.image_path.empty())
                    set_path(entry.image_path);
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && !selected_path_.empty())
                    confirmed = true;
            }
            ImGui::TableNextColumn();
            ImGui::Text("%lu", entry.pid);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(image.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(path.c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    ImGui::Separator();
    ImGui::TextWrapped("%s", status_.empty() ? "Select a window or browse a file." : status_.c_str());

    const bool can_analyze = !selected_path_.empty();
    if (!can_analyze)
        ImGui::BeginDisabled();
    if (ImGui::Button("Analyze"))
        confirmed = true;
    if (!can_analyze)
        ImGui::EndDisabled();

    ImGui::End();
    return confirmed;
}
