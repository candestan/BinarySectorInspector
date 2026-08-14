#include "platform/file_picker.h"

#include <shobjidl.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

bool pick_pe_file(HWND owner, std::wstring& out_path)
{
    IFileOpenDialog* dialog = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&dialog));
    if (FAILED(hr))
        return false;

    const COMDLG_FILTERSPEC filters[] = {
        { L"PE files", L"*.exe;*.dll;*.sys;*.scr;*.ocx;*.cpl" },
        { L"All files", L"*.*" },
    };
    dialog->SetFileTypes(ARRAYSIZE(filters), filters);
    dialog->SetTitle(L"Select PE file");

    FILEOPENDIALOGOPTIONS options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_FILEMUSTEXIST | FOS_FORCEFILESYSTEM);

    hr = dialog->Show(owner);
    if (FAILED(hr))
    {
        dialog->Release();
        return false;
    }

    IShellItem* item = nullptr;
    hr = dialog->GetResult(&item);
    dialog->Release();
    if (FAILED(hr))
        return false;

    PWSTR path = nullptr;
    hr = item->GetDisplayName(SIGDN_FILESYSPATH, &path);
    item->Release();
    if (FAILED(hr) || path == nullptr)
        return false;

    out_path.assign(path);
    CoTaskMemFree(path);
    return true;
}
