#include "desktop_integration.h"

#include <shlobj.h>
#include <flutter/standard_method_codec.h>

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "resource.h"

namespace {
constexpr wchar_t kPreferencesKey[] = L"Software\\RDPMonitor\\Desktop";
constexpr wchar_t kCloseToTrayValue[] = L"CloseToTray";
constexpr wchar_t kRunKey[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kStartupValue[] = L"RDPMonitorDesktop";
constexpr UINT kTrayMessage = WM_APP + 20;
constexpr UINT kTrayIconId = 1;
constexpr UINT kOpenCommand = 1;
constexpr UINT kExitCommand = 2;

bool IsMissing(DWORD error) {
  return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

DWORD ReadCloseToTray(bool* enabled) {
  *enabled = false;
  DWORD value = 0;
  DWORD size = sizeof(value);
  const LSTATUS status = RegGetValueW(
      HKEY_CURRENT_USER, kPreferencesKey, kCloseToTrayValue, RRF_RT_REG_DWORD,
      nullptr, &value, &size);
  if (IsMissing(status)) {
    return ERROR_SUCCESS;
  }
  if (status != ERROR_SUCCESS) {
    return status;
  }
  if (value > 1) {
    return ERROR_INVALID_DATA;
  }
  *enabled = value != 0;
  return ERROR_SUCCESS;
}

DWORD WriteCloseToTray(bool enabled) {
  HKEY key = nullptr;
  LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, kPreferencesKey, 0,
                                  nullptr, 0, KEY_SET_VALUE, nullptr, &key,
                                  nullptr);
  if (status != ERROR_SUCCESS) {
    return status;
  }
  const DWORD value = enabled ? 1 : 0;
  status = RegSetValueExW(key, kCloseToTrayValue, 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&value), sizeof(value));
  RegCloseKey(key);
  return status;
}

DWORD ReadStartAtLogin(bool* enabled) {
  *enabled = false;
  DWORD size = 0;
  constexpr DWORD flags =
      RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
  LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, kRunKey, kStartupValue,
                                flags, nullptr, nullptr, &size);
  if (IsMissing(status)) {
    return ERROR_SUCCESS;
  }
  if (status != ERROR_SUCCESS) {
    return status;
  }
  if (size % sizeof(wchar_t) != 0) {
    return ERROR_INVALID_DATA;
  }
  std::vector<wchar_t> value(size / sizeof(wchar_t) + 1, L'\0');
  status = RegGetValueW(HKEY_CURRENT_USER, kRunKey, kStartupValue, flags,
                       nullptr, value.data(), &size);
  if (IsMissing(status)) {
    return ERROR_SUCCESS;
  }
  if (status == ERROR_SUCCESS) {
    *enabled = value.front() != L'\0';
  }
  return status;
}

DWORD StartupCommand(std::wstring* command) {
  PWSTR programs_path = nullptr;
  const HRESULT result = SHGetKnownFolderPath(
      FOLDERID_CommonPrograms, KF_FLAG_DONT_VERIFY, nullptr, &programs_path);
  if (FAILED(result)) {
    return HRESULT_FACILITY(result) == FACILITY_WIN32
               ? HRESULT_CODE(result)
               : static_cast<DWORD>(result);
  }
  std::wstring shortcut(programs_path);
  CoTaskMemFree(programs_path);
  shortcut += L"\\RDPMonitor.lnk";
  const DWORD attributes = GetFileAttributesW(shortcut.c_str());
  if (attributes != INVALID_FILE_ATTRIBUTES) {
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      return ERROR_DIRECTORY;
    }
    wchar_t windows_path[MAX_PATH];
    const UINT length = GetWindowsDirectoryW(windows_path, MAX_PATH);
    if (length == 0) {
      return GetLastError();
    }
    if (length >= MAX_PATH) {
      return ERROR_INSUFFICIENT_BUFFER;
    }
    // The installer updates this shortcut when the versioned release changes.
    *command = L"\"" + std::wstring(windows_path, length) +
               L"\\explorer.exe\" \"" + shortcut + L"\"";
    return ERROR_SUCCESS;
  }
  const DWORD shortcut_error = GetLastError();
  if (!IsMissing(shortcut_error)) {
    return shortcut_error;
  }

  // Source builds have no installed shortcut. Quote the full executable path.
  std::wstring executable(512, L'\0');
  for (;;) {
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0) {
      return GetLastError();
    }
    if (length < executable.size()) {
      executable.resize(length);
      *command = L"\"" + executable + L"\"";
      return ERROR_SUCCESS;
    }
    if (executable.size() >= 32768) {
      return ERROR_INSUFFICIENT_BUFFER;
    }
    executable.resize(executable.size() * 2);
  }
}

DWORD WriteStartAtLogin(bool enabled) {
  HKEY key = nullptr;
  if (!enabled) {
    LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0,
                                   KEY_SET_VALUE, &key);
    if (IsMissing(status)) {
      return ERROR_SUCCESS;
    }
    if (status != ERROR_SUCCESS) {
      return status;
    }
    status = RegDeleteValueW(key, kStartupValue);
    RegCloseKey(key);
    return IsMissing(status) ? ERROR_SUCCESS : status;
  }

  std::wstring command;
  DWORD error = StartupCommand(&command);
  if (error != ERROR_SUCCESS) {
    return error;
  }
  // Run values have a documented 260-character command-line limit.
  if (command.size() > 260) {
    return ERROR_FILENAME_EXCED_RANGE;
  }
  LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, nullptr, 0,
                                  KEY_SET_VALUE, nullptr, &key, nullptr);
  if (status != ERROR_SUCCESS) {
    return status;
  }
  status = RegSetValueExW(
      key, kStartupValue, 0, REG_SZ,
      reinterpret_cast<const BYTE*>(command.c_str()),
      static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
  RegCloseKey(key);
  return status;
}

void ReportError(flutter::MethodResult<flutter::EncodableValue>* result,
                 const char* operation, DWORD error) {
  wchar_t* system_message = nullptr;
  const DWORD length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, error, 0, reinterpret_cast<wchar_t*>(&system_message), 0, nullptr);
  std::string message(operation);
  message += " failed (Windows error " + std::to_string(error) + ")";
  if (length != 0 && system_message != nullptr) {
    const int utf8_length = WideCharToMultiByte(
        CP_UTF8, 0, system_message, static_cast<int>(length), nullptr, 0,
        nullptr, nullptr);
    std::string utf8(static_cast<size_t>(utf8_length), '\0');
    if (utf8_length > 0) {
      WideCharToMultiByte(CP_UTF8, 0, system_message, static_cast<int>(length),
                          utf8.data(), utf8_length, nullptr, nullptr);
      message += ": " + utf8;
    }
  }
  if (system_message != nullptr) {
    LocalFree(system_message);
  }
  const flutter::EncodableValue details(flutter::EncodableMap{
      {flutter::EncodableValue("windowsError"),
       flutter::EncodableValue(static_cast<int64_t>(error))},
      {flutter::EncodableValue("operation"),
       flutter::EncodableValue(operation)}});
  result->Error("windows_error", message, details);
}
}  // namespace

DesktopIntegration::DesktopIntegration(HWND window,
                                       flutter::BinaryMessenger* messenger)
    : window_(window) {
  taskbar_created_message_ = RegisterWindowMessageW(L"TaskbarCreated");
  ReadCloseToTray(&close_to_tray_);
  EnsureTrayIcon();
  channel_ = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      messenger, "rdpmonitor/desktop",
      &flutter::StandardMethodCodec::GetInstance());
  channel_->SetMethodCallHandler(
      [this](const flutter::MethodCall<flutter::EncodableValue>& call,
             std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>
                 result) { HandleMethodCall(call, std::move(result)); });
}

DesktopIntegration::~DesktopIntegration() {
  channel_->SetMethodCallHandler(nullptr);
  RemoveTrayIcon();
}

DWORD DesktopIntegration::EnsureTrayIcon() {
  if (tray_icon_added_) {
    // Verify that Explorer still owns the icon before making the window hidden.
    if (Shell_NotifyIconW(NIM_MODIFY, &tray_icon_)) {
      return ERROR_SUCCESS;
    }
    tray_icon_added_ = false;
  }
  if (taskbar_created_message_ == 0) {
    taskbar_created_message_ = RegisterWindowMessageW(L"TaskbarCreated");
    if (taskbar_created_message_ == 0) {
      return GetLastError();
    }
  }
  tray_icon_.cbSize = sizeof(tray_icon_);
  tray_icon_.hWnd = window_;
  tray_icon_.uID = kTrayIconId;
  tray_icon_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
  tray_icon_.uCallbackMessage = kTrayMessage;
  tray_icon_.hIcon = LoadIconW(GetModuleHandleW(nullptr),
                              MAKEINTRESOURCEW(IDI_APP_ICON));
  if (tray_icon_.hIcon == nullptr) {
    return GetLastError();
  }
  wcscpy_s(tray_icon_.szTip, L"RDPMonitor");
  SetLastError(ERROR_SUCCESS);
  if (!Shell_NotifyIconW(NIM_ADD, &tray_icon_)) {
    const DWORD error = GetLastError();
    // Shell_NotifyIcon does not promise to populate GetLastError.
    return error == ERROR_SUCCESS ? ERROR_NOT_READY : error;
  }
  tray_icon_added_ = true;
  return ERROR_SUCCESS;
}

void DesktopIntegration::RemoveTrayIcon() {
  if (tray_icon_added_) {
    Shell_NotifyIconW(NIM_DELETE, &tray_icon_);
    tray_icon_added_ = false;
  }
  // LoadIcon returns a shared resource icon; it must not be destroyed.
}

void DesktopIntegration::RestoreWindow() {
  ShowWindow(window_, IsIconic(window_) ? SW_RESTORE : SW_SHOW);
  SetForegroundWindow(window_);
}

void DesktopIntegration::ShowTrayMenu() {
  HMENU menu = CreatePopupMenu();
  if (menu == nullptr) {
    RestoreWindow();
    return;
  }
  if (!AppendMenuW(menu, MF_STRING, kOpenCommand, L"Open RDPMonitor") ||
      !AppendMenuW(menu, MF_STRING, kExitCommand, L"Exit")) {
    DestroyMenu(menu);
    RestoreWindow();
    return;
  }
  SetMenuDefaultItem(menu, kOpenCommand, FALSE);
  POINT position{};
  GetCursorPos(&position);
  SetForegroundWindow(window_);
  const UINT command = TrackPopupMenu(
      menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, position.x,
      position.y, 0, window_, nullptr);
  DestroyMenu(menu);
  // Required by notification-area menus so a subsequent click dismisses them.
  PostMessageW(window_, WM_NULL, 0, 0);
  if (command == kOpenCommand) {
    RestoreWindow();
  } else if (command == kExitCommand) {
    if (RequestQuit() != ERROR_SUCCESS) {
      RestoreWindow();
    }
  }
}

DWORD DesktopIntegration::RequestQuit() {
  if (!PostMessageW(window_, WM_CLOSE, 0, 0)) {
    return GetLastError();
  }
  quit_requested_ = true;
  return ERROR_SUCCESS;
}

DWORD DesktopIntegration::ReadState(flutter::EncodableValue* state) {
  bool start_at_login = false;
  DWORD error = ReadStartAtLogin(&start_at_login);
  if (error != ERROR_SUCCESS) {
    return error;
  }
  bool close_to_tray = false;
  error = ReadCloseToTray(&close_to_tray);
  if (error != ERROR_SUCCESS) {
    return error;
  }
  close_to_tray_ = close_to_tray;
  *state = flutter::EncodableValue(flutter::EncodableMap{
      {flutter::EncodableValue("startAtLogin"),
       flutter::EncodableValue(start_at_login)},
      {flutter::EncodableValue("closeToTray"),
       flutter::EncodableValue(close_to_tray_)}});
  return ERROR_SUCCESS;
}

void DesktopIntegration::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  const std::string& method = call.method_name();
  if (method == "hide") {
    const DWORD error = EnsureTrayIcon();
    if (error != ERROR_SUCCESS) {
      ReportError(result.get(), "Create notification-area icon", error);
      return;
    }
    ShowWindow(window_, SW_HIDE);
    result->Success();
    return;
  }
  if (method == "quit") {
    const DWORD error = RequestQuit();
    if (error != ERROR_SUCCESS) {
      ReportError(result.get(), "Exit desktop client", error);
      return;
    }
    result->Success();
    return;
  }
  if (method != "getState" && method != "setStartAtLogin" &&
      method != "setCloseToTray") {
    result->NotImplemented();
    return;
  }

  const bool* enabled = nullptr;
  if (method != "getState") {
    if (call.arguments() != nullptr) {
      enabled = std::get_if<bool>(call.arguments());
    }
    if (enabled == nullptr) {
      result->Error("invalid_argument", "Expected a boolean argument.");
      return;
    }
  }

  DWORD error = ERROR_SUCCESS;
  if (method == "setStartAtLogin") {
    error = WriteStartAtLogin(*enabled);
  } else if (method == "setCloseToTray") {
    if (*enabled) {
      error = EnsureTrayIcon();
    }
    if (error == ERROR_SUCCESS) {
      error = WriteCloseToTray(*enabled);
      if (error == ERROR_SUCCESS) {
        close_to_tray_ = *enabled;
      }
    }
  }
  if (error != ERROR_SUCCESS) {
    ReportError(result.get(), method.c_str(), error);
    return;
  }
  flutter::EncodableValue state;
  error = ReadState(&state);
  if (error != ERROR_SUCCESS) {
    ReportError(result.get(), "Read desktop preferences", error);
    return;
  }
  result->Success(state);
}

std::optional<LRESULT> DesktopIntegration::HandleMessage(
    UINT message, WPARAM wparam, LPARAM lparam) {
  if (taskbar_created_message_ != 0 && message == taskbar_created_message_) {
    tray_icon_added_ = false;
    if (EnsureTrayIcon() != ERROR_SUCCESS && !IsWindowVisible(window_)) {
      // Never leave a hidden client inaccessible if Explorer cannot restore it.
      RestoreWindow();
    }
    return 0;
  }
  if (message == kTrayMessage && wparam == kTrayIconId) {
    if (lparam == WM_LBUTTONUP || lparam == WM_LBUTTONDBLCLK ||
        lparam == NIN_SELECT || lparam == NIN_KEYSELECT) {
      RestoreWindow();
    } else if (lparam == WM_RBUTTONUP || lparam == WM_CONTEXTMENU) {
      ShowTrayMenu();
    }
    return 0;
  }
  if (message == WM_CLOSE && !quit_requested_ && close_to_tray_ &&
      EnsureTrayIcon() == ERROR_SUCCESS) {
    ShowWindow(window_, SW_HIDE);
    return 0;
  }
  return std::nullopt;
}
