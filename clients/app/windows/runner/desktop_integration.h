#ifndef RUNNER_DESKTOP_INTEGRATION_H_
#define RUNNER_DESKTOP_INTEGRATION_H_

#include <windows.h>
#include <shellapi.h>

#include <flutter/encodable_value.h>
#include <flutter/method_channel.h>

#include <memory>
#include <optional>

// Owns client-only desktop preferences, notification icon, and Flutter channel.
class DesktopIntegration {
 public:
  DesktopIntegration(HWND window, flutter::BinaryMessenger* messenger);
  ~DesktopIntegration();

  DesktopIntegration(const DesktopIntegration&) = delete;
  DesktopIntegration& operator=(const DesktopIntegration&) = delete;

  std::optional<LRESULT> HandleMessage(UINT message, WPARAM wparam,
                                       LPARAM lparam);

 private:
  DWORD EnsureTrayIcon();
  void RemoveTrayIcon();
  void RestoreWindow();
  void ShowTrayMenu();
  DWORD RequestQuit();
  DWORD ReadState(flutter::EncodableValue* state);
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue>& call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  HWND window_;
  UINT taskbar_created_message_ = 0;
  NOTIFYICONDATAW tray_icon_{};
  bool tray_icon_added_ = false;
  bool close_to_tray_ = false;
  bool quit_requested_ = false;
  std::unique_ptr<flutter::MethodChannel<flutter::EncodableValue>> channel_;
};

#endif  // RUNNER_DESKTOP_INTEGRATION_H_
