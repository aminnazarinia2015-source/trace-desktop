; Real TRACE product copy only (captured from the live tracems.com homepage and
; TRACE's own stated positioning) -- no fabricated claims, no testimonials.
;
; 2026-09-11: switched to electron-builder's one-click installer (oneClick: true
; in package.json) -- a single branded progress window, no wizard pages, matching
; the modern-app install feel (Slack/Discord/Chrome) instead of the classic NSIS
; multi-page wizard. The Welcome/Finish page macros and custom sidebar bitmaps
; that only applied to the old assisted (multi-page) installer have been removed
; since oneClick mode has no wizard pages to customize. customInit below still
; runs in both modes, so the pre-install cleanup step is unchanged.
;
; 2026-09-30: added ManifestDPIAware -- without it, the one-click installer
; window is not declared DPI-aware to Windows, so on scaled high-DPI displays
; (e.g. 250% scaling) Windows bitmap-stretches the installer window and its
; text renders blurry. This embeds a DPI-aware manifest in the installer exe
; so Windows renders it natively sharp at any scale factor. Does not affect
; the installed app itself (Electron/Chromium is already per-monitor DPI aware).
ManifestDPIAware true

!macro customInit
; Close legacy and current desktop processes before replacing application files.
; Local encrypted drafts are persisted continuously and application data is retained.
nsExec::ExecToStack 'taskkill /F /T /IM "ZecoCM Desktop.exe"'
Pop $0
Pop $1
nsExec::ExecToStack 'taskkill /F /T /IM "TRACE Desktop.exe"'
Pop $0
Pop $1
Sleep 1200
!macroend
