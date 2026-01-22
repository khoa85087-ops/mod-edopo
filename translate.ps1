
Add-Type -AssemblyName PresentationCore

# ===== HÀM WRAP THÔNG MINH THEO ĐỘ RỘNG CỬA SỔ =====
function Write-WrappedText {
    param (
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $width = $Host.UI.RawUI.WindowSize.Width - 4
    if ($width -lt 40) { $width = 40 }

    $words = $Text -split '\s+'
    $line = ""

    foreach ($word in $words) {
        if (($line.Length + $word.Length + 1) -gt $width) {
            Write-Host $line -ForegroundColor $Color
            $line = $word
        } else {
            if ($line) {
                $line += " " + $word
            } else {
                $line = $word
            }
        }
    }

    if ($line) {
        Write-Host $line -ForegroundColor $Color
    }
}

# ===== HÀM IN HEADER =====
function Show-Header {
    Write-Host "=== Dich Clipboard (EN + VI) ===" -ForegroundColor Cyan
    Write-Host "Boi den van ban tieng Anh -> Ctrl+C" -ForegroundColor DarkGray
    Write-Host "--------------------------------" -ForegroundColor DarkGray
}

# ===== KHỞI TẠO =====
Clear-Host
Show-Header

$lastText = ""

while ($true) {
    Start-Sleep -Milliseconds 700

    $text = Get-Clipboard -Raw

    if ([string]::IsNullOrWhiteSpace($text)) { continue }
    if ($text -eq $lastText) { continue }
    if ($text.Length -gt 5000) {
        Clear-Host
        Show-Header
        Write-Host "Van ban qua dai (>5000 ky tu), bo qua." -ForegroundColor Yellow
        $lastText = $text
        continue
    }

    $lastText = $text

    try {
        $encoded = [uri]::EscapeDataString($text)
        $url = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=vi&dt=t&dj=1&q=$encoded"

        $result = Invoke-RestMethod -Uri $url -TimeoutSec 10
        $translated = ($result.sentences | ForEach-Object { $_.trans }) -join ""

        # ===== XÓA KẾT QUẢ CŨ =====
        Clear-Host
        Show-Header

        Write-Host "EN:" -ForegroundColor Cyan
        Write-WrappedText $text Gray

        Write-Host ""

        Write-Host "VI:" -ForegroundColor Green
        Write-WrappedText $translated DarkGreen
    }
    catch {
        Clear-Host
        Show-Header
        Write-Host "Loi khi dich!" -ForegroundColor Red
    }
}
