
Add-Type -AssemblyName PresentationCore

# ===== DANH SÁCH TỪ ĐÃ LƯU =====
$WordList = @()

# ===== DANH SÁCH TỪ CẤM =====
$ExcludeWords = @(
    "translate","powershell","script","ps1","cd","dir","cls",
    "windows","system32","users","desktop","documents",
    "program","files","local","appdata","profile"
)

# ===== HÀM WRAP (XUỐNG DÒNG KHI KÝ TỰ ĐẶC BIỆT + CHỮ HOA) =====
function Write-WrappedText {
    param (
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $width = $Host.UI.RawUI.WindowSize.Width - 4
    if ($width -lt 40) { $width = 40 }

    # Chuẩn hóa: chèn xuống dòng trước ký tự đặc biệt nếu sau nó là chữ HOA
    $normalized = $Text -replace '([•\-\*\:\;→])\s*([A-Z])', "`n`$1 `$2"

    $lines = $normalized -split "`r?`n"

    foreach ($rawLine in $lines) {
        $words = $rawLine -split '\s+'
        $line = ""

        foreach ($word in $words) {
            if (($line.Length + $word.Length + 1) -gt $width) {
                Write-Host $line -ForegroundColor $Color
                $line = $word
            } else {
                if ($line) { $line += " " + $word } else { $line = $word }
            }
        }

        if ($line) {
            Write-Host $line -ForegroundColor $Color
        }
    }
}

# ===== HÀM DỊCH =====
function Translate-Text {
    param ([string]$Text)

    $encoded = [uri]::EscapeDataString($Text)
    $url = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=vi&dt=t&dj=1&q=$encoded"
    $result = Invoke-RestMethod -Uri $url -TimeoutSec 10
    return ($result.sentences | ForEach-Object { $_.trans }) -join ""
}

# ===== LẤY TỪ NGẪU NHIÊN =====
function Get-RandomWord {
    param ([string]$Text)

    if ($Text -match '^\s*(cd|dir|cls|\.\\|\.\/)') { return $null }

    $words = $Text.ToLower() `
        -replace '[^a-z\s]', '' `
        -split '\s+' |
        Where-Object {
            $_.Length -ge 5 -and
            ($ExcludeWords -notcontains $_)
        }

    if ($words.Count -eq 0) { return $null }
    return Get-Random -InputObject $words
}

# ===== HEADER =====
function Show-Header {
    Write-Host "=== Dich Clipboard (EN) + Tu Vung ===" -ForegroundColor Cyan
    Write-Host "Boi den van ban tieng Anh -> Ctrl+C" -ForegroundColor DarkGray
    Write-Host "--------------------------------" -ForegroundColor DarkGray
}

Clear-Host
Show-Header
$lastText = ""

while ($true) {
    Start-Sleep -Milliseconds 700
    $text = Get-Clipboard -Raw

    if ([string]::IsNullOrWhiteSpace($text)) { continue }
    if ($text -eq $lastText) { continue }
    if ($text.Length -gt 5000) { continue }

    $lastText = $text

    try {
        $translated = Translate-Text $text

        $word = Get-RandomWord $text
        if ($word -and ($WordList.word -notcontains $word)) {
            $WordList += [PSCustomObject]@{
                word    = $word
                meaning = (Translate-Text $word)
            }
        }

        Clear-Host
        Show-Header

        Write-Host "EN:" -ForegroundColor Cyan
        Write-WrappedText $text Gray

        Write-Host ""
        Write-Host "VI:" -ForegroundColor Green
        Write-WrappedText $translated DarkGreen

        Write-Host ""
        Write-Host "=== TU VUNG NGAU NHIEN ===" -ForegroundColor Yellow
        foreach ($item in $WordList | Select-Object -Last 8) {
            Write-Host ("• " + $item.word) -ForegroundColor Cyan -NoNewline
            Write-Host ("  →  " + $item.meaning) -ForegroundColor DarkGreen
        }
    }
    catch {
        Clear-Host
        Show-Header
        Write-Host "Loi khi dich!" -ForegroundColor Red
    }
}
