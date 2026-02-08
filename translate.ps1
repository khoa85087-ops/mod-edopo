Add-Type -AssemblyName PresentationCore

# ===== FILE LƯU LỊCH SỬ (1 FILE DUY NHẤT) =====
$LogFile = "$PSScriptRoot\translate_log.txt"

# ===== DANH SÁCH TỪ / CỤM ĐÃ LƯU =====
$WordList = @()

# ===== BỘ NHỚ CHỐNG LẶP (CỤM 2 TỪ) =====
$UsedPhrases = New-Object System.Collections.Generic.HashSet[string]

# ===== DANH SÁCH TỪ CẤM =====
$ExcludeWords = @(
    "translate","translation","translator",
    "powershell","script","ps1","cmd","console",
    "cd","dir","cls","clear","exit",
    "windows","system32","users","desktop","documents",
    "program","files","local","appdata","profile",
    "github","google","http","https","www","api",
    "function","param","return","object","string",
    "host","name","rawui","window","size",
    "foreach","while","true","false","null",
    "write","foregroundcolor","newline",
    "the","and","but","for","with","just","very","really"
)

# ===== PHÁT HIỆN CODE / SCRIPT (ĐÃ FIX) =====
function Is-CodeText {
    param ([string]$Text)

    # Chuẩn hoá dash Unicode (– —) về -
    $t = $Text -replace '[–—]', '-'

    $score = 0

    # Dấu hiệu code MẠNH
    if ($t -match '\$[a-zA-Z_][a-zA-Z0-9_]*') { $score += 2 }
    if ($t -match '\b(Add-Type|Write-Host|Invoke-|Get-|Set-|function|param|foreach|while|try|catch)\b') { $score += 2 }

    # Dấu hiệu code TRUNG BÌNH
    if ($t -match '^\s*#') { $score += 1 }
    if ($t -match '\{\s*$') { $score += 1 }
    if ($t -match ';\s*$') { $score += 1 }

    # Chỉ coi là code khi ĐỦ mạnh
    return ($score -ge 3)
}

# ===== WRAP TEXT =====
function Write-WrappedText {
    param (
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $width = $Host.UI.RawUI.WindowSize.Width - 4
    if ($width -lt 40) { $width = 40 }

    $lines = $Text -split "`r?`n"

    foreach ($rawLine in $lines) {
        $words = $rawLine -split '\s+'
        $line = ""

        foreach ($w in $words) {
            if (($line.Length + $w.Length + 1) -gt $width) {
                Write-Host $line -ForegroundColor $Color
                $line = $w
            } else {
                if ($line) { $line += " $w" } else { $line = $w }
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

    if (-not $result.sentences) {
        throw "Google Translate khong tra ve ket qua hop le"
    }

    return ($result.sentences | ForEach-Object { $_.trans }) -join ""
}

# ===== GHI LOG RA FILE =====
function Write-TranslateLog {
    param (
        [string]$EN,
        [string]$VI
    )

    $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $log = @"
==============================
TIME: $time

EN:
$EN

VI:
$VI
==============================

"@

    Add-Content -Path $LogFile -Value $log -Encoding UTF8
}

# ===== LẤY CỤM 2 TỪ LIỀN KỀ =====
function Get-RandomPhrase2 {
    param ([string]$Text)

    if (Is-CodeText $Text) { return $null }

    $rawWords = $Text.ToLower() `
        -replace '[^a-z\s]', ' ' `
        -split '\s+' |
        Where-Object { $_ -ne "" }

    if ($rawWords.Count -lt 2) { return $null }

    $phrases = @()

    for ($i = 0; $i -lt $rawWords.Count - 1; $i++) {
        $w1 = $rawWords[$i]
        $w2 = $rawWords[$i + 1]

        if (
            $w1.Length -lt 3 -or
            $w2.Length -lt 3 -or
            $ExcludeWords -contains $w1 -or
            $ExcludeWords -contains $w2
        ) { continue }

        $phrase = "$w1 $w2"

        if (-not $UsedPhrases.Contains($phrase)) {
            $phrases += $phrase
        }
    }

    if ($phrases.Count -eq 0) { return $null }
    return Get-Random -InputObject $phrases
}

# ===== HEADER =====
function Show-Header {
    Write-Host "=== Dich Clipboard (EN) + Cum Tu ===" -ForegroundColor Cyan
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
    if (Is-CodeText $text) { continue }

    $lastText = $text

    try {
        $translated = Translate-Text $text

        Write-TranslateLog -EN $text -VI $translated

        $phrase = Get-RandomPhrase2 $text
        if ($phrase) {
            $UsedPhrases.Add($phrase) | Out-Null
            $WordList += [PSCustomObject]@{
                word    = $phrase
                meaning = (Translate-Text $phrase)
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
        Write-Host "=== CUM TU NGAU NHIEN ===" -ForegroundColor Yellow
        foreach ($item in $WordList | Select-Object -Last 8) {
            Write-Host ("• " + $item.word) -ForegroundColor Cyan -NoNewline
            Write-Host ("  →  " + $item.meaning) -ForegroundColor DarkGreen
        }
    }
    catch {
        Clear-Host
        Show-Header
        Write-Host "Loi khi dich!" -ForegroundColor Red
        Write-Host $_ -ForegroundColor DarkRed
    }
}
