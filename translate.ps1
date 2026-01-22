

# ================== THIẾT LẬP CỬA SỔ ==================
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(120, 300)
$Host.UI.RawUI.WindowSize = New-Object Management.Automation.Host.Size(120, 40)

Add-Type -AssemblyName PresentationCore

# ================== DANH SÁCH TỪ VỰNG ==================
$WordList = @()

# ❗ TỪ KHÓA KHÔNG LẤY (sửa nếu muốn)
$ExcludeWords = @(
    "translate","powershell","script","ps1",
    "cd","dir","cls","windows","system32"
)

# ================== HÀM DỊCH (GIỮ NGUYÊN DÒNG) ==================
function Translate-Text {
    param ([string]$Text)

    $lines = $Text -split "`r?`n"
    $out = @()

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            $out += ""
            continue
        }

        $encoded = [uri]::EscapeDataString($line)
        $url = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=vi&dt=t&dj=1&q=$encoded"
        $result = Invoke-RestMethod -Uri $url -TimeoutSec 10
        $out += ($result.sentences | ForEach-Object { $_.trans }) -join ""
    }

    return ($out -join "`n")
}

# ================== LẤY TỪ NGẪU NHIÊN ==================
function Get-RandomWord {
    param ([string]$Text)

    if ($Text -match '^\s*(cd|dir|cls|\.\\)') { return $null }

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

# ================== HEADER ==================
function Show-Header {
    Write-Host "=== Dich Clipboard (GIU DINH DANG) ===" -ForegroundColor Cyan
    Write-Host "Boi den van ban tieng Anh -> Ctrl+C" -ForegroundColor DarkGray
    Write-Host "------------------------------------" -ForegroundColor DarkGray
}

Clear-Host
Show-Header

$lastText = ""

# ================== LOOP CHÍNH ==================
while ($true) {
    Start-Sleep -Milliseconds 700
    $text = Get-Clipboard -Raw

    if ([string]::IsNullOrWhiteSpace($text)) { continue }
    if ($text -eq $lastText) { continue }
    if ($text.Length -gt 5000) { continue }

    $lastText = $text

    try {
        $translated = Translate-Text $text

        # ---- TỪ VỰNG NGẪU NHIÊN ----
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
        Write-Host $text -ForegroundColor Gray

        Write-Host ""
        Write-Host "VI:" -ForegroundColor Green
        Write-Host $translated -ForegroundColor DarkGreen

        Write-Host ""
        Write-Host "=== TU VUNG DA LUU ===" -ForegroundColor Yellow

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


