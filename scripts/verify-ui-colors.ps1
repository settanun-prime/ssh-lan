$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework
$path = Join-Path $PSScriptRoot 'ssh-lan-ui.xaml'
$xml = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
$reader = [Xml.XmlReader]::Create([IO.StringReader]::new($xml))
$window = [Windows.Markup.XamlReader]::Load($reader)
function Format-Brush($brush) {
    if (-not $brush) { return 'none' }
    $c = $brush.Color
    return ('#{0:X2}{1:X2}{2:X2}' -f $c.R, $c.G, $c.B)
}
foreach ($name in @('BtnPrimary', 'BtnTest', 'BtnRemove')) {
    $button = $window.FindName($name)
    $hoverBg = 'n/a'
    $hoverFg = 'n/a'
    foreach ($trigger in $button.Template.Triggers) {
        if ($trigger -isnot [System.Windows.Trigger]) { continue }
        if ($trigger.Property.Name -ne 'IsMouseOver') { continue }
        foreach ($setter in $trigger.Setters) {
            if ($setter.Property.Name -eq 'Background') { $hoverBg = Format-Brush $setter.Value }
            if ($setter.Property.Name -eq 'Foreground') { $hoverFg = Format-Brush $setter.Value }
        }
    }
    $restFg = Format-Brush $button.Foreground
    $restBg = Format-Brush $button.Background
    Write-Output "$name restFg=$restFg restBg=$restBg hoverFg=$hoverFg hoverBg=$hoverBg"
}
