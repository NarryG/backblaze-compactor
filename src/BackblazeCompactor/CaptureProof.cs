using System.Globalization;
using System.Text.Json;

namespace BackblazeCompactor;

internal sealed class CaptureProof
{
    internal const string BinarySha256 = "9522d21b72fd25896c9e5b857acb3b5b022fb14618d863b7294ea40ab65c3b70";
    public bool ClientMatches { get; }
    public bool ObservedQuiescent { get; }
    public bool PendingCovered { get; }
    public bool HistoryCovered { get; }
    public bool RepairFree { get; }
    private readonly string[] excluded = [];
    private readonly string[] included = [];
    private readonly bool exclusionInventoryComplete;

    public CaptureProof(JsonElement manifest)
    {
        if (!manifest.TryGetProperty("capture", out var capture) || capture.ValueKind != JsonValueKind.Object) return;
        ClientMatches = capture.TryGetProperty("clientSha256", out var sha) && sha.ValueKind == JsonValueKind.String
            && string.Equals(sha.GetString(), BinarySha256, StringComparison.OrdinalIgnoreCase);
        ObservedQuiescent = Flag(capture, "writerObservationComplete") && Flag(capture, "writerDrainComplete")
            && Empty(capture, "writersBefore") && Empty(capture, "writersAfter") && Empty(capture, "writersStarted");
        HistoryCovered = Flag(capture, "historyCoverageComplete") && Empty(capture, "unsupportedLedgerNames");
        PendingCovered = Flag(capture, "pendingCoverageComplete")
            && Volume(capture, "externalScratchVolumeBefore", out var before)
            && Volume(capture, "externalScratchVolumeAfter", out var after) && before == after
            && capture.TryGetProperty("pendingDirectories", out var pending) && pending.ValueKind == JsonValueKind.Object
            && Empty(pending, "thread") && Empty(pending, "mainLarge")
            && Empty(pending, "externalLargeBefore") && Empty(pending, "externalLargeAfter")
            && pending.EnumerateObject().All(p => p.Value.ValueKind == JsonValueKind.Array && p.Value.GetArrayLength() == 0);
        RepairFree = Empty(capture, "repairMarkers") && Empty(capture, "catalogSidecars");
        bool excludedComplete = Strings(capture, "excludedDirectories", out excluded);
        bool includedComplete = Strings(capture, "includedDirectories", out included);
        exclusionInventoryComplete = excludedComplete && includedComplete;
    }

    private static bool Flag(JsonElement element, string name) => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
    private static bool Empty(JsonElement element, string name) => element.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 0;
    private static bool Strings(JsonElement element, string name, out string[] values)
    {
        values = [];
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array
            || !value.EnumerateArray().All(v => v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString())))
            return false;
        values = value.EnumerateArray().Select(v => v.GetString()!).ToArray();
        return true;
    }

    private static bool Volume(JsonElement capture, string name, out (Guid Volume, uint Serial) identity)
    {
        identity = default;
        if (!capture.TryGetProperty(name, out var volume) || volume.ValueKind != JsonValueKind.Object
            || !Flag(volume, "available") || volume.TryGetProperty("error", out _)
            || !volume.TryGetProperty("volumeId", out var id) || id.ValueKind != JsonValueKind.String)
            return false;
        string value = id.GetString()!;
        if (value.Length != 58 || !value.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase)
            || !value.AsSpan(47, 3).SequenceEqual(@"}\:") || !Guid.TryParse(value.AsSpan(10, 38), out var guid)
            || !uint.TryParse(value.AsSpan(50), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out uint serial))
            return false;
        identity = (guid, serial);
        return true;
    }

    // Only compare unambiguous, drive-absolute directory selectors. In particular,
    // never turn a relative, wildcard or dot-segment selector into proof.
    private static bool TrySelector(string value, out string selector)
    {
        selector = "";
        value = value.Replace('/', '\\');
        if (value.Length < 3 || !char.IsAsciiLetter(value[0]) || value[1] != ':' || value[2] != '\\'
            || value.Any(c => c < 32 || c > 126 || c is '*' or '?' or '"' or '<' or '>' or '|')
            || value.AsSpan(2).Contains(':'))
            return false;
        string[] parts = value[3..].TrimEnd('\\').Split('\\');
        if (parts.Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
        {
            if (value.Length != 3) return false;
        }
        selector = value.TrimEnd('\\') + "\\";
        return true;
    }

    public bool ExclusionCovers(RetiredPrefix prefix)
    {
        if (!exclusionInventoryComplete || !TrySelector(prefix.Value, out string target)) return false;
        int longestExclusion = 0;
        foreach (string entry in excluded)
        {
            if (!TrySelector(entry, out string selector)) return false;
            if (target.StartsWith(selector, StringComparison.OrdinalIgnoreCase))
                longestExclusion = Math.Max(longestExclusion, selector.Length);
        }
        foreach (string entry in included)
        {
            if (!TrySelector(entry, out string selector)) return false;
            // Any included part of the target prevents proving the whole subtree.
            if (selector.StartsWith(target, StringComparison.OrdinalIgnoreCase)
                || (target.StartsWith(selector, StringComparison.OrdinalIgnoreCase)
                    && selector.Length >= longestExclusion))
                return false;
        }
        return longestExclusion != 0;
    }
}
