namespace BackblazeCompactor;

internal static class ByteFields
{
    public static int Split(ReadOnlySpan<byte> content, Span<Range> fields)
    {
        int start = 0;
        int count = 0;
        while (true)
        {
            if (count == fields.Length) return fields.Length;
            int next = content[start..].IndexOf((byte)'\t');
            if (next < 0)
            {
                fields[count++] = new Range(start, content.Length);
                return count;
            }
            fields[count++] = new Range(start, start + next);
            start += next + 1;
        }
    }
}
