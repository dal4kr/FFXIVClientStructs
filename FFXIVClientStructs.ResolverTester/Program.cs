using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Reflection.PortableExecutable;
using FFXIVClientStructs.Interop.Generated;
using InteropGenerator.Runtime;

var gamePath = args.Length > 0 ? args[0] : @"C:\Program Files (x86)\FINAL FANTASY XIV - KOREA\game\ffxiv_dx11.exe";

using var reader = new PEReader(File.OpenRead(gamePath));
var textHeader = reader.PEHeaders.SectionHeaders[0];

var relocateFile = new Span<byte>(new byte[reader.PEHeaders.PEHeader!.SizeOfImage]);

reader.GetSectionData(textHeader.Name).GetContent().CopyTo(relocateFile.Slice(textHeader.VirtualAddress, textHeader.VirtualSize));
unsafe {
    fixed (byte* bytes = relocateFile) {

        Resolver.GetInstance.Setup(new IntPtr(bytes),
            relocateFile.Length,
            textHeader.VirtualAddress,
            textHeader.VirtualSize);

        var watch = new Stopwatch();
        watch.Start();
        Addresses.Register();

        var addresses = Resolver.GetInstance.Addresses.ToList();
        var matchResults = new ConcurrentDictionary<Address, List<nint>>();

        var textSectionOffset = textHeader.VirtualAddress;
        var textSectionSize = textHeader.VirtualSize;
        var bytesPtr = (nint)bytes;

        Parallel.ForEach(addresses,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            address => {
                var pattern = ParseSignature(address.String);
                var matches = new List<nint>();

                if (pattern.Length == 0) {
                    matchResults[address] = matches;
                    return;
                }

                var localBytes = (byte*)bytesPtr;
                var searchStart = localBytes + textSectionOffset;
                var searchEnd = searchStart + textSectionSize - pattern.Length;

                var firstNonWildcardIndex = -1;
                byte firstNonWildcardByte = 0;
                for (var i = 0; i < pattern.Length; i++) {
                    if (!pattern[i].isWildcard) {
                        firstNonWildcardIndex = i;
                        firstNonWildcardByte = pattern[i].value;
                        break;
                    }
                }

                if (firstNonWildcardIndex == -1) {
                    for (var current = searchStart; current <= searchEnd; current++) {
                        if (MatchesPatternOptimized(current, pattern))
                            matches.Add((nint)(current - localBytes));
                    }
                } else {
                    for (var current = searchStart; current <= searchEnd; current++) {
                        if (current[firstNonWildcardIndex] == firstNonWildcardByte) {
                            if (MatchesPatternOptimized(current, pattern))
                                matches.Add((nint)(current - localBytes));
                        }
                    }
                }

                matchResults[address] = matches;
            });

        watch.Stop();

        var totalSigCount = addresses.Count;
        var resolvedUnique = matchResults.Count(kvp => kvp.Value.Count == 1);
        var ambiguousCount = matchResults.Count(kvp => kvp.Value.Count > 1);
        var failedCount = matchResults.Count(kvp => kvp.Value.Count == 0);

        Console.WriteLine("\n=== 扫描结果统计 ===");
        Console.WriteLine($"总计: {totalSigCount} 个特征码");
        Console.WriteLine($"成功 (唯一匹配): {resolvedUnique} 个 ({(double)resolvedUnique / totalSigCount * 100:F1}%)");
        Console.WriteLine($"多结果 (需修复): {ambiguousCount} 个 ({(double)ambiguousCount / totalSigCount * 100:F1}%)");
        Console.WriteLine($"失败 (未匹配): {failedCount} 个 ({(double)failedCount / totalSigCount * 100:F1}%)");
        Console.WriteLine($"耗时: {watch.ElapsedMilliseconds}ms");

        if (failedCount > 0) {
            Console.WriteLine("\n=== 失败的特征码 ===");
            foreach (var kvp in matchResults.Where(kvp => kvp.Value.Count == 0)) {
                Console.WriteLine($"[FAIL] {kvp.Key.Name}: {kvp.Key.String}");
            }
        }

        if (ambiguousCount > 0) {
            Console.WriteLine("\n=== 多结果的特征码 ===");
            foreach (var kvp in matchResults.Where(kvp => kvp.Value.Count > 1)) {
                var preview = string.Join(", ", kvp.Value.Take(5).Select(a => $"0x{a:X}"));
                var more = kvp.Value.Count > 5 ? $"... 等 {kvp.Value.Count} 处" : "";
                Console.WriteLine($"[AMB] {kvp.Key.Name}: {kvp.Key.String} -> {preview} {more}".Trim());
            }
        }
    }
}

return;

static (byte value, bool isWildcard)[] ParseSignature(string signature) {
    var parts = signature.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    var lastNonWildcard = -1;
    for (var i = 0; i < parts.Length; i++) {
        if (parts[i] != "??" && parts[i] != "**") {
            lastNonWildcard = i;
        }
    }

    if (lastNonWildcard == -1) return [];

    var pattern = new List<(byte value, bool isWildcard)>();
    for (var i = 0; i <= lastNonWildcard; i++) {
        var part = parts[i];
        if (part is "??" or "**")
            pattern.Add((0, true));
        else if (byte.TryParse(part, NumberStyles.HexNumber, null, out var value))
            pattern.Add((value, false));
    }

    return pattern.ToArray();
}

static unsafe bool MatchesPatternOptimized(byte* memory, (byte value, bool isWildcard)[] pattern) {
    fixed (void* patternPtr = pattern) {
        var patternData = ((byte value, bool isWildcard)*)patternPtr;
        for (var i = 0; i < pattern.Length; i++) {
            if (!patternData[i].isWildcard && memory[i] != patternData[i].value)
                return false;
        }
    }
    return true;
}
