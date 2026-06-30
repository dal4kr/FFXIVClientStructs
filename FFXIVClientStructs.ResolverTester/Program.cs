using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Reflection.PortableExecutable;
using System.Text;
using FFXIVClientStructs.ResolverTester;
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

        foreach (Address address in Resolver.GetInstance.Addresses)
            Console.WriteLine($"{address.Name} {address.Value:X}");
    }
}

using StreamReader dataReader = new StreamReader("ida/data.yml");

var deserializer = new YamlDotNet.Serialization.DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance).Build();
var data = deserializer.Deserialize<Data>(dataReader);

int havokSigs = 0;
int notFoundSigs = 0;
int matchedSigs = 0;
int failedSigs = 0;

List<string> failedOutputs = [];
List<string> notfoundOutputs = [];

foreach (Address addr in Resolver.GetInstance.Addresses) {
    // havok names in data.yml mangled
    if (addr.Name.StartsWith("FFXIVClientStructs.Havok")) {
        havokSigs += 1;
        continue;
    }
    ReadOnlySpan<char> nameWithoutPrefix = addr.Name.Replace(".", "::").AsSpan(27);
    int index = nameWithoutPrefix.LastIndexOf(':');
    var className = nameWithoutPrefix[..(index - 1)].ToString();
    var functionName = nameWithoutPrefix[(index + 1)..].ToString();

    if (!data.Classes.TryGetValue(className, out Class? theClass) || theClass == null) {
        notfoundOutputs.Add($"Class {className} not found in data.yml for signature {functionName} @ {addr.String}");
        notFoundSigs += 1;
        continue;
    }

    if (functionName == "Instance") {
        if (theClass.Instances.Count == 0) {
            notfoundOutputs.Add($"No instance found in data.yml for class {className} / signature {functionName} @ {addr.String}");
            notFoundSigs += 1;
            continue;
        }
        if (!nint.TryParse(theClass.Instances[0].Ea.AsSpan(4), NumberStyles.HexNumber, null, out nint address)) {
            notfoundOutputs.Add($"Unable to parse data.yml offset {theClass.Instances[0].Ea} for class {className} Instance");
            notFoundSigs += 1;
            continue;
        }

        if (addr.Value == 0) {
            failedOutputs.Add($"{addr.Name} - {addr.String} failed to resolve, data.yml has {address:X}");
            failedSigs += 1;
            continue;
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

        matchedSigs += 1;
        continue;
    }

    if (functionName == "StaticVirtualTable") {
        if (theClass.Vtbls.Count == 0) {
            notfoundOutputs.Add($"No vtbl found in data.yml for class {className} / signature {functionName} @ {addr.String}");
            notFoundSigs += 1;
            continue;
        }

        if (!nint.TryParse(theClass.Vtbls[0].Ea.AsSpan(4), NumberStyles.HexNumber, null, out nint address)) {
            notfoundOutputs.Add($"Unable to parse data.yml offset {theClass.Instances[0].Ea} for class {className} StaticVirtualTable");
            notFoundSigs += 1;
            continue;
        }

        if (addr.Value == 0) {
            failedOutputs.Add($"{addr.Name} - {addr.String} failed to resolve, data.yml has {address:X}");
            failedSigs += 1;
            continue;
        }

        if (address != addr.Value) {
            failedOutputs.Add($"{addr.Name} - {addr.String} resolved to {addr.Value:X}, data.yml has {address:X}");
            failedSigs += 1;
            continue;
        }

        matchedSigs += 1;
        continue;
    }

    if (functionName.StartsWith("Ctor") || functionName.StartsWith("Dtor"))
        functionName = char.ToLowerInvariant(functionName[0]) + functionName[1..]; // lowercase ctor/dtor

    if (theClass.Funcs == null)
        continue;

    if (theClass.Funcs.Count == 0 || !theClass.Funcs.ContainsValue(functionName)) {
        notfoundOutputs.Add($"Function {functionName} of class {className} not found in data.yml for signature {addr.String}");
        notFoundSigs += 1;
        continue;
    }

    var key = theClass.Funcs.FirstOrDefault(x => x.Value == functionName).Key!;

    if (!nint.TryParse(key.AsSpan(4), NumberStyles.HexNumber, null, out nint dataAddress)) {
        notfoundOutputs.Add($"Unable to parse data.yml offset {key} for class {className} function {functionName}");
        notFoundSigs += 1;
        continue;
    }

    if (addr.Value == 0) {
        failedOutputs.Add($"{addr.Name} - {addr.String} failed to resolve, data.yml has {dataAddress:X}");
        failedSigs += 1;
        continue;
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

var sb = new StringBuilder();

sb.AppendLine($"Total Sigs {Resolver.GetInstance.Addresses.Count}");
sb.AppendLine($"Skipped Havok Sig Count {havokSigs}");
sb.AppendLine($"Sigs Not Found in data.yml Count {notFoundSigs}");
sb.AppendLine($"Sigs Matching data.yml Count {matchedSigs}");
sb.AppendLine($"Sigs Not Matching data.yml Count {failedSigs}");

sb.AppendLine();

sb.AppendLine("Failed Matches");
foreach (string line in failedOutputs)
    sb.AppendLine(line);

sb.AppendLine();

sb.AppendLine("Not Found in data.yml");
foreach (string line in notfoundOutputs)
    sb.AppendLine(line);

Console.WriteLine(sb.ToString());
File.WriteAllText("ida/data-missmatch2.txt", sb.ToString());
